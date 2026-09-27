//! Find OpenSSL's `SSL_read` / `SSL_write` functions in the target image.
//!
//! The game statically links OpenSSL 1.1 and its `.text` is decrypted only in
//! the running process, so the functions have no fixed address and no export to
//! look up. They are found by structure instead:
//!
//! 1. Find the C source string `ssl\ssl_lib.c`, which OpenSSL passes as the
//!    `file` argument to its error macro.
//! 2. In `.text`, find each `lea r9, [rip+disp]` that points at that string.
//!    Each is an `ERR_put_error(lib, func, reason, file, line)` call site inside
//!    a function defined in `ssl_lib.c`.
//! 3. Read the two constant arguments at the site: `mov ecx, 0x14`
//!    (`ERR_LIB_SSL`) confirms it is an SSL error call, and `mov edx, <func>`
//!    gives the function code that names which function the site sits in.
//! 4. Map the site to its enclosing function start through `.pdata`.
//!
//! The function codes are stable in OpenSSL 1.1: `SSL_read` = 223,
//! `SSL_write` = 208, `ssl_read_internal` = 523, `ssl_write_internal` = 524.

use crate::mem::MemReader;
use crate::pe::{PeError, PeImage};

/// `ERR_LIB_SSL`, the `lib` argument of every SSL error call.
const ERR_LIB_SSL: u32 = 0x14;

/// OpenSSL 1.1 `SSL_F_*` function codes.
pub const F_SSL_WRITE: u32 = 208;
pub const F_SSL_READ: u32 = 223;
pub const F_SSL_READ_INTERNAL: u32 = 523;
pub const F_SSL_WRITE_INTERNAL: u32 = 524;

const SSL_LIB_C: &[u8] = b"ssl\\ssl_lib.c\0";

/// The located OpenSSL entry points, as virtual addresses in the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SslFunctions {
    /// `ssl_write_internal(SSL*, const void *buf, size_t num, size_t *written)`.
    pub ssl_write_internal: Option<u64>,
    /// `ssl_read_internal(SSL*, void *buf, size_t num, size_t *readbytes)`.
    pub ssl_read_internal: Option<u64>,
    /// The public `SSL_write` wrapper.
    pub ssl_write: Option<u64>,
    /// The public `SSL_read` wrapper.
    pub ssl_read: Option<u64>,
}

impl SslFunctions {
    /// True once both directions of the internal path are known.
    pub fn has_internal_pair(&self) -> bool {
        self.ssl_write_internal.is_some() && self.ssl_read_internal.is_some()
    }

    /// True once the tracer has what it captures with: `ssl_write_internal` for
    /// sends (read on entry) and the public `SSL_read` for receives (whose
    /// return value gives the exact byte count).
    pub fn ready(&self) -> bool {
        self.ssl_write_internal.is_some() && self.ssl_read.is_some()
    }
}

/// Error while locating the OpenSSL functions.
#[derive(Debug, thiserror::Error)]
pub enum LocateError {
    #[error(transparent)]
    Pe(#[from] PeError),
    #[error("read failed: {0}")]
    Read(#[from] std::io::Error),
    #[error("could not find the {0:?} string in the image")]
    NoString(&'static str),
    #[error("found the ssl_lib.c string but no ssl_write_internal/ssl_read_internal call sites")]
    NoSites,
}

/// One recovered `ERR_put_error` call site: which function code it reports and
/// where the reporting instructions sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrSite {
    pub func: u32,
    pub site_va: u64,
}

/// Scan a `.text` byte image for SSL error call sites that reference
/// `string_va`.
///
/// Pure over bytes so it is unit-tested without a process. For each
/// `lea r9, [rip+disp]` whose rip-relative target is `string_va`, it scans
/// forward to the terminating `call` and, within that span, requires
/// `mov ecx, ERR_LIB_SSL` and reads `mov edx, <func>`.
pub fn scan_err_sites(text: &[u8], text_va: u64, string_va: u64) -> Vec<ErrSite> {
    const LEA_R9: [u8; 3] = [0x4C, 0x8D, 0x0D]; // lea r9, [rip+disp32]
    const WINDOW: usize = 0x30;

    let mut sites = Vec::new();
    let mut i = 0usize;
    while i + 7 <= text.len() {
        if text[i..i + 3] != LEA_R9 {
            i += 1;
            continue;
        }
        let disp = i32::from_le_bytes([text[i + 3], text[i + 4], text[i + 5], text[i + 6]]);
        let next = text_va + (i as u64) + 7;
        let target = (next as i64).wrapping_add(disp as i64) as u64;
        if target != string_va {
            i += 1;
            continue;
        }
        // Scan forward from the lea to the ERR_put_error `call`, gathering the
        // constant arguments in between.
        let span_end = (i + 7 + WINDOW).min(text.len());
        let span = &text[i + 7..span_end];
        if let Some(func) = err_call_func(span) {
            sites.push(ErrSite {
                func,
                site_va: text_va + i as u64,
            });
        }
        i += 7;
    }
    sites
}

/// Within the window that follows a `lea r9`, confirm `mov ecx, ERR_LIB_SSL` is
/// present (the `lib` argument of the same `ERR_put_error` call) and return the
/// `mov edx, <func>` immediate. Returns `None` if the window is not such a call.
///
/// The `lib` marker and the `func` move are both arguments of the one call, set
/// within a few bytes of each other, so the `func` move is taken as the `BA`
/// nearest the marker. The window is not cut at the first `0xE8`: that byte also
/// occurs *inside* an immediate — e.g. the line number 1000 (`0x3E8`) in
/// `mov dword [rsp+0x20], line` — and cutting there would hide the marker.
fn err_call_func(span: &[u8]) -> Option<u32> {
    // mov ecx, ERR_LIB_SSL  (0xB9 imm32)
    let mut mov_ecx_lib = [0xB9u8, 0, 0, 0, 0];
    mov_ecx_lib[1..].copy_from_slice(&ERR_LIB_SSL.to_le_bytes());
    let lib_pos = span.windows(5).position(|w| w == mov_ecx_lib)?;

    // `mov edx, imm32` is 0xBA imm32 with a small func code; take the one closest
    // to the lib marker (both are arguments of the same call).
    let mut best: Option<(usize, u32)> = None;
    let mut j = 0;
    while j + 5 <= span.len() {
        if span[j] == 0xBA {
            let imm = u32::from_le_bytes([span[j + 1], span[j + 2], span[j + 3], span[j + 4]]);
            if imm < 0x1_0000 {
                let dist = lib_pos.abs_diff(j);
                if best.is_none_or(|(d, _)| dist < d) {
                    best = Some((dist, imm));
                }
            }
        }
        j += 1;
    }
    best.map(|(_, imm)| imm)
}

/// Find a NUL-terminated byte string in a section, returning its virtual
/// address.
pub fn find_cstr(
    reader: &dyn MemReader,
    section_va: u64,
    section_size: u64,
    needle: &[u8],
) -> Result<Option<u64>, std::io::Error> {
    // Read the section in one shot and search it. Section sizes here are a few
    // megabytes, well within a single read.
    let bytes = reader.read_vec(section_va, section_size as usize)?;
    Ok(bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|off| section_va + off as u64))
}

/// Locate the OpenSSL entry points in the image mapped at the PE's base.
pub fn locate(reader: &dyn MemReader, pe: &PeImage) -> Result<SslFunctions, LocateError> {
    let rdata = pe
        .section(".rdata")
        .or_else(|| pe.section(".rodata"))
        .ok_or(PeError::NoSection(".rdata"))?;
    let string_va = find_cstr(reader, rdata.va, rdata.size, SSL_LIB_C)?
        .ok_or(LocateError::NoString("ssl\\ssl_lib.c"))?;

    let text = pe.executable_section().ok_or(PeError::NoSection(".text"))?;
    let text_bytes = reader.read_vec(text.va, text.size as usize)?;
    let sites = scan_err_sites(&text_bytes, text.va, string_va);

    let mut out = SslFunctions::default();
    for site in sites {
        let Some(start) = pe.function_start(reader, site.site_va)? else {
            continue;
        };
        let slot = match site.func {
            F_SSL_WRITE_INTERNAL => &mut out.ssl_write_internal,
            F_SSL_READ_INTERNAL => &mut out.ssl_read_internal,
            F_SSL_WRITE => &mut out.ssl_write,
            F_SSL_READ => &mut out.ssl_read,
            _ => continue,
        };
        // First match wins; every site of a function maps to the same start.
        slot.get_or_insert(start);
    }

    if !out.has_internal_pair() {
        return Err(LocateError::NoSites);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT_VA: u64 = 0x140001000;
    const STRING_VA: u64 = 0x143000000;

    /// Emit the byte sequence of one SSL error call site, mirroring the real
    /// OpenSSL 1.1 layout: `lea r9,[rip+disp]; mov [rsp+0x20],line;
    /// mov edx,func; mov ecx,0x14; mov r8d,reason; call rel32`.
    fn emit_site(out: &mut Vec<u8>, site_va: u64, func: u32) {
        let lea_va = site_va;
        // lea r9, [rip+disp32]
        let next = lea_va + 7;
        let disp = (STRING_VA as i64 - next as i64) as i32;
        out.extend_from_slice(&[0x4C, 0x8D, 0x0D]);
        out.extend_from_slice(&disp.to_le_bytes());
        // mov dword [rsp+0x20], line
        out.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0xEB, 0x06, 0x00, 0x00]);
        // mov edx, func
        out.push(0xBA);
        out.extend_from_slice(&func.to_le_bytes());
        // mov ecx, 0x14
        out.extend_from_slice(&[0xB9, 0x14, 0x00, 0x00, 0x00]);
        // mov r8d, 0x10f
        out.extend_from_slice(&[0x41, 0xB8, 0x0F, 0x01, 0x00, 0x00]);
        // call rel32
        out.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn finds_one_site_with_its_func_code() {
        let mut text = Vec::new();
        // Some filler, then a site at a known offset.
        text.extend_from_slice(&[0x90; 16]);
        let site_va = TEXT_VA + text.len() as u64;
        emit_site(&mut text, site_va, F_SSL_WRITE_INTERNAL);

        let sites = scan_err_sites(&text, TEXT_VA, STRING_VA);
        assert_eq!(
            sites,
            vec![ErrSite {
                func: F_SSL_WRITE_INTERNAL,
                site_va
            }]
        );
    }

    #[test]
    fn ignores_a_lea_that_points_elsewhere() {
        // A lea r9 to a different string must not be taken for an SSL site.
        let mut text = vec![0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00];
        text.extend_from_slice(&[0xB9, 0x14, 0x00, 0x00, 0x00, 0xE8, 0, 0, 0, 0]);
        let sites = scan_err_sites(&text, TEXT_VA, STRING_VA);
        assert!(sites.is_empty());
    }

    #[test]
    fn ignores_a_site_without_the_ssl_lib_marker() {
        // lea points at the string, but ecx is not ERR_LIB_SSL: not an SSL call.
        let mut text = Vec::new();
        let site_va = TEXT_VA;
        let disp = (STRING_VA as i64 - (site_va + 7) as i64) as i32;
        text.extend_from_slice(&[0x4C, 0x8D, 0x0D]);
        text.extend_from_slice(&disp.to_le_bytes());
        text.extend_from_slice(&[0xB9, 0x0A, 0x00, 0x00, 0x00]); // mov ecx, 0x0A
        text.extend_from_slice(&[0xBA, 0xD0, 0x00, 0x00, 0x00]); // mov edx, 208
        text.extend_from_slice(&[0xE8, 0, 0, 0, 0]);
        assert!(scan_err_sites(&text, TEXT_VA, STRING_VA).is_empty());
    }

    #[test]
    fn finds_a_site_whose_line_number_contains_an_e8_byte() {
        // Line 1000 = 0x3E8, so `mov dword [rsp+0x20], 1000` is C7 44 24 20 E8
        // 03 00 00 — the 0xE8 is an immediate byte, not the terminating call.
        let site_va = TEXT_VA;
        let disp = (STRING_VA as i64 - (site_va + 7) as i64) as i32;
        let mut text = Vec::new();
        text.extend_from_slice(&[0x4C, 0x8D, 0x0D]);
        text.extend_from_slice(&disp.to_le_bytes());
        text.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0xE8, 0x03, 0x00, 0x00]); // line 1000
        text.extend_from_slice(&[0xBA, 0xD0, 0x00, 0x00, 0x00]); // mov edx, 208 (SSL_write)
        text.extend_from_slice(&[0xB9, 0x14, 0x00, 0x00, 0x00]); // mov ecx, ERR_LIB_SSL
        text.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]); // call
        let sites = scan_err_sites(&text, TEXT_VA, STRING_VA);
        assert_eq!(
            sites,
            vec![ErrSite {
                func: F_SSL_WRITE,
                site_va
            }]
        );
    }

    #[test]
    fn finds_several_functions_and_keeps_first_per_code() {
        let mut text = Vec::new();
        text.extend_from_slice(&[0x90; 4]);
        let w = TEXT_VA + text.len() as u64;
        emit_site(&mut text, w, F_SSL_WRITE_INTERNAL);
        // a second write-internal site (same function, later) — first wins
        let w2 = TEXT_VA + text.len() as u64;
        emit_site(&mut text, w2, F_SSL_WRITE_INTERNAL);
        let r = TEXT_VA + text.len() as u64;
        emit_site(&mut text, r, F_SSL_READ_INTERNAL);

        let sites = scan_err_sites(&text, TEXT_VA, STRING_VA);
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0].func, F_SSL_WRITE_INTERNAL);
        assert_eq!(sites[0].site_va, w);
        assert_eq!(sites[2].func, F_SSL_READ_INTERNAL);
    }
}
