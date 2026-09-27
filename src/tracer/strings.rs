//! Bounded string and body reads from a target's memory.
//!
//! Shared by both OS backends so the reads are written and fixed once. Each read
//! is clipped to page boundaries: a string that ends just before an unmapped
//! page is still recovered, where a single oversized read would fail as a whole
//! and lose everything (a chunk crossing into unmapped memory errors entirely).
//! Reads go through [`MemReader`], so they are unit-tested with a fake mapping.

use crate::mem::MemReader;

const PAGE: u64 = 4096;

/// Cap on a single captured string or body, to bound a capture's size.
pub const MAX_BUFFER: usize = 256 * 1024;
/// Cap on a NUL-terminated wide string (host, verb, target) in UTF-16 units.
const MAX_WSTR_UNITS: usize = 4096;
/// Cap on a counted wide string (request headers) in UTF-16 units.
const MAX_WSTR_LEN_UNITS: usize = 64 * 1024;

/// Bytes from `addr` to the end of its page, capped by `remaining` and the
/// scratch buffer.
fn chunk_to_page_end(addr: u64, remaining: usize, buf_len: usize) -> usize {
    let to_page = (PAGE - (addr % PAGE)) as usize;
    to_page.min(buf_len).min(remaining)
}

/// Read a NUL-terminated ASCII/UTF-8 string from the tracee (bounded).
pub fn read_cstr(reader: &dyn MemReader, addr: u64) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    let mut buf = [0u8; PAGE as usize];
    let mut a = addr;
    while out.len() < MAX_BUFFER {
        let n = chunk_to_page_end(a, MAX_BUFFER - out.len(), buf.len());
        if reader.read_exact_at(a, &mut buf[..n]).is_err() {
            break;
        }
        if let Some(pos) = buf[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..pos]);
            break;
        }
        out.extend_from_slice(&buf[..n]);
        a += n as u64;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read a run of UTF-16LE units in page-clipped chunks, stopping at the first
/// `0x0000` if `stop_at_nul`, or after `max_units` either way.
fn read_utf16(reader: &dyn MemReader, addr: u64, max_units: usize, stop_at_nul: bool) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut units: Vec<u16> = Vec::new();
    let mut buf = [0u8; PAGE as usize];
    let mut a = addr;
    while units.len() < max_units {
        // Read whole units only, and never cross a page in one read.
        let n = chunk_to_page_end(a, (max_units - units.len()) * 2, buf.len()) & !1;
        if n == 0 {
            // An odd address at a page's last byte: read the one crossing unit.
            match reader.read_u16(a) {
                Ok(0) if stop_at_nul => break,
                Ok(u) => units.push(u),
                Err(_) => break,
            }
            a += 2;
            continue;
        }
        if reader.read_exact_at(a, &mut buf[..n]).is_err() {
            break;
        }
        let mut hit_nul = false;
        for pair in buf[..n].as_chunks::<2>().0 {
            let u = u16::from_le_bytes(*pair);
            if u == 0 && stop_at_nul {
                hit_nul = true;
                break;
            }
            units.push(u);
        }
        if hit_nul {
            break;
        }
        a += n as u64;
    }
    String::from_utf16_lossy(&units)
}

/// Read a NUL-terminated UTF-16LE string from the tracee (bounded).
pub fn read_wstr(reader: &dyn MemReader, addr: u64) -> String {
    read_utf16(reader, addr, MAX_WSTR_UNITS, true)
}

/// Read a UTF-16LE string of `len` characters, or NUL-terminated if `len` is 0
/// or `0xFFFFFFFF` (WinHTTP's "unknown length").
pub fn read_wstr_len(reader: &dyn MemReader, addr: u64, len: u32) -> String {
    if len == 0 || len == u32::MAX {
        return read_wstr(reader, addr);
    }
    read_utf16(reader, addr, (len as usize).min(MAX_WSTR_LEN_UNITS), false)
}

/// Read a request body of `len` bytes (bounded).
pub fn read_body(reader: &dyn MemReader, addr: u64, len: u32) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return Vec::new();
    }
    reader
        .read_vec(addr, (len as usize).min(MAX_BUFFER))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A fake mapping: only `[lo, hi)` is readable; any read touching outside
    /// fails as a whole, as a real cross into an unmapped page would.
    struct Paged {
        lo: u64,
        hi: u64,
        bytes: Vec<u8>,
    }

    impl MemReader for Paged {
        fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
            let end = addr + buf.len() as u64;
            if addr < self.lo || end > self.hi {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unmapped"));
            }
            let off = (addr - self.lo) as usize;
            buf.copy_from_slice(&self.bytes[off..off + buf.len()]);
            Ok(())
        }
    }

    /// Map whole pages ending at `hi`, with `content` placed flush against the
    /// end, so its final byte is the last mapped byte and `hi` onward is
    /// unmapped. Returns the reader and the content's start address.
    fn ending_before_page(hi: u64, content: &[u8]) -> (Paged, u64) {
        let span = content.len().div_ceil(PAGE as usize).max(1) * PAGE as usize;
        let lo = hi - span as u64;
        let mut bytes = vec![0x41u8; span]; // 'A' filler
        let start = span - content.len();
        bytes[start..].copy_from_slice(content);
        (Paged { lo, hi, bytes }, lo + start as u64)
    }

    #[test]
    fn cstr_recovered_when_it_ends_in_the_last_mapped_page() {
        // "hello\0" sits in the last 6 bytes of the mapped page; the next page is
        // unmapped. A page-clipped read still finds it.
        let (r, addr) = ending_before_page(0x2000, b"hello\0");
        assert_eq!(read_cstr(&r, addr), "hello");
    }

    #[test]
    fn cstr_across_a_page_boundary_is_read_whole() {
        // Map two pages and place a long string spanning the boundary.
        let s = "x".repeat(4100);
        let mut content = s.clone().into_bytes();
        content.push(0);
        let (r, addr) = ending_before_page(0x3000, &content); // spans 0x1000..0x3000
        assert_eq!(read_cstr(&r, addr), s);
    }

    #[test]
    fn wstr_recovered_when_it_ends_in_the_last_mapped_page() {
        let mut content: Vec<u8> = "hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
        content.extend_from_slice(&[0, 0]); // NUL unit
        let (r, addr) = ending_before_page(0x2000, &content);
        assert_eq!(read_wstr(&r, addr), "hi");
    }

    #[test]
    fn wstr_len_reads_exactly_the_counted_units() {
        let content: Vec<u8> = "abcd".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (r, addr) = ending_before_page(0x2000, &content);
        assert_eq!(read_wstr_len(&r, addr, 3), "abc");
    }

    #[test]
    fn a_null_address_reads_empty() {
        let r = Paged {
            lo: 0x1000,
            hi: 0x2000,
            bytes: vec![0; PAGE as usize],
        };
        assert_eq!(read_cstr(&r, 0), "");
        assert_eq!(read_wstr(&r, 0), "");
    }
}
