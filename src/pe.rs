//! The minimal PE facts the locator needs: the section table and the
//! `.pdata` exception table.
//!
//! This is not a general PE parser. It reads only what maps an address to its
//! function start and finds the executable and read-only-data sections. It runs
//! through a [`MemReader`], so it parses a memory-mapped image the same whether
//! that image is a dump file or a live process.

use crate::mem::MemReader;
use std::io;

/// Error while reading PE structure from the target.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("read failed: {0}")]
    Read(#[from] io::Error),
    #[error("not a PE image: {0}")]
    NotPe(&'static str),
    #[error("image has no {0} section")]
    NoSection(&'static str),
    #[error("image has no exception (.pdata) directory")]
    NoException,
}

/// One section's virtual placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub size: u64,
    pub characteristics: u32,
}

impl Section {
    /// True if a virtual address falls inside this section.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.va && addr < self.va + self.size
    }
}

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Validate the PE headers of the image at `base` and return the offset of the
/// PE signature (`base + e_lfanew`). Errors unless it is a 64-bit PE32+ image.
/// Shared by every reader below so the MZ/`PE\0\0`/magic checks live once.
fn pe_headers(reader: &dyn MemReader, base: u64) -> Result<u64, PeError> {
    if reader.read_u16(base)? != 0x5A4D {
        return Err(PeError::NotPe("no MZ signature"));
    }
    let pe = base + reader.read_u32(base + 0x3C)? as u64;
    if reader.read_u32(pe)? != 0x0000_4550 {
        return Err(PeError::NotPe("no PE\\0\\0 signature"));
    }
    // The optional header starts at pe + 24; its magic marks PE32+ (0x20B).
    if reader.read_u16(pe + 24)? != 0x20B {
        return Err(PeError::NotPe("not a PE32+ (64-bit) image"));
    }
    Ok(pe)
}

/// The parsed pieces of a PE image needed to locate a function.
#[derive(Debug, Clone)]
pub struct PeImage {
    pub base: u64,
    pub sections: Vec<Section>,
    /// Virtual address of the `.pdata` `RUNTIME_FUNCTION` array.
    pub pdata_va: u64,
    /// Number of `RUNTIME_FUNCTION` entries (each 12 bytes).
    pub pdata_count: usize,
}

impl PeImage {
    /// Parse the headers of the image mapped at `base`.
    pub fn parse(reader: &dyn MemReader, base: u64) -> Result<Self, PeError> {
        let pe = pe_headers(reader, base)?;
        let num_sections = reader.read_u16(pe + 6)? as usize;
        let opt_size = reader.read_u16(pe + 20)? as u64;
        let opt = pe + 24;
        // Data directory 3 is the exception table; it lives at a fixed offset
        // inside the PE32+ optional header.
        let exception_dir = opt + 112 + 3 * 8;
        let pdata_rva = reader.read_u32(exception_dir)?;
        let pdata_size = reader.read_u32(exception_dir + 4)?;
        if pdata_rva == 0 || pdata_size == 0 {
            return Err(PeError::NoException);
        }

        let sec_table = opt + opt_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let e = sec_table + (i as u64) * 40;
            let name_bytes = reader.read_vec(e, 8)?;
            let name = String::from_utf8_lossy(&name_bytes)
                .trim_end_matches('\0')
                .to_string();
            let vsize = reader.read_u32(e + 8)? as u64;
            let vaddr = reader.read_u32(e + 12)? as u64;
            let chars = reader.read_u32(e + 36)?;
            sections.push(Section {
                name,
                va: base + vaddr,
                size: vsize,
                characteristics: chars,
            });
        }

        Ok(PeImage {
            base,
            sections,
            pdata_va: base + pdata_rva as u64,
            pdata_count: pdata_size as usize / 12,
        })
    }

    /// The section with this exact name.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The first executable section (`.text`).
    pub fn executable_section(&self) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    }

    /// The function start covering `addr`, from the `.pdata` table.
    ///
    /// `RUNTIME_FUNCTION` entries are sorted by start address, so this is a
    /// binary search: `[begin_rva u32, end_rva u32, unwind_rva u32]`, 12 bytes
    /// each. Returns `None` when `addr` is in no described function (leaf code
    /// without unwind info, or data).
    pub fn function_start(
        &self,
        reader: &dyn MemReader,
        addr: u64,
    ) -> Result<Option<u64>, PeError> {
        // RVAs are 32-bit. An address below the base, or more than 4 GiB above
        // it, is in no `RUNTIME_FUNCTION`; guard so it cannot alias one by
        // truncation to `u32`.
        let Some(rva) = addr
            .checked_sub(self.base)
            .filter(|&d| d <= u32::MAX as u64)
        else {
            return Ok(None);
        };
        let target = rva as u32;
        let (mut lo, mut hi) = (0usize, self.pdata_count);
        let mut found: Option<u64> = None;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let entry = self.pdata_va + (mid as u64) * 12;
            let begin = reader.read_u32(entry)?;
            let end = reader.read_u32(entry + 4)?;
            if target < begin {
                hi = mid;
            } else if target >= end {
                lo = mid + 1;
            } else {
                found = Some(self.base + begin as u64);
                break;
            }
        }
        Ok(found)
    }
}

/// Resolve an exported function's virtual address by name, from the image
/// mapped at `base`.
///
/// This reads the PE export directory (data directory 0), independent of the
/// section/`.pdata` parse, so it works on a module like `winhttp.dll` whose
/// exports the tracer needs. Returns `None` if the image has no export named
/// `name`.
pub fn resolve_export(
    reader: &dyn MemReader,
    base: u64,
    name: &str,
) -> Result<Option<u64>, PeError> {
    let opt = pe_headers(reader, base)? + 24;
    // Data directory 0 is the export table.
    let export_rva = reader.read_u32(opt + 112)?;
    if export_rva == 0 {
        return Ok(None);
    }
    let dir = base + export_rva as u64;
    let num_names = reader.read_u32(dir + 0x18)?;
    let functions = base + reader.read_u32(dir + 0x1C)? as u64;
    let names = base + reader.read_u32(dir + 0x20)? as u64;
    let ordinals = base + reader.read_u32(dir + 0x24)? as u64;

    for i in 0..num_names as u64 {
        let name_rva = reader.read_u32(names + i * 4)?;
        if export_name_matches(reader, base + name_rva as u64, name)? {
            let ordinal = reader.read_u16(ordinals + i * 2)? as u64;
            let func_rva = reader.read_u32(functions + ordinal * 4)?;
            return Ok(Some(base + func_rva as u64));
        }
    }
    Ok(None)
}

/// Compare a NUL-terminated ASCII export name at `addr` with `want`.
fn export_name_matches(reader: &dyn MemReader, addr: u64, want: &str) -> Result<bool, PeError> {
    let bytes = reader.read_vec(addr, want.len() + 1)?;
    Ok(bytes.len() == want.len() + 1
        && bytes[want.len()] == 0
        && &bytes[..want.len()] == want.as_bytes())
}

/// Resolve the runtime address of a function this image imports from `dll`.
///
/// This reads the import table (data directory 1) of the image mapped at
/// `base`, finds the descriptor for `dll` (matched case-insensitively), and
/// returns the bound address from the import address table (IAT) for
/// `func`. The loader has bound the IAT by the time the process is running, so
/// this yields the actual function address inside the imported DLL — without
/// needing to find that DLL's base or how it is mapped.
pub fn resolve_import(
    reader: &dyn MemReader,
    base: u64,
    dll: &str,
    func: &str,
) -> Result<Option<u64>, PeError> {
    let opt = pe_headers(reader, base)? + 24;
    // Data directory 1 is the import table.
    let import_rva = reader.read_u32(opt + 112 + 8)?;
    if import_rva == 0 {
        return Ok(None);
    }

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the array ends at an all-zero one.
    let mut desc = base + import_rva as u64;
    loop {
        let ilt_rva = reader.read_u32(desc)?; // OriginalFirstThunk
        let name_rva = reader.read_u32(desc + 12)?;
        let iat_rva = reader.read_u32(desc + 16)?; // FirstThunk
        if name_rva == 0 && iat_rva == 0 {
            return Ok(None);
        }
        if dll_name_matches(reader, base + name_rva as u64, dll)? {
            // Walk the lookup table for the name; the address is the IAT slot at
            // the same index. Fall back to the IAT itself if there is no ILT.
            let lookup = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            let mut i = 0u64;
            loop {
                let entry = reader.read_u64(base + lookup as u64 + i * 8)?;
                if entry == 0 {
                    break;
                }
                // High bit set means import-by-ordinal; skip those.
                if entry & (1 << 63) == 0 {
                    let by_name = base + (entry & 0x7fff_ffff);
                    // IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
                    if import_name_matches(reader, by_name + 2, func)? {
                        return Ok(Some(reader.read_u64(base + iat_rva as u64 + i * 8)?));
                    }
                }
                i += 1;
            }
        }
        desc += 20;
    }
}

fn dll_name_matches(reader: &dyn MemReader, addr: u64, want: &str) -> Result<bool, PeError> {
    let bytes = read_cstr(reader, addr, 64)?;
    Ok(bytes.eq_ignore_ascii_case(want.as_bytes()))
}

fn import_name_matches(reader: &dyn MemReader, addr: u64, want: &str) -> Result<bool, PeError> {
    let bytes = read_cstr(reader, addr, 128)?;
    Ok(bytes == want.as_bytes())
}

/// Read a NUL-terminated ASCII string (up to `max` bytes) as raw bytes,
/// one byte at a time so it never reads past the string.
fn read_cstr(reader: &dyn MemReader, addr: u64, max: usize) -> Result<Vec<u8>, PeError> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    for i in 0..max as u64 {
        reader.read_exact_at(addr + i, &mut b)?;
        if b[0] == 0 {
            break;
        }
        out.push(b[0]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::SliceReader;

    const BASE: u64 = 0x140000000;

    /// Build a tiny but valid PE32+ memory image with one `.text` section and a
    /// `.pdata` holding the given `RUNTIME_FUNCTION` entries `(begin, end)`.
    fn build_pe(text_va: u32, text_size: u32, funcs: &[(u32, u32)]) -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        img[0] = b'M';
        img[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        img[pe..pe + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
        let num_sections: u16 = 2;
        img[pe + 6..pe + 8].copy_from_slice(&num_sections.to_le_bytes());
        let opt_size: u16 = 240;
        img[pe + 20..pe + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt = pe + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());

        // .pdata goes at a fixed spot after the header; describe it in dir[3].
        let pdata_va: u32 = 0x9000;
        let pdata_size: u32 = (funcs.len() * 12) as u32;
        let exc = opt + 112 + 3 * 8;
        img[exc..exc + 4].copy_from_slice(&pdata_va.to_le_bytes());
        img[exc + 4..exc + 8].copy_from_slice(&pdata_size.to_le_bytes());

        let sec = opt + opt_size as usize;
        let mut put_section = |off: usize, name: &[u8], va: u32, size: u32, ch: u32| {
            img[off..off + name.len()].copy_from_slice(name);
            img[off + 8..off + 12].copy_from_slice(&size.to_le_bytes());
            img[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            img[off + 36..off + 40].copy_from_slice(&ch.to_le_bytes());
        };
        put_section(sec, b".text", text_va, text_size, IMAGE_SCN_MEM_EXECUTE);
        put_section(sec + 40, b".pdata", pdata_va, pdata_size, 0x4000_0040);

        // Grow to cover .pdata and write the RUNTIME_FUNCTION array.
        let need = pdata_va as usize + funcs.len() * 12;
        if img.len() < need {
            img.resize(need, 0);
        }
        for (i, (b, e)) in funcs.iter().enumerate() {
            let o = pdata_va as usize + i * 12;
            img[o..o + 4].copy_from_slice(&b.to_le_bytes());
            img[o + 4..o + 8].copy_from_slice(&e.to_le_bytes());
        }
        img
    }

    #[test]
    fn parses_sections_and_finds_the_executable_one() {
        let img = build_pe(0x1000, 0x2000, &[(0x1000, 0x1100)]);
        let r = SliceReader::new(BASE, &img);
        let pe = PeImage::parse(&r, BASE).unwrap();
        assert_eq!(pe.section(".text").unwrap().va, BASE + 0x1000);
        assert_eq!(pe.executable_section().unwrap().name, ".text");
        assert!(pe.section(".text").unwrap().contains(BASE + 0x1500));
        assert!(!pe.section(".text").unwrap().contains(BASE + 0x3000));
    }

    #[test]
    fn function_start_binary_searches_pdata() {
        let funcs = [(0x1000, 0x1100), (0x1100, 0x1250), (0x2000, 0x2040)];
        let img = build_pe(0x1000, 0x2000, &funcs);
        let r = SliceReader::new(BASE, &img);
        let pe = PeImage::parse(&r, BASE).unwrap();
        // An address inside the second function resolves to its start.
        assert_eq!(
            pe.function_start(&r, BASE + 0x1200).unwrap(),
            Some(BASE + 0x1100)
        );
        // Exact start of a function.
        assert_eq!(
            pe.function_start(&r, BASE + 0x2000).unwrap(),
            Some(BASE + 0x2000)
        );
        // A gap between described functions resolves to nothing.
        assert_eq!(pe.function_start(&r, BASE + 0x1300).unwrap(), None);
        // An address more than 4 GiB above the base must not alias a function
        // by truncation to u32: 0x1_0000_1050 & 0xffff_ffff = 0x1050, inside the
        // first function — but it is not in that function.
        assert_eq!(pe.function_start(&r, BASE + 0x1_0000_1050).unwrap(), None);
        // An address below the base is likewise in no function.
        assert_eq!(pe.function_start(&r, BASE - 1).unwrap(), None);
    }

    #[test]
    fn rejects_a_non_pe_image() {
        let img = vec![0u8; 0x400];
        let r = SliceReader::new(BASE, &img);
        assert!(matches!(PeImage::parse(&r, BASE), Err(PeError::NotPe(_))));
    }

    /// Build a PE32+ image that exports one function `name` at `func_rva`.
    fn build_pe_with_export(name: &str, func_rva: u32) -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        img[0] = b'M';
        img[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        img[pe..pe + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
        let opt = pe + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());

        // Lay the export structures out at fixed RVAs.
        let export_rva: u32 = 0x2000;
        let eat_rva: u32 = 0x2100; // AddressOfFunctions
        let ent_rva: u32 = 0x2200; // AddressOfNames
        let ord_rva: u32 = 0x2300; // AddressOfNameOrdinals
        let name_rva: u32 = 0x2400;
        img[opt + 112..opt + 116].copy_from_slice(&export_rva.to_le_bytes());
        img[opt + 116..opt + 120].copy_from_slice(&64u32.to_le_bytes());

        let need = name_rva as usize + name.len() + 1;
        if img.len() < need {
            img.resize(need, 0);
        }
        let d = export_rva as usize;
        img[d + 0x14..d + 0x18].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
        img[d + 0x18..d + 0x1C].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
        img[d + 0x1C..d + 0x20].copy_from_slice(&eat_rva.to_le_bytes());
        img[d + 0x20..d + 0x24].copy_from_slice(&ent_rva.to_le_bytes());
        img[d + 0x24..d + 0x28].copy_from_slice(&ord_rva.to_le_bytes());
        img[eat_rva as usize..eat_rva as usize + 4].copy_from_slice(&func_rva.to_le_bytes());
        img[ent_rva as usize..ent_rva as usize + 4].copy_from_slice(&name_rva.to_le_bytes());
        img[ord_rva as usize..ord_rva as usize + 2].copy_from_slice(&0u16.to_le_bytes());
        let n = name_rva as usize;
        img[n..n + name.len()].copy_from_slice(name.as_bytes());
        img
    }

    #[test]
    fn resolves_an_export_by_name() {
        let img = build_pe_with_export("WinHttpSendRequest", 0x3120);
        let r = SliceReader::new(BASE, &img);
        assert_eq!(
            resolve_export(&r, BASE, "WinHttpSendRequest").unwrap(),
            Some(BASE + 0x3120)
        );
        assert_eq!(resolve_export(&r, BASE, "NoSuchExport").unwrap(), None);
    }

    /// Build a PE32+ image that imports one `func` from `dll`, with the IAT
    /// slot bound to `bound_addr` (as the loader would leave it at runtime).
    fn build_pe_with_import(dll: &str, func: &str, bound_addr: u64) -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        img[0] = b'M';
        img[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        img[pe..pe + 4].copy_from_slice(&[b'P', b'E', 0, 0]);
        let opt = pe + 24;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());

        let import_rva: u32 = 0x2000; // IMAGE_IMPORT_DESCRIPTOR[]
        let ilt_rva: u32 = 0x2100; // lookup table
        let iat_rva: u32 = 0x2200; // import address table (bound)
        let dllname_rva: u32 = 0x2300;
        let byname_rva: u32 = 0x2340; // IMAGE_IMPORT_BY_NAME
        img[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&import_rva.to_le_bytes());

        let need = byname_rva as usize + 2 + func.len() + 1;
        if img.len() < need {
            img.resize(need, 0);
        }
        // One descriptor, then a zero terminator.
        let d = import_rva as usize;
        img[d..d + 4].copy_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
        img[d + 12..d + 16].copy_from_slice(&dllname_rva.to_le_bytes());
        img[d + 16..d + 20].copy_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
        // (bytes d+20.. stay zero = terminator)

        // ILT[0] -> byname_rva; ILT[1] = 0.
        img[ilt_rva as usize..ilt_rva as usize + 8]
            .copy_from_slice(&(byname_rva as u64).to_le_bytes());
        // IAT[0] = bound address; IAT[1] = 0.
        img[iat_rva as usize..iat_rva as usize + 8].copy_from_slice(&bound_addr.to_le_bytes());
        // DLL name.
        let n = dllname_rva as usize;
        img[n..n + dll.len()].copy_from_slice(dll.as_bytes());
        // IMAGE_IMPORT_BY_NAME: hint u16, then name.
        let b = byname_rva as usize;
        img[b + 2..b + 2 + func.len()].copy_from_slice(func.as_bytes());
        img
    }

    #[test]
    fn resolves_an_import_to_its_bound_iat_address() {
        let img = build_pe_with_import("WINHTTP.dll", "WinHttpSendRequest", 0x7fff_1234_5670);
        let r = SliceReader::new(BASE, &img);
        assert_eq!(
            resolve_import(&r, BASE, "winhttp.dll", "WinHttpSendRequest").unwrap(),
            Some(0x7fff_1234_5670)
        );
        assert_eq!(
            resolve_import(&r, BASE, "winhttp.dll", "WinHttpConnect").unwrap(),
            None
        );
        assert_eq!(
            resolve_import(&r, BASE, "other.dll", "WinHttpSendRequest").unwrap(),
            None
        );
    }
}
