//! End-to-end locator check against a real decrypted AoE2DE_s.exe image.
//!
//! This is the strongest evidence that the locator works on the real client:
//! it runs the exact section/`.pdata`/instruction-scan pipeline the tracer uses
//! at runtime, over a real decrypted dump, and asserts it recovers the OpenSSL
//! functions.
//!
//! The dump is not in the repository. Point `SOCKETSPY_TEST_DUMP` at a decrypted
//! image file (on-disk section layout) to run this; without it the test skips,
//! so the repo's test suite passes anywhere.

use socketspy::locate;
use socketspy::mem::{MemReader, SliceReader};
use socketspy::pe::PeImage;
use std::path::PathBuf;

/// Lay an on-disk PE image out the way it appears in a running process:
/// section raw bytes copied to their virtual addresses. Returns `(base, image)`.
fn map_to_process_image(raw: &[u8]) -> (u64, Vec<u8>) {
    let rd_u16 = |o: usize| u16::from_le_bytes(raw[o..o + 2].try_into().unwrap());
    let rd_u32 = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
    let rd_u64 = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());

    let pe = rd_u32(0x3C) as usize;
    let num_sections = rd_u16(pe + 6) as usize;
    let opt_size = rd_u16(pe + 20) as usize;
    let opt = pe + 24;
    let base = rd_u64(opt + 24);
    let size_of_image = rd_u32(opt + 56) as usize;
    let size_of_headers = rd_u32(opt + 60) as usize;

    let mut image = vec![0u8; size_of_image];
    image[..size_of_headers].copy_from_slice(&raw[..size_of_headers]);

    let sec_table = opt + opt_size;
    for i in 0..num_sections {
        let e = sec_table + i * 40;
        let vsize = rd_u32(e + 8) as usize;
        let vaddr = rd_u32(e + 12) as usize;
        let raw_size = rd_u32(e + 16) as usize;
        let raw_ptr = rd_u32(e + 20) as usize;
        let n = raw_size.min(vsize);
        if raw_ptr + n <= raw.len() && vaddr + n <= image.len() {
            image[vaddr..vaddr + n].copy_from_slice(&raw[raw_ptr..raw_ptr + n]);
        }
    }
    (base, image)
}

#[test]
fn locates_openssl_in_the_real_dump() {
    let Ok(path) = std::env::var("SOCKETSPY_TEST_DUMP") else {
        eprintln!("SOCKETSPY_TEST_DUMP not set; skipping real-dump locator test");
        return;
    };
    let raw = std::fs::read(PathBuf::from(&path)).expect("read dump file");
    let (base, image) = map_to_process_image(&raw);
    let reader = SliceReader::new(base, &image);

    let pe = PeImage::parse(&reader, base).expect("parse PE");
    assert!(pe.section(".text").is_some(), ".text present");
    assert!(pe.pdata_count > 100_000, "pdata has many functions");

    let funcs = locate::locate(&reader, &pe).expect("locate OpenSSL functions");
    assert!(
        funcs.has_internal_pair(),
        "both internal functions found: {funcs:?}"
    );

    // The functions must start with a standard prologue, not mid-instruction:
    // push rbx; push rbp; push rsi (48 89 5C 24 08 ...).
    for va in [
        funcs.ssl_write_internal.unwrap(),
        funcs.ssl_read_internal.unwrap(),
    ] {
        let head = reader.read_vec(va, 4).unwrap();
        assert_eq!(head, [0x48, 0x89, 0x5C, 0x24], "prologue at {va:#x}");
    }

    // A site's function code must map to the matching internal function; the two
    // must be distinct functions.
    assert_ne!(funcs.ssl_write_internal, funcs.ssl_read_internal);
    eprintln!("located: {funcs:#x?}");
}

#[test]
fn locates_curl_easy_setopt_in_the_real_dump() {
    let Ok(path) = std::env::var("SOCKETSPY_TEST_DUMP") else {
        eprintln!("SOCKETSPY_TEST_DUMP not set; skipping");
        return;
    };
    let raw = std::fs::read(std::path::PathBuf::from(&path)).expect("read dump");
    let (base, image) = map_to_process_image(&raw);
    let reader = SliceReader::new(base, &image);
    let pe = PeImage::parse(&reader, base).expect("parse PE");
    let text = pe.executable_section().expect("text");
    let bytes = reader.read_vec(text.va, text.size as usize).unwrap();
    let setopt = socketspy::curl::locate_setopt(&bytes, text.va).expect("locate curl_easy_setopt");
    eprintln!("curl_easy_setopt at {setopt:#x}");
    // Not a hardcoded address (it changes across builds): the consensus target
    // must land inside the executable section it was scanned from.
    assert!(text.contains(setopt), "setopt {setopt:#x} inside .text");
}
