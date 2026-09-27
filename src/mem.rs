//! Reading a target's memory through one interface.
//!
//! The locator (`crate::locate`) and the PE reader (`crate::pe`) work against
//! any `MemReader`. In a test that is a byte slice; at runtime it is the live
//! game process. The same code reads both, so the parsing logic is verified
//! offline against a real dump before it ever attaches to a process.

use std::io;

/// Reads bytes from a target address space, addressed by virtual address.
///
/// Design by Contract: `read_exact` fills the whole buffer or returns `Err`. A
/// short read is an error, never a silent partial fill, so a caller never acts
/// on stale buffer bytes.
pub trait MemReader {
    /// Fill `buf` from `addr` onward. Errors if the whole range is not readable.
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Read `len` bytes from `addr` as an owned vector.
    fn read_vec(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(addr, &mut buf)?;
        Ok(buf)
    }

    /// Read a little-endian `u16`.
    fn read_u16(&self, addr: u64) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact_at(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    /// Read a little-endian `u32`.
    fn read_u32(&self, addr: u64) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact_at(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Read a little-endian `u64`.
    fn read_u64(&self, addr: u64) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact_at(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// A `MemReader` over an in-memory image laid out at `base`.
///
/// This models a memory-mapped PE: index 0 of `image` is virtual address
/// `base`. A dump taken with `pefile.get_memory_mapped_image()` has exactly
/// this shape, so tests read the real client the way the tracer reads the live
/// process.
pub struct SliceReader<'a> {
    base: u64,
    image: &'a [u8],
}

impl<'a> SliceReader<'a> {
    pub fn new(base: u64, image: &'a [u8]) -> Self {
        Self { base, image }
    }
}

impl MemReader for SliceReader<'_> {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = addr.checked_sub(self.base).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("address {addr:#x} below image base {:#x}", self.base),
            )
        })? as usize;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "length overflow"))?;
        let slice = self.image.get(start..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("range {addr:#x}..+{} past image end", buf.len()),
            )
        })?;
        buf.copy_from_slice(slice);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x140000000;

    fn reader() -> SliceReader<'static> {
        // bytes: 00 01 02 03 04 05 06 07 08 09 at BASE
        static IMG: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        SliceReader::new(BASE, &IMG)
    }

    #[test]
    fn reads_a_range_at_base_offset() {
        let r = reader();
        assert_eq!(r.read_vec(BASE + 2, 3).unwrap(), vec![2, 3, 4]);
    }

    #[test]
    fn reads_little_endian_words() {
        let r = reader();
        assert_eq!(r.read_u32(BASE).unwrap(), 0x03020100);
        assert_eq!(r.read_u64(BASE).unwrap(), 0x0706050403020100);
    }

    #[test]
    fn address_below_base_is_an_error() {
        let r = reader();
        assert!(r.read_vec(BASE - 1, 1).is_err());
    }

    #[test]
    fn reading_past_the_end_is_an_error_not_a_short_fill() {
        let r = reader();
        assert!(r.read_vec(BASE + 8, 4).is_err());
    }
}
