//! Reading OpenSSL call arguments from a register snapshot.
//!
//! The game is a Windows x64 binary. Under Wine on Linux it still uses the
//! Windows calling convention, so the first four integer arguments are in
//! `RCX, RDX, R8, R9` on both platforms. Only the way the registers are read
//! differs per OS; this arithmetic is shared and pure, so it is unit-tested.

/// The registers the tracer needs at a breakpoint. Filled from `ptrace`'s
/// `user_regs_struct` on Linux and from `CONTEXT` on Windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Regs {
    /// Return value register, read at a function's return.
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rsp: u64,
    pub rip: u64,
}

/// Arguments of `ssl_write_internal(SSL*, const void *buf, size_t num, ...)`,
/// read on function entry, where the buffer is already filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteArgs {
    pub buf: u64,
    pub num: u64,
}

impl WriteArgs {
    pub fn from_entry(regs: &Regs) -> Self {
        Self {
            buf: regs.rdx,
            num: regs.r8,
        }
    }
}

/// Saved state of an `SSL_read(SSL*, void *buf, int num)` call, captured on
/// entry. The buffer is not filled until the call returns, so the tracer reads
/// it at the return address, where `SSL_read` reports the byte count in its
/// return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadEntry {
    pub buf: u64,
    /// The `num` argument: the buffer capacity, an upper bound on the count.
    pub max: u64,
    /// The return address, read from the top of the stack at entry.
    pub ret_addr: u64,
    /// The value `RSP` will hold when this call returns (entry `RSP` + 8, after
    /// the `ret` pops the return address). Distinguishes nested and concurrent
    /// calls that share a return address.
    pub ret_rsp: u64,
}

impl ReadEntry {
    /// Build from the entry registers and the return address read from
    /// `[RSP]`.
    pub fn from_entry(regs: &Regs, return_address: u64) -> Self {
        Self {
            buf: regs.rdx,
            max: regs.r8,
            ret_addr: return_address,
            ret_rsp: regs.rsp.wrapping_add(8),
        }
    }

    /// The number of bytes actually read, from `SSL_read`'s return value in
    /// `RAX` at the return. `SSL_read` returns a signed int: `<= 0` means no
    /// plaintext (a close or a retry), and a positive count never exceeds the
    /// buffer capacity.
    pub fn read_len(&self, return_regs: &Regs) -> u64 {
        let ret = return_regs.rax as i32 as i64;
        if ret <= 0 {
            0
        } else {
            (ret as u64).min(self.max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_args_come_from_rdx_and_r8() {
        let regs = Regs {
            rdx: 0x1000,
            r8: 298,
            ..Default::default()
        };
        assert_eq!(
            WriteArgs::from_entry(&regs),
            WriteArgs {
                buf: 0x1000,
                num: 298
            }
        );
    }

    #[test]
    fn read_entry_saves_buffer_capacity_and_return_frame() {
        let regs = Regs {
            rdx: 0x2000,
            r8: 0x4000,
            rsp: 0x7fff_ff00,
            ..Default::default()
        };
        let e = ReadEntry::from_entry(&regs, 0x140abcdef);
        assert_eq!(e.buf, 0x2000);
        assert_eq!(e.max, 0x4000);
        assert_eq!(e.ret_addr, 0x140abcdef);
        assert_eq!(e.ret_rsp, 0x7fff_ff08);
    }

    #[test]
    fn read_len_uses_the_return_value_clamped_to_capacity() {
        let e = ReadEntry {
            buf: 0x2000,
            max: 512,
            ret_addr: 0,
            ret_rsp: 0,
        };
        // A normal positive count.
        assert_eq!(
            e.read_len(&Regs {
                rax: 176,
                ..Default::default()
            }),
            176
        );
        // Zero or negative (close/retry) yields nothing.
        assert_eq!(
            e.read_len(&Regs {
                rax: 0,
                ..Default::default()
            }),
            0
        );
        assert_eq!(
            e.read_len(&Regs {
                rax: u64::MAX,
                ..Default::default()
            }),
            0
        ); // -1
        // A count is never trusted past the buffer capacity.
        assert_eq!(
            e.read_len(&Regs {
                rax: 100_000,
                ..Default::default()
            }),
            512
        );
    }
}
