//! Bookkeeping for in-flight `ssl_read_internal` calls.
//!
//! A read's buffer is only filled when the call returns, so the tracer breaks
//! at entry to save the call, then breaks at the return address to read the
//! buffer. Several threads can be inside a read at once, and one thread can be
//! nested, so pending reads are keyed by thread and matched on return by the
//! stack pointer. This logic is pure and unit-tested; the `ptrace` layer only
//! feeds it events.

use crate::tracer::regs::ReadEntry;
use std::collections::{HashMap, HashSet};

/// The set of in-flight reads, grouped by thread id.
#[derive(Debug, Default)]
pub struct PendingReads {
    by_thread: HashMap<i32, Vec<ReadEntry>>,
}

impl PendingReads {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `tid` has entered a read.
    pub fn on_entry(&mut self, tid: i32, entry: ReadEntry) {
        self.by_thread.entry(tid).or_default().push(entry);
    }

    /// Take the pending read for `tid` that returns to `ret_addr` with stack
    /// pointer `rsp`. Matching on `rsp` selects the right frame when a thread
    /// has more than one read in flight.
    pub fn take_matching_return(&mut self, tid: i32, ret_addr: u64, rsp: u64) -> Option<ReadEntry> {
        let stack = self.by_thread.get_mut(&tid)?;
        let pos = stack
            .iter()
            .rposition(|e| e.ret_addr == ret_addr && e.ret_rsp == rsp)?;
        let entry = stack.remove(pos);
        if stack.is_empty() {
            self.by_thread.remove(&tid);
        }
        Some(entry)
    }

    /// Every return address that currently has a pending read. The tracer keeps
    /// a breakpoint at each of these and removes it once none remain.
    pub fn active_return_addresses(&self) -> HashSet<u64> {
        self.by_thread
            .values()
            .flatten()
            .map(|e| e.ret_addr)
            .collect()
    }

    /// The most recent pending read's return address for a thread, or `None` if
    /// the thread has no read in flight. A per-thread hardware breakpoint holds
    /// one return address at a time, so on a return the tracer re-points it at
    /// whatever remains (LIFO).
    pub fn newest_return_addr(&self, tid: i32) -> Option<u64> {
        self.by_thread
            .get(&tid)
            .and_then(|v| v.last())
            .map(|e| e.ret_addr)
    }

    /// Drop every pending read for a thread that has exited.
    pub fn forget_thread(&mut self, tid: i32) {
        self.by_thread.remove(&tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ret_addr: u64, ret_rsp: u64) -> ReadEntry {
        ReadEntry {
            buf: 0x1000 + ret_rsp,
            max: 0x4000,
            ret_addr,
            ret_rsp,
        }
    }

    #[test]
    fn matches_a_return_by_thread_and_stack_pointer() {
        let mut p = PendingReads::new();
        p.on_entry(7, entry(0xAAA, 0x100));
        assert!(p.take_matching_return(7, 0xAAA, 0x999).is_none()); // wrong rsp
        assert!(p.take_matching_return(9, 0xAAA, 0x100).is_none()); // wrong thread
        let got = p.take_matching_return(7, 0xAAA, 0x100).unwrap();
        assert_eq!(got.ret_rsp, 0x100);
        // Taken once only.
        assert!(p.take_matching_return(7, 0xAAA, 0x100).is_none());
    }

    #[test]
    fn handles_nested_reads_on_one_thread() {
        let mut p = PendingReads::new();
        p.on_entry(7, entry(0xAAA, 0x200)); // outer
        p.on_entry(7, entry(0xBBB, 0x180)); // inner returns first
        let inner = p.take_matching_return(7, 0xBBB, 0x180).unwrap();
        assert_eq!(inner.ret_rsp, 0x180);
        let outer = p.take_matching_return(7, 0xAAA, 0x200).unwrap();
        assert_eq!(outer.ret_rsp, 0x200);
    }

    #[test]
    fn tracks_which_return_addresses_are_live() {
        let mut p = PendingReads::new();
        p.on_entry(1, entry(0xAAA, 0x10));
        p.on_entry(2, entry(0xBBB, 0x20));
        assert_eq!(
            p.active_return_addresses(),
            [0xAAA, 0xBBB].into_iter().collect()
        );
        p.take_matching_return(1, 0xAAA, 0x10);
        assert_eq!(p.active_return_addresses(), [0xBBB].into_iter().collect());
    }

    #[test]
    fn newest_return_addr_is_the_last_entered_for_a_thread() {
        let mut p = PendingReads::new();
        assert_eq!(p.newest_return_addr(7), None);
        p.on_entry(7, entry(0xAAA, 0x200));
        p.on_entry(7, entry(0xBBB, 0x180));
        assert_eq!(p.newest_return_addr(7), Some(0xBBB));
        p.take_matching_return(7, 0xBBB, 0x180);
        assert_eq!(p.newest_return_addr(7), Some(0xAAA));
    }

    #[test]
    fn forgetting_a_thread_drops_its_reads() {
        let mut p = PendingReads::new();
        p.on_entry(1, entry(0xAAA, 0x10));
        p.forget_thread(1);
        assert!(p.active_return_addresses().is_empty());
    }
}
