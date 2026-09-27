//! The OS-independent trace session shared by both backends.
//!
//! Everything that decides *what* to do at a breakpoint lives here: the `DR7`
//! bookkeeping, the OpenSSL/libcurl/WinHTTP trap handling, the argument
//! decoding, and the JSON export. The two OS backends ([`super::linux`],
//! `super::windows`) supply only the primitives that genuinely differ, through
//! [`Backend`], and drive the event loop. This keeps the per-OS code thin and
//! stops the two from drifting apart.

use crate::capture::{Capture, Direction};
use crate::curl::{self, CurlTracker};
use crate::locate::SslFunctions;
use crate::mem::MemReader;
use crate::pe;
use crate::rest::{RestCapture, WinHttpTracker};
use crate::tracer::CaptureMode;
use crate::tracer::pending::PendingReads;
use crate::tracer::regs::{ReadEntry, Regs, WriteArgs};
use crate::tracer::strings::{self, MAX_BUFFER};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, warn};

/// Local-enable bits in `DR7`. `DR0`/`DR1` carry the mode's fixed hooks; `DR2`
/// and `DR3` are toggled per thread for the two kinds of return breakpoint.
/// RW/LEN fields stay 0 (1-byte execution).
const DR7_D0: u64 = 1 << 0; // curl_easy_setopt (rest mode)
const DR7_D0_D1: u64 = (1 << 0) | (1 << 2); // send + read entry (wss) / setopt + write cb (rest)
const DR7_L2: u64 = 1 << 4; // OpenSSL SSL_read return
const DR7_L3: u64 = 1 << 6; // WinHttpReadData return

/// The WinHTTP entry points hooked with software breakpoints, and what each
/// contributes to a reconstructed request.
#[derive(Clone, Copy, Debug)]
pub enum WinHttpFn {
    Connect,
    OpenRequest,
    SendRequest,
    ReadData,
}

/// The exported names, paired with the meaning above.
pub const WINHTTP_HOOKS: &[(&str, WinHttpFn)] = &[
    ("WinHttpConnect", WinHttpFn::Connect),
    ("WinHttpOpenRequest", WinHttpFn::OpenRequest),
    ("WinHttpSendRequest", WinHttpFn::SendRequest),
    ("WinHttpReadData", WinHttpFn::ReadData),
];

/// A `WinHttpReadData` call in flight on a thread, awaiting its return.
#[derive(Clone, Copy)]
struct WinHttpRead {
    /// The request handle (`hRequest`, RCX at entry), so the response attaches to
    /// the right request even if the read completes on another (pool) thread.
    handle: u64,
    /// The response buffer the call fills.
    buffer: u64,
    /// Pointer to the `DWORD` the call writes the byte count into.
    count_ptr: u64,
}

/// The OS primitives the shared session needs. Everything else is shared.
///
/// A `Backend` is also a [`MemReader`] over the tracee, so the PE and string
/// helpers read through it directly.
pub trait Backend: MemReader {
    /// Set debug register `n` (`DR0`–`DR3`, `DR6`, `DR7`) on a thread.
    fn set_debugreg(&self, tid: i32, n: usize, value: u64) -> io::Result<()>;
    /// Patch one byte of executable code (used only for the `winhttp.dll`
    /// software breakpoints), handling page protection and the instruction cache.
    fn write_code_byte(&self, addr: u64, byte: u8) -> io::Result<()>;
    /// The load base of the mapped `winhttp.dll`, for the export-table fallback
    /// when the game's import table does not resolve.
    fn winhttp_module_base(&self) -> Option<u64>;
    /// DLL basenames mapped in the target, for a diagnostic when WinHTTP is not
    /// found. Empty by default.
    fn loaded_modules(&self) -> Vec<String> {
        Vec::new()
    }
}

/// The running trace: the OS backend plus all the shared decision state.
pub struct Session<B: Backend> {
    os: B,
    pub pid: i32,
    /// Load base of the game module, for reading its import table.
    pub base: u64,
    mode: CaptureMode,
    out_dir: PathBuf,
    install: bool,
    // --- OpenSSL / WebSocket (hardware breakpoints, wss mode) ---
    capture: Capture,
    started: Instant,
    pending: PendingReads,
    write_addr: u64,
    read_addr: u64,
    armed: HashSet<i32>,
    read_ret: HashMap<i32, u64>,
    // --- libcurl / RLink REST (hardware breakpoints on setopt + write cb) ---
    curl_setopt: u64,
    curl: CurlTracker,
    /// The write callback address (`CURLOPT_WRITEFUNCTION`), 0 until seen.
    write_cb: u64,
    /// Per-thread fallback: the curl handle whose URL was last set on the thread.
    thread_handle: HashMap<i32, u64>,
    /// `CURLOPT_WRITEDATA` pointer → curl handle, the exact key the write
    /// callback carries in its fourth argument.
    writedata_handle: HashMap<u64, u64>,
    /// `CURLOPT_POSTFIELDSIZE` per handle, so a body with a NUL is read by length.
    curl_body_size: HashMap<u64, u64>,
    // --- WinHTTP / REST (software breakpoints on entry, DR3 on return) ---
    rest: WinHttpTracker,
    sw_bps: HashMap<u64, (WinHttpFn, u8)>,
    winhttp_reads: HashMap<i32, WinHttpRead>,
}

impl<B: Backend> Session<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        os: B,
        pid: i32,
        base: u64,
        mode: CaptureMode,
        funcs: SslFunctions,
        curl_setopt: u64,
        out_dir: PathBuf,
        install: bool,
    ) -> Self {
        Self {
            os,
            pid,
            base,
            mode,
            out_dir,
            install,
            capture: Capture::new(pid),
            started: Instant::now(),
            pending: PendingReads::new(),
            write_addr: funcs.ssl_write_internal.unwrap_or(0),
            read_addr: funcs.ssl_read.unwrap_or(0),
            armed: HashSet::new(),
            read_ret: HashMap::new(),
            curl_setopt,
            curl: CurlTracker::new(),
            write_cb: 0,
            thread_handle: HashMap::new(),
            writedata_handle: HashMap::new(),
            curl_body_size: HashMap::new(),
            rest: WinHttpTracker::new(),
            sw_bps: HashMap::new(),
            winhttp_reads: HashMap::new(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Shift the located hooks and the base by `delta`, if the module base moved
    /// between the pre-attach locate and the create-process event.
    pub fn rebase(&mut self, delta: u64) {
        for a in [
            &mut self.write_addr,
            &mut self.read_addr,
            &mut self.curl_setopt,
        ] {
            if *a != 0 {
                *a = a.wrapping_add(delta);
            }
        }
        self.base = self.base.wrapping_add(delta);
    }

    /// The software breakpoint at `addr`, if any (the WinHTTP kind and the
    /// original byte to restore when stepping over it).
    pub fn sw_breakpoint(&self, addr: u64) -> Option<(WinHttpFn, u8)> {
        self.sw_bps.get(&addr).copied()
    }

    /// The OS backend, for a backend-specific setup step (e.g. handing the
    /// Windows backend its process handle once the create-process event lands).
    pub fn backend(&self) -> &B {
        &self.os
    }

    // ---- hardware breakpoints (mode-dependent) ----

    /// The base `DR7` for the current mode: `DR0`+`DR1` in wss mode (send + read
    /// entry), just `DR0` in rest mode until the write callback is found.
    fn base_dr7(&self) -> u64 {
        match self.mode {
            CaptureMode::Wss => DR7_D0_D1,
            CaptureMode::Rest if self.write_cb != 0 => DR7_D0_D1,
            CaptureMode::Rest => DR7_D0,
        }
    }

    /// Compute and set a thread's `DR7` from the base plus the return breakpoints
    /// it currently has active, so toggling one does not clobber another.
    fn update_dr7(&self, tid: i32) {
        let mut v = self.base_dr7();
        if self.read_ret.contains_key(&tid) {
            v |= DR7_L2;
        }
        if self.winhttp_reads.contains_key(&tid) {
            v |= DR7_L3;
        }
        let _ = self.os.set_debugreg(tid, 7, v);
    }

    /// Arm `DR0`/`DR1` for the mode: OpenSSL send + read entry (wss), or
    /// `curl_easy_setopt` + write callback (rest).
    pub fn arm_thread(&mut self, tid: i32) {
        if !self.install || self.armed.contains(&tid) {
            return;
        }
        let ok = match self.mode {
            CaptureMode::Wss => self
                .os
                .set_debugreg(tid, 0, self.write_addr)
                .and_then(|_| self.os.set_debugreg(tid, 1, self.read_addr)),
            CaptureMode::Rest => self
                .os
                .set_debugreg(tid, 0, self.curl_setopt)
                .and_then(|_| self.os.set_debugreg(tid, 1, self.write_cb)),
        }
        .and_then(|_| self.os.set_debugreg(tid, 7, self.base_dr7()));
        match ok {
            Ok(()) => {
                self.armed.insert(tid);
                debug!(tid, "thread armed with hardware breakpoints");
            }
            Err(e) => warn!(tid, error = %e, "could not arm thread"),
        }
    }

    /// Drop all per-thread state for a thread that has exited.
    pub fn forget_thread(&mut self, tid: i32) {
        self.armed.remove(&tid);
        self.read_ret.remove(&tid);
        self.winhttp_reads.remove(&tid);
        self.thread_handle.remove(&tid);
        self.pending.forget_thread(tid);
    }

    /// Record the curl write-callback address and arm `DR1` on every armed thread
    /// so responses are captured from now on.
    fn set_write_cb(&mut self, cb: u64) {
        self.write_cb = cb;
        info!(
            cb = format_args!("{cb:#x}"),
            "found curl write callback; capturing responses"
        );
        let threads: Vec<i32> = self.armed.iter().copied().collect();
        for tid in threads {
            let _ = self.os.set_debugreg(tid, 1, cb);
            self.update_dr7(tid);
        }
    }

    // ---- WinHTTP software breakpoints ----

    /// Set `0xCC` breakpoints on the WinHTTP request-building functions.
    ///
    /// The address of each is taken from the game's own import address table
    /// (the game statically imports WinHTTP), so this needs neither the DLL's
    /// base nor how it is mapped. If the import table has no `winhttp.dll` (or is
    /// not yet bound), it falls back to the mapped module's export table. Failure
    /// is logged, not fatal: the primary stack still runs.
    pub fn install_winhttp_breakpoints(&mut self) {
        let module_base = self.os.winhttp_module_base();
        let mut any = false;
        for &(name, kind) in WINHTTP_HOOKS {
            match self.resolve_winhttp(name, module_base) {
                Some(addr) => match self.set_sw_bp(addr, kind) {
                    Ok(()) => {
                        any = true;
                        debug!(
                            name,
                            addr = format_args!("{addr:#x}"),
                            "WinHTTP breakpoint set"
                        );
                    }
                    Err(e) => warn!(name, error = %e, "could not set WinHTTP breakpoint"),
                },
                None => warn!(name, "could not resolve WinHTTP function"),
            }
        }
        if !any {
            warn!(
                loaded = ?self.os.loaded_modules(),
                "no WinHTTP hooks set; REST capture disabled for this run"
            );
        }
    }

    /// The runtime address of a WinHTTP function: the game's IAT first, then the
    /// mapped module's export table.
    fn resolve_winhttp(&self, name: &str, module_base: Option<u64>) -> Option<u64> {
        if let Ok(Some(addr)) = pe::resolve_import(&self.os, self.base, "winhttp.dll", name) {
            return Some(addr);
        }
        let base = module_base?;
        pe::resolve_export(&self.os, base, name).ok().flatten()
    }

    fn set_sw_bp(&mut self, addr: u64, kind: WinHttpFn) -> io::Result<()> {
        let mut b = [0u8; 1];
        self.os.read_exact_at(addr, &mut b)?;
        self.os.write_code_byte(addr, 0xCC)?;
        self.sw_bps.insert(addr, (kind, b[0]));
        Ok(())
    }

    // ---- breakpoint handling ----

    /// A hardware breakpoint fired. `DR6` says which register; `regs` is the
    /// thread's state at the trap.
    pub fn on_hw_trap(&mut self, tid: i32, dr6: u64, regs: &Regs) -> io::Result<()> {
        if dr6 & 0b001 != 0 {
            // DR0: OpenSSL send (wss) or curl_easy_setopt (rest).
            match self.mode {
                CaptureMode::Wss => {
                    let a = WriteArgs::from_entry(regs);
                    self.capture_buffer(Direction::Send, a.buf, a.num);
                }
                CaptureMode::Rest => self.on_curl_setopt(regs, tid),
            }
        } else if dr6 & 0b010 != 0 {
            // DR1: OpenSSL read entry (wss) or the curl write callback (rest).
            if self.mode == CaptureMode::Rest {
                self.on_curl_write(regs, tid);
                return Ok(());
            }
            let ret_addr = self.os.read_u64(regs.rsp)?;
            let entry = ReadEntry::from_entry(regs, ret_addr);
            self.pending.on_entry(tid, entry);
            let _ = self.os.set_debugreg(tid, 2, ret_addr);
            self.read_ret.insert(tid, ret_addr);
            self.update_dr7(tid);
        } else if dr6 & 0b100 != 0 {
            // DR2: an SSL_read returned; its buffer is now filled.
            if let Some(e) = self.pending.take_matching_return(tid, regs.rip, regs.rsp) {
                let n = e.read_len(regs);
                self.capture_buffer(Direction::Recv, e.buf, n);
            }
            match self.pending.newest_return_addr(tid) {
                Some(next) => {
                    let _ = self.os.set_debugreg(tid, 2, next);
                    self.read_ret.insert(tid, next);
                }
                None => {
                    let _ = self.os.set_debugreg(tid, 2, 0);
                    self.read_ret.remove(&tid);
                    self.update_dr7(tid);
                }
            }
        } else if dr6 & 0b1000 != 0 {
            // DR3: a WinHttpReadData returned. Its buffer is now filled and the
            // byte count is at the pointer we saved on entry.
            if let Some(r) = self.winhttp_reads.remove(&tid) {
                let n = self.os.read_u32(r.count_ptr).unwrap_or(0);
                let len = (n as usize).min(MAX_BUFFER);
                if r.buffer != 0
                    && len > 0
                    && let Ok(data) = self.os.read_vec(r.buffer, len)
                {
                    self.rest.on_read_data(r.handle, &data);
                }
            }
            let _ = self.os.set_debugreg(tid, 3, 0);
            self.update_dr7(tid);
        }
        Ok(())
    }

    /// The curl write callback fired (rest mode, `DR1`):
    /// `cb(char *ptr, size_t size, size_t nmemb, void *userdata)` — RCX=ptr,
    /// RDX=size, R8=nmemb, R9=userdata. Correlate by the `CURLOPT_WRITEDATA`
    /// pointer the game set, falling back to the per-thread handle.
    fn on_curl_write(&mut self, regs: &Regs, tid: i32) {
        let len = (regs.rdx.saturating_mul(regs.r8) as usize).min(MAX_BUFFER);
        let handle = self
            .writedata_handle
            .get(&regs.r9)
            .copied()
            .or_else(|| self.thread_handle.get(&tid).copied());
        if let Some(handle) = handle
            && regs.rcx != 0
            && len > 0
            && let Ok(data) = self.os.read_vec(regs.rcx, len)
        {
            self.curl.on_response(handle, &data);
        }
    }

    /// A WinHTTP entry breakpoint fired: decode its arguments and feed the REST
    /// tracker. Windows x64 ABI: integer args in RCX, RDX, R8, R9; the fifth in
    /// `[rsp+0x28]`.
    pub fn on_winhttp(&mut self, kind: WinHttpFn, regs: &Regs, tid: i32) -> io::Result<()> {
        match kind {
            WinHttpFn::Connect => {
                let host = strings::read_wstr(&self.os, regs.rdx);
                self.rest.on_connect(tid, host);
            }
            WinHttpFn::OpenRequest => {
                let verb = if regs.rdx == 0 {
                    "GET".to_string()
                } else {
                    strings::read_wstr(&self.os, regs.rdx)
                };
                let target = strings::read_wstr(&self.os, regs.r8);
                self.rest.on_open_request(tid, verb, target);
            }
            WinHttpFn::SendRequest => {
                let headers = strings::read_wstr_len(&self.os, regs.rdx, regs.r8 as u32);
                let opt_len = self.os.read_u32(regs.rsp + 0x28).unwrap_or(0);
                let body = strings::read_body(&self.os, regs.r9, opt_len);
                let ts = self.now_ms();
                self.rest
                    .on_send_request(tid, regs.rcx, &headers, &body, ts);
            }
            WinHttpFn::ReadData => {
                // The buffer (RDX) is filled by the time the call returns, and the
                // count is written to *R9. Break at the return (DR3) to read them.
                // WinHttpReadData(hRequest, lpBuffer, dwToRead, lpdwRead).
                let ret_addr = self.os.read_u64(regs.rsp)?;
                self.winhttp_reads.insert(
                    tid,
                    WinHttpRead {
                        handle: regs.rcx,
                        buffer: regs.rdx,
                        count_ptr: regs.r9,
                    },
                );
                let _ = self.os.set_debugreg(tid, 3, ret_addr);
                self.update_dr7(tid);
            }
        }
        Ok(())
    }

    /// A `curl_easy_setopt(handle, option, value)` call fired. Decode the option
    /// we care about and feed the curl tracker. Windows x64 ABI: RCX=handle,
    /// RDX=option, R8=value.
    fn on_curl_setopt(&mut self, regs: &Regs, tid: i32) {
        let handle = regs.rcx;
        let option = regs.rdx as u32;
        let value = regs.r8;
        match option {
            curl::CURLOPT_URL => {
                let url = strings::read_cstr(&self.os, value);
                let ts = self.now_ms();
                self.curl.on_url(handle, url, ts);
                // A new request on this handle: drop any size left from a prior
                // one so it cannot be applied to a later strlen-sized body.
                self.curl_body_size.remove(&handle);
                // The write callback runs on this thread during a blocking
                // transfer; remember which handle it belongs to as a fallback.
                self.thread_handle.insert(tid, handle);
            }
            curl::CURLOPT_WRITEDATA => {
                if value != 0 {
                    self.writedata_handle.insert(value, handle);
                }
            }
            curl::CURLOPT_WRITEFUNCTION => {
                if value != 0 && self.write_cb == 0 {
                    self.set_write_cb(value);
                }
            }
            curl::CURLOPT_CUSTOMREQUEST => {
                let method = strings::read_cstr(&self.os, value);
                self.curl.on_method(handle, method);
            }
            curl::CURLOPT_POST => self.curl.on_post(handle),
            curl::CURLOPT_POSTFIELDSIZE => {
                self.curl_body_size.insert(handle, value);
            }
            curl::CURLOPT_POSTFIELDS | curl::CURLOPT_COPYPOSTFIELDS => {
                // Read the body by its declared size when known (so a NUL in the
                // body is not a false terminator), else as a C string.
                let body = match self.curl_body_size.get(&handle).copied() {
                    Some(n) if (n as i64) > 0 => {
                        strings::read_body(&self.os, value, (n as usize).min(MAX_BUFFER) as u32)
                    }
                    _ => strings::read_cstr(&self.os, value).into_bytes(),
                };
                self.curl.on_body(handle, body);
            }
            curl::CURLOPT_HTTPHEADER => {
                // value is a curl_slist*: { char *data; curl_slist *next; }.
                let mut node = value;
                for _ in 0..256 {
                    if node == 0 {
                        break;
                    }
                    let data = self.os.read_u64(node).unwrap_or(0);
                    let next = self.os.read_u64(node + 8).unwrap_or(0);
                    if data != 0 {
                        let line = strings::read_cstr(&self.os, data);
                        self.curl.on_header(handle, &line);
                    }
                    node = next;
                }
            }
            _ => {}
        }
    }

    fn capture_buffer(&mut self, dir: Direction, buf: u64, num: u64) {
        let len = (num as usize).min(MAX_BUFFER);
        if buf == 0 || len == 0 {
            return;
        }
        match self.os.read_vec(buf, len) {
            Ok(bytes) => {
                let ts = self.now_ms();
                self.capture.record(dir, ts, &bytes);
            }
            Err(e) => warn!(?dir, error = %e, "could not read plaintext buffer"),
        }
    }

    // ---- shutdown ----

    /// Every thread with hardware breakpoints armed (for the backend's shutdown).
    pub fn armed_tids(&self) -> Vec<i32> {
        self.armed.iter().copied().collect()
    }

    /// Patch one code byte through the backend (used to step over a software
    /// breakpoint: restore, single-step, re-arm).
    pub fn patch_byte(&self, addr: u64, byte: u8) -> io::Result<()> {
        self.os.write_code_byte(addr, byte)
    }

    /// Restore every patched code byte and clear every thread's `DR7`, so the
    /// game is left un-booby-trapped when the tracer detaches. Best effort: each
    /// failure is logged, not fatal. The caller must have the threads stopped.
    pub fn disarm(&self) {
        for (&addr, &(_, orig)) in &self.sw_bps {
            if let Err(e) = self.os.write_code_byte(addr, orig) {
                warn!(addr = format_args!("{addr:#x}"), error = %e, "could not restore code byte");
            }
        }
        for &tid in &self.armed {
            let _ = self.os.set_debugreg(tid, 7, 0);
        }
    }

    /// Write both capture files. `wss.json` holds the OpenSSL WebSocket capture
    /// (wss mode); `rest.json` merges the RLink libcurl requests (rest mode) and
    /// the WinHTTP requests (both modes), re-sequenced in order.
    pub fn finish(self) -> io::Result<()> {
        let wss = self.out_dir.join("wss.json");
        let rest = self.out_dir.join("rest.json");
        let pid = self.pid;

        self.capture
            .write_json(io::BufWriter::new(File::create(&wss)?))?;

        let mut requests = self.rest.into_capture(pid).requests;
        requests.extend(self.curl.into_requests());
        for (i, r) in requests.iter_mut().enumerate() {
            r.seq = i as u64 + 1;
        }
        let rest_cap = RestCapture { pid, requests };
        rest_cap.write_json(io::BufWriter::new(File::create(&rest)?))?;

        info!(
            wss = %wss.display(),
            wss_records = self.capture.records.len(),
            rest = %rest.display(),
            rest_requests = rest_cap.requests.len(),
            "capture written"
        );
        Ok(())
    }
}

/// The DLL basenames mapped in a process, from its `/proc/<pid>/maps` (Linux
/// diagnostic). Shared here so the backend does not carry it inline.
pub fn loaded_dlls_from_maps(proc_root: &Path, pid: i32) -> Vec<String> {
    let mut names: Vec<String> =
        std::fs::read_to_string(proc_root.join(pid.to_string()).join("maps"))
            .into_iter()
            .flat_map(|maps| {
                maps.lines()
                    .filter_map(|l| {
                        // The path is columns 6+ and may contain spaces.
                        let path = l.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
                        let base = path.rsplit(['/', '\\']).next()?.to_string();
                        base.to_ascii_lowercase().ends_with(".dll").then_some(base)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
    names.sort();
    names.dedup();
    names
}
