//! The Windows Debug API backend (for the game running natively on Windows).
//!
//! It shares every decision with [`super::session`] and the tested pure modules;
//! only the OS calls differ from the Linux backend: the Debug API instead of
//! `ptrace`, `ReadProcessMemory` instead of `/proc/<pid>/mem`, and thread
//! `CONTEXT` instead of `user_regs_struct`.
//!
//! The game uses two heavy TLS stacks and only four CPU debug registers exist,
//! so a run captures one, chosen by [`CaptureMode`]:
//!
//! - **OpenSSL** (`--capture wss`) — the WebSocket traffic, in protected code,
//!   hooked with hardware breakpoints (`DR0`–`DR2`). Captured to `wss.json`.
//! - **libcurl** (`--capture rest`) — the RLink REST API; `curl_easy_setopt` is
//!   also protected, so `DR0` hooks it and `DR1` its write callback. Captured to
//!   `rest.json`.
//! - **WinHTTP** (both modes) — Xbox/PlayFab/telemetry, in the OS `winhttp.dll`,
//!   hooked with software breakpoints (`0xCC`); the `WinHttpReadData` return, in
//!   protected game code, uses `DR3`. Captured to `rest.json`.
//!
//! Hooks are located **structurally** and **before attaching** (attaching
//! freezes the process, so it must finish decrypting first). This backend
//! compiles and cross-checks, but can only be exercised against the game on
//! Windows.

use crate::locate::{self, SslFunctions};
use crate::mem::MemReader;
use crate::pe::PeImage;
use crate::tracer::CaptureMode;
use crate::tracer::regs::Regs;
use crate::tracer::session::{Backend, Session};

use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent,
    DEBUG_EVENT, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    FlushInstructionCache, GetThreadContext, LOAD_DLL_DEBUG_EVENT, ReadProcessMemory,
    SetThreadContext, WaitForDebugEventEx, WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_ALL_ACCESS,
};

/// How long to wait for the client's code to decrypt before giving up.
const LOCATE_TIMEOUT: Duration = Duration::from_secs(30);
const LOCATE_POLL: Duration = Duration::from_millis(200);

const DBG_CONTINUE: i32 = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001u32 as i32;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
/// `WaitForDebugEventEx` timed out (no event within the poll interval).
const ERROR_SEM_TIMEOUT: u32 = 121;
/// Poll interval for the debug loop, so `SIGINT`/Ctrl-C is noticed promptly.
const WAIT_POLL_MS: u32 = 200;

/// `CONTEXT` part selectors for AMD64. `Get`/`SetThreadContext` read or write
/// only the parts named in `ContextFlags`.
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1; // Rip, Rsp, EFlags, SegCs/Ss
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2; // Rax, Rcx, Rdx, R8, R9, …
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10; // Dr0–Dr7

/// The single-step (trap) flag, used to step over a software breakpoint.
const TRAP_FLAG: u32 = 0x100;
/// The resume flag: suppresses a hardware breakpoint for one instruction so the
/// instruction under it runs once without re-triggering.
const EFLAGS_RF: u32 = 1 << 16;

/// Set by the console Ctrl handler so the debug loop can stop cleanly.
static STOP: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn ctrl_handler(_: u32) -> i32 {
    STOP.store(true, Ordering::SeqCst);
    1 // handled
}

fn install_ctrl_handler() {
    // SAFETY: the handler only sets an atomic flag.
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
}

/// Find a running process by executable name (case-insensitive).
pub fn find_pid_by_name(exe: &str) -> Option<u32> {
    // SAFETY: standard ToolHelp snapshot walk; handles are checked and closed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                if wide_to_string(&entry.szExeFile).eq_ignore_ascii_case(exe) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

/// Walk the module snapshot of `pid`, returning the base of the first module
/// `pick` accepts. Retries the snapshot: at process creation it commonly fails
/// with a partial-copy error until the module list settles.
fn snapshot_module(pid: u32, mut pick: impl FnMut(&MODULEENTRY32W) -> bool) -> Option<u64> {
    let deadline = Instant::now() + LOCATE_TIMEOUT;
    loop {
        // SAFETY: standard ToolHelp module walk; the snapshot handle is closed.
        let out = unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snap.is_null() || snap as isize == -1 {
                None
            } else {
                let mut e: MODULEENTRY32W = std::mem::zeroed();
                e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
                let mut found = None;
                if Module32FirstW(snap, &mut e) != 0 {
                    loop {
                        if pick(&e) {
                            found = Some(e.modBaseAddr as u64);
                            break;
                        }
                        if Module32NextW(snap, &mut e) == 0 {
                            break;
                        }
                    }
                }
                CloseHandle(snap);
                found
            }
        };
        if out.is_some() || Instant::now() >= deadline {
            return out;
        }
        std::thread::sleep(LOCATE_POLL);
    }
}

/// The load base of the process's own executable (the first module).
fn find_main_module_base(pid: u32) -> Option<u64> {
    snapshot_module(pid, |_| true)
}

/// The load base of a named module (e.g. `winhttp.dll`), for the export-table
/// fallback when the game's import table does not resolve.
fn find_module_base_by_name(pid: u32, name: &str) -> Option<u64> {
    snapshot_module(pid, |e| {
        wide_to_string(&e.szModule).eq_ignore_ascii_case(name)
    })
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
}

/// The Windows Debug API primitives the shared session needs. The process handle
/// is filled from the create-process event, so it is held with interior
/// mutability.
struct WindowsBackend {
    process: Cell<HANDLE>,
    pid: u32,
}

impl WindowsBackend {
    fn new(pid: u32) -> Self {
        Self {
            process: Cell::new(std::ptr::null_mut()),
            pid,
        }
    }

    fn set_process(&self, h: HANDLE) {
        self.process.set(h);
    }

    fn process(&self) -> HANDLE {
        self.process.get()
    }
}

impl MemReader for WindowsBackend {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut read = 0usize;
        // SAFETY: reading into our own buffer from a process we opened.
        let ok = unsafe {
            ReadProcessMemory(
                self.process(),
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                &mut read,
            )
        };
        if ok == 0 || read != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("read {read} of {} bytes at {addr:#x}", buf.len()),
            ));
        }
        Ok(())
    }
}

impl Backend for WindowsBackend {
    fn set_debugreg(&self, tid: i32, n: usize, value: u64) -> io::Result<()> {
        set_debugreg(tid as u32, n, value)
    }

    fn write_code_byte(&self, addr: u64, byte: u8) -> io::Result<()> {
        write_byte(self.process(), addr, byte)
    }

    fn winhttp_module_base(&self) -> Option<u64> {
        find_module_base_by_name(self.pid, "winhttp.dll")
    }
}

/// Attach to `pid`, capture until it exits or is interrupted, then always
/// restore the game and write `wss.json` and `rest.json` into `out_dir`.
pub fn run(
    pid: u32,
    out_dir: &Path,
    mode: CaptureMode,
    install_breakpoints: bool,
) -> io::Result<()> {
    install_ctrl_handler();
    let base = find_main_module_base(pid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not find the game's main module",
        )
    })?;
    info!(base = format_args!("{base:#x}"), "found game module base");

    // Locate before attaching, retrying while the client decrypts its code.
    let os = WindowsBackend::new(pid);
    // SAFETY: OpenProcess for read/query; the handle is closed after locate.
    let pre = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
    if pre.is_null() {
        return Err(last_error());
    }
    os.set_process(pre);
    let mut funcs = SslFunctions::default();
    let mut curl_setopt = 0u64;
    let located = match mode {
        CaptureMode::Wss => locate_with_retry("OpenSSL", &os, base, |r, b| {
            let f = try_locate_ssl(r, b)?;
            if f.ready() { Ok(Some(f)) } else { Ok(None) }
        })
        .map(|f| {
            info!(?f, "located OpenSSL functions");
            funcs = f;
        }),
        CaptureMode::Rest => locate_with_retry("curl_easy_setopt", &os, base, |r, b| {
            Ok(try_locate_curl(r, b))
        })
        .map(|c| {
            info!(
                curl_setopt = format_args!("{c:#x}"),
                "located curl_easy_setopt"
            );
            curl_setopt = c;
        }),
    };
    unsafe { CloseHandle(pre) };
    os.set_process(std::ptr::null_mut());
    located?;

    // SAFETY: DebugActiveProcess on a pid we intend to trace; paired with the
    // event loop that consumes every event.
    if unsafe { DebugActiveProcess(pid) } == 0 {
        return Err(last_error());
    }
    // Leave the game running if the tracer detaches.
    unsafe { DebugSetProcessKillOnExit(0) };

    let session = Session::new(
        os,
        pid as i32,
        base,
        mode,
        funcs,
        curl_setopt,
        out_dir.to_path_buf(),
        install_breakpoints,
    );
    let mut tracer = WinTracer {
        session,
        install: install_breakpoints,
        stepping: HashMap::new(),
    };
    let res = tracer.event_loop();
    if !matches!(res, Ok(true)) {
        tracer.shutdown();
    }
    let w = tracer.session.finish();
    res.map(|_| ()).and(w)
}

/// Retry a locator while the client decrypts its code.
fn locate_with_retry<T>(
    what: &str,
    reader: &dyn MemReader,
    base: u64,
    mut attempt: impl FnMut(&dyn MemReader, u64) -> Result<Option<T>, String>,
) -> io::Result<T> {
    let deadline = Instant::now() + LOCATE_TIMEOUT;
    loop {
        let last = match attempt(reader, base) {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => "not found yet".to_string(),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("gave up locating {what} after {LOCATE_TIMEOUT:?}: {last}"),
            ));
        }
        debug!(what, reason = %last, "not located yet; the code may still be decrypting");
        std::thread::sleep(LOCATE_POLL);
    }
}

fn try_locate_ssl(reader: &dyn MemReader, base: u64) -> Result<SslFunctions, String> {
    let pe = PeImage::parse(reader, base).map_err(|e| e.to_string())?;
    locate::locate(reader, &pe).map_err(|e| e.to_string())
}

fn try_locate_curl(reader: &dyn MemReader, base: u64) -> Option<u64> {
    let pe = PeImage::parse(reader, base).ok()?;
    let text = pe.executable_section()?;
    let bytes = reader.read_vec(text.va, text.size as usize).ok()?;
    crate::curl::locate_setopt(&bytes, text.va)
}

/// The running trace: the shared session plus the Windows-only step-over state.
struct WinTracer {
    session: Session<WindowsBackend>,
    install: bool,
    /// Threads mid-step-over of a software breakpoint: the address to re-arm on
    /// their next single-step, keyed by thread id.
    stepping: HashMap<u32, u64>,
}

impl WinTracer {
    /// Pump debug events until the process exits (returns `true`), Ctrl-C is
    /// caught (returns `false`), or a wait fails.
    fn event_loop(&mut self) -> io::Result<bool> {
        loop {
            if STOP.load(Ordering::SeqCst) {
                info!("interrupted (Ctrl-C); stopping capture");
                return Ok(false);
            }
            let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            if unsafe { WaitForDebugEventEx(&mut ev, WAIT_POLL_MS) } == 0 {
                let e = unsafe { GetLastError() };
                if e == ERROR_SEM_TIMEOUT {
                    continue; // no event this interval; re-check STOP
                }
                return Err(io::Error::from_raw_os_error(e as i32));
            }
            let mut status = DBG_CONTINUE;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => self.on_create_process(&ev)?,
                CREATE_THREAD_DEBUG_EVENT => self.session.arm_thread(ev.dwThreadId as i32),
                LOAD_DLL_DEBUG_EVENT => {
                    // The debugger owns the image-file handle; close it.
                    let h = unsafe { ev.u.LoadDll.hFile };
                    if !h.is_null() {
                        unsafe { CloseHandle(h) };
                    }
                }
                EXCEPTION_DEBUG_EVENT => status = self.on_exception(&ev)?,
                EXIT_THREAD_DEBUG_EVENT => {
                    self.session.forget_thread(ev.dwThreadId as i32);
                    self.stepping.remove(&ev.dwThreadId);
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    info!("game exited");
                    unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE) };
                    return Ok(true);
                }
                _ => {}
            }
            unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status) };
        }
    }

    fn on_create_process(&mut self, ev: &DEBUG_EVENT) -> io::Result<()> {
        // SAFETY: this union arm is valid for a create-process event.
        let info = unsafe { ev.u.CreateProcessInfo };
        self.session.backend().set_process(info.hProcess);
        let event_base = info.lpBaseOfImage as u64;
        if event_base != self.session.base {
            warn!(
                preattach = format_args!("{:#x}", self.session.base),
                event = format_args!("{event_base:#x}"),
                "module base moved since locate; rebasing hooks"
            );
            self.session
                .rebase(event_base.wrapping_sub(self.session.base));
        }
        info!(
            base = format_args!("{:#x}", self.session.base),
            "attached; process created"
        );

        if self.install {
            self.session.arm_thread(ev.dwThreadId as i32);
            self.session.install_winhttp_breakpoints();
        } else {
            info!("diagnostic mode: no breakpoints set; only observing process lifetime");
        }
        // The debugger owns the image-file handle; close it.
        if !info.hFile.is_null() {
            unsafe { CloseHandle(info.hFile) };
        }
        Ok(())
    }

    fn on_exception(&mut self, ev: &DEBUG_EVENT) -> io::Result<i32> {
        // SAFETY: valid union arm for an exception event.
        let er = unsafe { ev.u.Exception.ExceptionRecord };
        let tid = ev.dwThreadId;
        match er.ExceptionCode as u32 {
            EXCEPTION_BREAKPOINT => {
                // A software breakpoint: our `winhttp.dll` `0xCC` patches, or the
                // loader's initial breakpoint (not in `sw_bps`).
                let addr = er.ExceptionAddress as u64;
                if let Some((kind, orig)) = self.session.sw_breakpoint(addr) {
                    let ctx = get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
                    let regs = context_to_regs(&ctx.0);
                    self.session.on_winhttp(kind, &regs, tid as i32)?;
                    self.begin_step_over(tid, addr, orig)?;
                }
                Ok(DBG_CONTINUE)
            }
            EXCEPTION_SINGLE_STEP => {
                // Both a hardware breakpoint and a step-over land here; `DR6`
                // distinguishes them.
                let dr6 = get_debugreg(tid, 6).unwrap_or(0);
                if dr6 & 0b1111 != 0 {
                    let ctx = get_context(tid, CONTEXT_CONTROL | CONTEXT_INTEGER)?;
                    let regs = context_to_regs(&ctx.0);
                    self.session.on_hw_trap(tid as i32, dr6, &regs)?;
                    resume_over_hw(tid)?;
                    return Ok(DBG_CONTINUE);
                }
                if let Some(addr) = self.stepping.remove(&tid) {
                    self.session.patch_byte(addr, 0xCC)?; // re-arm after stepping over
                }
                Ok(DBG_CONTINUE)
            }
            _ => Ok(DBG_EXCEPTION_NOT_HANDLED),
        }
    }

    /// Restore the original byte and single-step over a software breakpoint; the
    /// resulting single-step re-arms the `0xCC` (see [`Self::on_exception`]).
    fn begin_step_over(&mut self, tid: u32, addr: u64, orig: u8) -> io::Result<()> {
        self.session.patch_byte(addr, orig)?;
        let mut ctx = get_context(tid, CONTEXT_CONTROL)?;
        ctx.0.Rip = addr;
        ctx.0.EFlags |= TRAP_FLAG;
        ctx.0.ContextFlags = CONTEXT_CONTROL;
        set_context(tid, &ctx.0)?;
        self.stepping.insert(tid, addr);
        Ok(())
    }

    /// Restore the game and detach, so it runs on cleanly after the tracer stops.
    fn shutdown(&mut self) {
        self.session.disarm();
        unsafe { DebugActiveProcessStop(self.session.pid as u32) };
    }
}

/// Write one byte into the (executable) code page, adjusting protection around
/// the write and flushing the instruction cache. Used only for the `winhttp.dll`
/// software breakpoints.
fn write_byte(process: HANDLE, addr: u64, byte: u8) -> io::Result<()> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    // SAFETY: standard debugger code patch: make the page writable, write one
    // byte, restore protection, flush the icache.
    unsafe {
        if VirtualProtectEx(
            process,
            addr as *const _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        ) == 0
        {
            return Err(last_error());
        }
        let mut written = 0usize;
        let ok = WriteProcessMemory(
            process,
            addr as *const _,
            [byte].as_ptr() as *const _,
            1,
            &mut written,
        );
        let mut discard: PAGE_PROTECTION_FLAGS = 0;
        VirtualProtectEx(process, addr as *const _, 1, old, &mut discard);
        if ok == 0 || written != 1 {
            return Err(last_error());
        }
        FlushInstructionCache(process, addr as *const _, 1);
    }
    Ok(())
}

/// A `CONTEXT` guaranteed 16-byte aligned, as `Get`/`SetThreadContext` require.
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

/// Fetch a thread's `CONTEXT`, reading only the parts named in `flags`.
fn get_context(tid: u32, flags: u32) -> io::Result<AlignedContext> {
    // SAFETY: open the thread, fetch its context with the requested flags.
    unsafe {
        let h = OpenThread(THREAD_ALL_ACCESS, 0, tid);
        if h.is_null() {
            return Err(last_error());
        }
        let mut ctx = AlignedContext(std::mem::zeroed());
        ctx.0.ContextFlags = flags;
        let ok = GetThreadContext(h, &mut ctx.0);
        CloseHandle(h);
        if ok == 0 {
            return Err(last_error());
        }
        Ok(ctx)
    }
}

/// Write a thread's `CONTEXT`, writing only the parts named in its
/// `ContextFlags`.
fn set_context(tid: u32, ctx: &CONTEXT) -> io::Result<()> {
    // SAFETY: open the thread and set the context we fetched and edited.
    unsafe {
        let h = OpenThread(THREAD_ALL_ACCESS, 0, tid);
        if h.is_null() {
            return Err(last_error());
        }
        let ok = SetThreadContext(h, ctx);
        CloseHandle(h);
        if ok == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

/// Set debug register `n` (`DR0`–`DR3`, `DR6`, `DR7`) on a thread.
fn set_debugreg(tid: u32, n: usize, value: u64) -> io::Result<()> {
    let mut ctx = get_context(tid, CONTEXT_DEBUG_REGISTERS)?;
    match n {
        0 => ctx.0.Dr0 = value,
        1 => ctx.0.Dr1 = value,
        2 => ctx.0.Dr2 = value,
        3 => ctx.0.Dr3 = value,
        6 => ctx.0.Dr6 = value,
        7 => ctx.0.Dr7 = value,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "debug register index out of range",
            ));
        }
    }
    ctx.0.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    set_context(tid, &ctx.0)
}

/// Read debug register `n` (only `DR6`, the status register, is needed).
fn get_debugreg(tid: u32, n: usize) -> io::Result<u64> {
    let ctx = get_context(tid, CONTEXT_DEBUG_REGISTERS)?;
    Ok(match n {
        0 => ctx.0.Dr0,
        1 => ctx.0.Dr1,
        2 => ctx.0.Dr2,
        3 => ctx.0.Dr3,
        6 => ctx.0.Dr6,
        7 => ctx.0.Dr7,
        _ => 0,
    })
}

/// Set the resume flag and clear `DR6`, so the instruction under a hardware
/// breakpoint runs once without re-triggering it.
fn resume_over_hw(tid: u32) -> io::Result<()> {
    let mut ctx = get_context(tid, CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS)?;
    ctx.0.EFlags |= EFLAGS_RF;
    ctx.0.Dr6 = 0;
    ctx.0.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    set_context(tid, &ctx.0)
}

fn context_to_regs(ctx: &CONTEXT) -> Regs {
    Regs {
        rax: ctx.Rax,
        rcx: ctx.Rcx,
        rdx: ctx.Rdx,
        r8: ctx.R8,
        r9: ctx.R9,
        rsp: ctx.Rsp,
        rip: ctx.Rip,
    }
}
