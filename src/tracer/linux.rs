//! The Linux `ptrace` backend (for the game under Proton/Wine).
//!
//! Two capture paths run at once, because the game uses two TLS stacks:
//!
//! - **OpenSSL** carries the WebSocket traffic (presence and the battle-server
//!   relay). It lives in the game's integrity-protected `.text`, so it is hooked
//!   with **hardware breakpoints** (debug registers `DR0`–`DR2`) that modify no
//!   code. Captured to `wss.json`.
//! - **libcurl** carries the RLink REST API. `curl_easy_setopt` is also in
//!   protected code, so it too is hooked with a hardware breakpoint. Captured to
//!   `rest.json`.
//! - **WinHTTP** carries Xbox/PlayFab/telemetry. Its functions live in Wine's
//!   `winhttp.dll`, which the game does not integrity-check, so they are hooked
//!   with cheap **software breakpoints** (`0xCC`) on the function entries. Also
//!   captured to `rest.json`.
//!
//! All decisions come from [`super::session`] and the tested pure modules; this
//! layer only attaches, reads memory, and drives the event loop. It cannot be
//! unit-tested without a live tracee, so it is kept short and heavily logged.
//!
//! Runtime note: this needs `ptrace` permission — run it as the same user with
//! `kernel.yama.ptrace_scope=0`, or with `sudo`.

use crate::locate::{self, SslFunctions};
use crate::mem::MemReader;
use crate::pe::PeImage;
use crate::tracer::CaptureMode;
use crate::tracer::proc::{self, Target};
use crate::tracer::regs::Regs;
use crate::tracer::session::{self, Backend, Session};

use nix::errno::Errno;
use nix::libc;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// How long to wait for the client's code to decrypt before giving up.
const LOCATE_TIMEOUT: Duration = Duration::from_secs(30);
const LOCATE_POLL: Duration = Duration::from_millis(200);

/// Offset of `u_debugreg[0]` in `struct user` on x86-64. `DRn` is at
/// `DEBUGREG + n * 8`.
const DEBUGREG: libc::c_long = 848;
const EFLAGS_RF: u64 = 1 << 16;

/// Set by the `SIGINT` handler so the event loop can stop cleanly (restore the
/// game, write the capture) instead of leaving it booby-trapped.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_sigint_handler() {
    // SAFETY: the handler only sets an atomic flag, which is async-signal-safe.
    let _ = unsafe { signal::signal(Signal::SIGINT, SigHandler::Handler(on_sigint)) };
}

/// Reads a live process's memory through `/proc/<pid>/mem`.
pub struct ProcessReader {
    mem: File,
}

impl ProcessReader {
    pub fn open(pid: i32) -> io::Result<Self> {
        let mem = OpenOptions::new()
            .read(true)
            .open(format!("/proc/{pid}/mem"))?;
        Ok(Self { mem })
    }
}

impl MemReader for ProcessReader {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            match self.mem.read_at(&mut buf[done..], addr + done as u64) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("no bytes at {:#x}", addr + done as u64),
                    ));
                }
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// The Linux `ptrace` primitives the shared session needs.
struct LinuxBackend {
    reader: ProcessReader,
    /// `/proc/<pid>/mem` opened for writing, to patch software breakpoints.
    mem_w: File,
    pid: i32,
}

impl LinuxBackend {
    fn open(pid: i32) -> io::Result<Self> {
        let mem_w = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/mem"))?;
        Ok(Self {
            reader: ProcessReader::open(pid)?,
            mem_w,
            pid,
        })
    }
}

impl MemReader for LinuxBackend {
    fn read_exact_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.reader.read_exact_at(addr, buf)
    }
}

impl Backend for LinuxBackend {
    fn set_debugreg(&self, tid: i32, n: usize, value: u64) -> io::Result<()> {
        set_debugreg(tid, n, value)
    }

    fn write_code_byte(&self, addr: u64, byte: u8) -> io::Result<()> {
        self.mem_w.write_all_at(&[byte], addr)
    }

    fn winhttp_module_base(&self) -> Option<u64> {
        proc::find_module_base(Path::new("/proc"), self.pid, "winhttp.dll")
    }

    fn loaded_modules(&self) -> Vec<String> {
        session::loaded_dlls_from_maps(Path::new("/proc"), self.pid)
    }
}

/// Attach to the target, locate the hooks, capture until it exits or is
/// interrupted, then always restore the game and write the capture.
pub fn run(
    target: Target,
    out_dir: &Path,
    mode: CaptureMode,
    install_breakpoints: bool,
) -> io::Result<()> {
    install_sigint_handler();
    let reader = ProcessReader::open(target.pid)?;

    // Locate the function(s) this mode hooks, retrying while the code decrypts.
    let mut funcs = SslFunctions::default();
    let mut curl_setopt = 0u64;
    match mode {
        CaptureMode::Wss => {
            funcs = locate_with_retry("OpenSSL", &reader, target.base, |r, b| {
                let f = try_locate_ssl(r, b)?;
                if f.ready() { Ok(Some(f)) } else { Ok(None) }
            })?;
            info!(?funcs, "located OpenSSL functions");
        }
        CaptureMode::Rest => {
            curl_setopt = locate_with_retry("curl_easy_setopt", &reader, target.base, |r, b| {
                Ok(try_locate_curl(r, b))
            })?;
            info!(
                curl_setopt = format_args!("{curl_setopt:#x}"),
                "located curl_easy_setopt"
            );
        }
    }

    let threads = attach_all_threads(target.pid)?;
    info!(pid = target.pid, threads = threads.len(), "attached");

    let os = LinuxBackend::open(target.pid)?;
    let mut session = Session::new(
        os,
        target.pid,
        target.base,
        mode,
        funcs,
        curl_setopt,
        out_dir.to_path_buf(),
        install_breakpoints,
    );
    // Threads whose SIGSTOP we have already accounted for; a stop from a thread
    // not here is a fresh clone's initial SIGSTOP, to be swallowed.
    let mut known: HashSet<i32> = threads.iter().copied().collect();
    if install_breakpoints {
        for &t in &threads {
            session.arm_thread(t);
        }
        session.install_winhttp_breakpoints();
    } else {
        info!("diagnostic mode: no breakpoints set; only observing process lifetime");
    }
    for &t in &threads {
        let _ = ptrace::cont(Pid::from_raw(t), None);
    }

    let r = event_loop(&mut session, &mut known);
    shutdown(&mut session, target.pid);
    let w = session.finish();
    r.and(w)
}

/// Retry a locator while the client decrypts its code.
fn locate_with_retry<T>(
    what: &str,
    reader: &ProcessReader,
    base: u64,
    mut attempt: impl FnMut(&ProcessReader, u64) -> Result<Option<T>, String>,
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

fn try_locate_ssl(reader: &ProcessReader, base: u64) -> Result<SslFunctions, String> {
    let pe = PeImage::parse(reader, base).map_err(|e| e.to_string())?;
    locate::locate(reader, &pe).map_err(|e| e.to_string())
}

fn try_locate_curl(reader: &ProcessReader, base: u64) -> Option<u64> {
    let pe = PeImage::parse(reader, base).ok()?;
    let text = pe.executable_section()?;
    let bytes = reader.read_vec(text.va, text.size as usize).ok()?;
    crate::curl::locate_setopt(&bytes, text.va)
}

/// Attach to every thread of `pid`, re-scanning until a pass finds no new one,
/// so threads created during attach are not missed.
fn attach_all_threads(pid: i32) -> io::Result<Vec<i32>> {
    let mut attached: Vec<i32> = Vec::new();
    let mut seen: HashSet<i32> = HashSet::new();
    loop {
        let before = attached.len();
        for tid in list_threads(pid) {
            if !seen.insert(tid) {
                continue;
            }
            let p = Pid::from_raw(tid);
            if ptrace::attach(p).is_err() {
                continue;
            }
            if waitpid(p, Some(WaitPidFlag::__WALL)).is_err() {
                continue;
            }
            if ptrace::setoptions(
                p,
                Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACEEXIT,
            )
            .is_err()
            {
                continue;
            }
            attached.push(tid);
        }
        if attached.len() == before {
            break;
        }
    }
    if attached.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no threads to attach; is the process still running?",
        ));
    }
    Ok(attached)
}

fn list_threads(pid: i32) -> Vec<i32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .collect()
}

fn errno(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn set_debugreg(tid: i32, n: usize, value: u64) -> io::Result<()> {
    let offset = DEBUGREG + (n as libc::c_long) * 8;
    // SAFETY: POKEUSER on a stopped tracee at the fixed debug-register offset.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            tid,
            offset as *mut libc::c_void,
            value as *mut libc::c_void,
        )
    };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_debugreg(tid: i32, n: usize) -> io::Result<u64> {
    let offset = DEBUGREG + (n as libc::c_long) * 8;
    Errno::clear();
    // SAFETY: PEEKUSER on a stopped tracee at the fixed debug-register offset.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKUSER,
            tid,
            offset as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if r == -1 && Errno::last() != Errno::UnknownErrno {
        return Err(io::Error::last_os_error());
    }
    Ok(r as u64)
}

/// Pump ptrace events until the game exits, `SIGINT` is caught, or a wait fails.
fn event_loop(session: &mut Session<LinuxBackend>, known: &mut HashSet<i32>) -> io::Result<()> {
    loop {
        if STOP.load(Ordering::SeqCst) {
            info!("interrupted (SIGINT); stopping capture");
            return Ok(());
        }
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
            Err(Errno::EINTR) => continue, // e.g. our SIGINT: re-check STOP
            Err(Errno::ECHILD) => {
                info!("no traced threads remain; game gone");
                return Ok(());
            }
            Err(e) => return Err(errno(e)),
            Ok(status) => on_status(session, status, known)?,
        }
    }
}

fn on_status(
    session: &mut Session<LinuxBackend>,
    status: WaitStatus,
    known: &mut HashSet<i32>,
) -> io::Result<()> {
    match status {
        WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
            let tid = pid.as_raw();
            session.forget_thread(tid);
            known.remove(&tid);
        }
        WaitStatus::PtraceEvent(pid, _, _) => {
            let tid = pid.as_raw();
            known.insert(tid);
            session.arm_thread(tid);
            let _ = ptrace::cont(pid, None);
        }
        WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
            let tid = pid.as_raw();
            known.insert(tid);
            session.arm_thread(tid);
            on_trap(session, pid)?;
        }
        WaitStatus::Stopped(pid, Signal::SIGSTOP) => {
            let tid = pid.as_raw();
            session.arm_thread(tid);
            if known.insert(tid) {
                // First time we've seen this thread: a fresh clone's initial
                // SIGSTOP. Swallow it — forwarding it group-stops the game.
                let _ = ptrace::cont(pid, None);
            } else {
                let _ = ptrace::cont(pid, Some(Signal::SIGSTOP));
            }
        }
        WaitStatus::Stopped(pid, sig) => {
            let tid = pid.as_raw();
            known.insert(tid);
            session.arm_thread(tid);
            let _ = ptrace::cont(pid, Some(sig));
        }
        other => debug!(?other, "unhandled wait status"),
    }
    Ok(())
}

/// Handle a `SIGTRAP`: a hardware breakpoint (`DR6` set), a software breakpoint
/// (`rip-1` is a `0xCC` we planted), or someone else's.
fn on_trap(session: &mut Session<LinuxBackend>, pid: Pid) -> io::Result<()> {
    let tid = pid.as_raw();
    let dr6 = get_debugreg(tid, 6).unwrap_or(0);
    if dr6 & 0b1111 != 0 {
        let regs = read_regs(pid)?;
        session.on_hw_trap(tid, dr6, &regs)?;
        let _ = set_debugreg(tid, 6, 0);
        return resume_over_hw(pid);
    }

    let regs = read_regs(pid)?;
    let addr = regs.rip.wrapping_sub(1);
    if let Some((kind, orig)) = session.sw_breakpoint(addr) {
        session.on_winhttp(kind, &regs, tid)?;
        step_over_sw(session, pid, addr, orig)?;
        return Ok(());
    }

    // Not ours.
    let _ = ptrace::cont(pid, None);
    Ok(())
}

/// Restore the original byte, single-step over it, then re-arm the `0xCC`.
///
/// Wine delivers thread-suspension (`SIGUSR1`) and exception (`SIGSEGV`) signals
/// that can land in the single-step window; loop until the step's own `SIGTRAP`,
/// forwarding any other signal on the way.
fn step_over_sw(
    session: &mut Session<LinuxBackend>,
    pid: Pid,
    addr: u64,
    orig: u8,
) -> io::Result<()> {
    write_rip(pid, addr)?;
    session.patch_byte(addr, orig)?;
    let mut sig: Option<Signal> = None;
    loop {
        ptrace::step(pid, sig).map_err(errno)?;
        match waitpid(pid, Some(WaitPidFlag::__WALL)).map_err(errno)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => break,
            WaitStatus::Stopped(_, other) => sig = Some(other),
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
            _ => sig = None,
        }
    }
    session.patch_byte(addr, 0xCC)?;
    ptrace::cont(pid, None).map_err(errno)
}

/// Restore the game and detach, so it runs on cleanly after the tracer stops.
/// Skipped if the game is already gone (normal exit): there is nothing to undo.
fn shutdown(session: &mut Session<LinuxBackend>, main_pid: i32) {
    if signal::kill(Pid::from_raw(main_pid), None).is_err() {
        return; // game already gone; nothing to restore
    }
    let tids = session.armed_tids();
    // Stop each thread so its debug registers and the code bytes can be edited.
    for &tid in &tids {
        let p = Pid::from_raw(tid);
        let _ = signal::kill(p, Signal::SIGSTOP);
        let _ = waitpid(p, Some(WaitPidFlag::__WALL));
    }
    session.disarm();
    for &tid in &tids {
        let _ = ptrace::detach(Pid::from_raw(tid), None);
    }
    if tids.is_empty() {
        let _ = ptrace::detach(Pid::from_raw(main_pid), None);
    }
}

fn read_regs(pid: Pid) -> io::Result<Regs> {
    let r = ptrace::getregs(pid).map_err(errno)?;
    Ok(Regs {
        rax: r.rax,
        rcx: r.rcx,
        rdx: r.rdx,
        r8: r.r8,
        r9: r.r9,
        rsp: r.rsp,
        rip: r.rip,
    })
}

fn write_rip(pid: Pid, rip: u64) -> io::Result<()> {
    let mut r = ptrace::getregs(pid).map_err(errno)?;
    r.rip = rip;
    ptrace::setregs(pid, r).map_err(errno)
}

/// Set the resume flag and continue, so the instruction under a hardware
/// breakpoint runs once without re-triggering it.
fn resume_over_hw(pid: Pid) -> io::Result<()> {
    let mut r = ptrace::getregs(pid).map_err(errno)?;
    r.eflags |= EFLAGS_RF;
    ptrace::setregs(pid, r).map_err(errno)?;
    ptrace::cont(pid, None).map_err(errno)
}
