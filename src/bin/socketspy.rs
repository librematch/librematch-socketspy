//! Libre:Match SocketSpy — wait for the AoE:DE client, attach, and capture its
//! TLS traffic to structured JSON.
//!
//! Start it before launching the game. It polls for the process, attaches when
//! it appears, and writes the JSON when the game exits.

use clap::Parser;
use socketspy::tracer::CaptureMode;
use socketspy::tracer::proc::DEFAULT_EXE;
use std::path::PathBuf;
use tracing::error;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Executable name to wait for.
    #[arg(long, default_value = DEFAULT_EXE)]
    exe: String,

    /// Directory to write the capture into. Two files are written: `wss.json`
    /// (the OpenSSL/WebSocket traffic) and `rest.json` (the libcurl RLink REST
    /// and WinHTTP traffic). Created if it does not exist.
    #[arg(short = 'd', long, default_value = ".")]
    dir: PathBuf,

    /// How often to poll for the process, in milliseconds.
    #[arg(long, default_value_t = 200)]
    poll_ms: u64,

    /// Attach to an already-running process id instead of polling by name.
    #[arg(long)]
    pid: Option<i32>,

    /// Which traffic to capture (only four hardware breakpoints exist, so the
    /// two stacks are captured in separate runs).
    #[arg(long, value_enum, default_value_t = CaptureMode::Rest)]
    capture: CaptureMode,

    /// Diagnostic: attach and locate but set no breakpoints. Use this to tell
    /// whether attaching alone destabilizes the game (it survives = the
    /// breakpoints are the cause; it dies = the attach is).
    #[arg(long)]
    no_breakpoints: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    if let Err(e) = run(args) {
        error!(error = %e, "socketspy failed");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run(args: Args) -> std::io::Result<()> {
    use socketspy::tracer::proc::{self, IMAGE_BASE, Target};
    use std::time::Duration;
    use tracing::info;

    let root = std::path::Path::new("/proc");
    let target = match args.pid {
        Some(pid) => {
            // Verify the process is mapped at the expected image base now, rather
            // than attaching and failing 30 s later in the locator.
            if !proc::maps_have_base(root, pid, IMAGE_BASE) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "pid {pid} has no mapping at the image base {IMAGE_BASE:#x}; \
                         is it an AoE:DE process?"
                    ),
                ));
            }
            Target {
                pid,
                base: IMAGE_BASE,
            }
        }
        None => {
            info!(exe = args.exe, "waiting for the game to start …");
            loop {
                if let Some(t) = proc::find_target(root, &args.exe, IMAGE_BASE) {
                    break t;
                }
                std::thread::sleep(Duration::from_millis(args.poll_ms));
            }
        }
    };
    std::fs::create_dir_all(&args.dir)?;
    info!(pid = target.pid, dir = %args.dir.display(), mode = ?args.capture, "found game; attaching");
    socketspy::tracer::linux::run(target, &args.dir, args.capture, !args.no_breakpoints)
}

#[cfg(windows)]
fn run(args: Args) -> std::io::Result<()> {
    use socketspy::tracer::windows as backend;
    use std::time::Duration;
    use tracing::info;

    let pid = match args.pid {
        Some(pid) => pid as u32,
        None => {
            info!(exe = args.exe, "waiting for the game to start …");
            loop {
                if let Some(pid) = backend::find_pid_by_name(&args.exe) {
                    break pid;
                }
                std::thread::sleep(Duration::from_millis(args.poll_ms));
            }
        }
    };
    std::fs::create_dir_all(&args.dir)?;
    info!(pid, dir = %args.dir.display(), mode = ?args.capture, "found game; attaching");
    backend::run(pid, &args.dir, args.capture, !args.no_breakpoints)
}
