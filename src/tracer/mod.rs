//! Attaching to the running game and capturing its TLS plaintext.
//!
//! The pure, cross-platform pieces — argument extraction ([`regs`]), in-flight
//! read bookkeeping ([`pending`]), process discovery ([`proc`]), string reads
//! ([`strings`]) — are unit tested on the build host, as is the shared
//! [`session`]. The two per-OS backends only attach and drive the event loop:
//!
//! - [`linux`] uses `ptrace` and `/proc/<pid>/mem` (for Proton/Wine).
//! - `windows` uses the Debug API.

pub mod pending;
pub mod proc;
pub mod regs;
pub mod session;
pub mod strings;

/// Which traffic a run captures. Only four hardware breakpoints exist, so the
/// OpenSSL and libcurl stacks are captured in separate runs. Values on the CLI
/// are `wss` and `rest`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum CaptureMode {
    /// OpenSSL WebSocket traffic (presence + battle relay) to `wss.json`, plus
    /// WinHTTP (Xbox/PlayFab) to `rest.json`.
    Wss,
    /// RLink REST via libcurl (aoe-api /game/...) plus WinHTTP, to `rest.json`.
    Rest,
}

#[cfg(unix)]
pub mod linux;

#[cfg(windows)]
pub mod windows;
