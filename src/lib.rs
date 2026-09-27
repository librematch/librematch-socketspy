//! Libre:Match SocketSpy.
//!
//! Trace an AoE:DE client's TLS traffic and export the captured requests and
//! responses as structured JSON. The client sends over three stacks, each
//! hooked at the right layer: **OpenSSL** (the WebSocket traffic), **libcurl**
//! (the RLink REST API), and **WinHTTP** (Xbox/PlayFab/telemetry).
//!
//! The crate is split so that everything that parses bytes is
//! platform-independent and unit-tested on the build host, while the parts that
//! attach to a live process live behind a thin per-OS backend:
//!
//! - [`mem`] — read a target's memory through one interface (slice or process).
//! - [`pe`] — the minimal PE facts the locators need (sections, `.pdata`,
//!   imports and exports).
//! - [`locate`] — find OpenSSL's `SSL_read`/`SSL_write` in the target image.
//! - [`curl`] — find `curl_easy_setopt` and reconstruct libcurl REST requests.
//! - [`http`] — parse a captured buffer as HTTP/1.x (method, endpoint, params).
//! - [`rest`] — correlate WinHTTP calls into REST requests.
//! - [`capture`] — the record store and the structured JSON export.
//! - [`tracer`] — the shared trace session and the per-OS attach-and-breakpoint
//!   backends, with their tested support logic.

pub mod capture;
pub mod curl;
pub mod http;
pub mod locate;
pub mod mem;
pub mod pe;
pub mod rest;
pub mod tracer;
