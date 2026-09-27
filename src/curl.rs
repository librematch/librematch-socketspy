//! Locate and interpret the game's statically-linked `curl_easy_setopt`.
//!
//! The RLink REST API (`aoe-api.worldsedgelink.com`, `POST /game/...`) goes
//! through libcurl, whose TLS backend is not the OpenSSL we hook — so the REST
//! is invisible to the OpenSSL and WinHTTP paths. libcurl is statically linked
//! and exports nothing, but every request sets its options through one function,
//! `curl_easy_setopt(handle, option, value)`. Hooking that one function captures
//! every request's URL, headers, and body.
//!
//! `curl_easy_setopt` has no export and no unique string of its own, so it is
//! located **structurally**, with no hardcoded address, by the calling
//! convention around it: callers load the option constant into `edx` before the
//! call. Every option in curl's *type-tagged* ranges (object 10xxx, function
//! 20xxx, off_t 30xxx, blob 40xxx) encodes as `mov edx, <imm>` (`BA` + imm32)
//! shortly before a `call`. Scanning `.text` for those and tallying, per call
//! target, how many *distinct* options reach it separates the real function
//! (reached by ~all option kinds) from a game wrapper (reached by only a few):
//! the target with the most distinct options, by a clear margin, is
//! `curl_easy_setopt`.
//!
//! This module holds the pure scan and the per-handle request tracker, both
//! unit-tested; the OS layer only sets the breakpoint and reads memory.

use crate::http::{self, Header};
use crate::rest::RestExchange;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

/// libcurl option numbers this tracer understands.
pub const CURLOPT_URL: u32 = 10002;
pub const CURLOPT_WRITEDATA: u32 = 10001;
pub const CURLOPT_POSTFIELDS: u32 = 10015;
pub const CURLOPT_COPYPOSTFIELDS: u32 = 10165;
pub const CURLOPT_HTTPHEADER: u32 = 10023;
pub const CURLOPT_CUSTOMREQUEST: u32 = 10036;
pub const CURLOPT_POSTFIELDSIZE: u32 = 60;
pub const CURLOPT_POST: u32 = 89;
pub const CURLOPT_WRITEFUNCTION: u32 = 20011;

/// One candidate `curl_easy_setopt` target and how strongly it voted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetoptCandidate {
    pub target: u64,
    /// How many *distinct* option constants are set through this target.
    pub distinct_options: usize,
    /// Total `mov edx, <opt>; call` sites reaching it.
    pub total_calls: usize,
}

/// True if `v` is a curl option in one of the type-tagged ranges, which are
/// distinctive enough not to collide with unrelated immediates near a `call`.
fn is_curl_option(v: u32) -> bool {
    matches!(v, 10_000..=10_999 | 20_000..=20_999 | 30_000..=30_999 | 40_000..=40_999)
}

/// Tally, per call target, the distinct type-tagged options set through it.
/// Sorted best-first: most distinct options, then most calls, then lowest
/// address (a deterministic tie-break).
pub fn setopt_candidates(text: &[u8], text_va: u64) -> Vec<SetoptCandidate> {
    const WINDOW: usize = 0x18;
    let mut votes: HashMap<u64, (HashSet<u32>, usize)> = HashMap::new();

    let mut i = 0usize;
    while i + 5 <= text.len() {
        // mov edx, imm32
        if text[i] != 0xBA {
            i += 1;
            continue;
        }
        let opt = u32::from_le_bytes([text[i + 1], text[i + 2], text[i + 3], text[i + 4]]);
        if !is_curl_option(opt) {
            i += 1;
            continue;
        }
        // Find the terminating `call rel32` after the option (and any other
        // argument moves) within a small window.
        let end = (i + 5 + WINDOW).min(text.len().saturating_sub(5));
        let mut j = i + 5;
        while j <= end {
            if text[j] == 0xE8 {
                let rel = i32::from_le_bytes([text[j + 1], text[j + 2], text[j + 3], text[j + 4]]);
                let after = text_va + (j as u64) + 5;
                let target = (after as i64).wrapping_add(rel as i64) as u64;
                let e = votes.entry(target).or_default();
                e.0.insert(opt);
                e.1 += 1;
                break;
            }
            j += 1;
        }
        i += 5;
    }

    let mut out: Vec<SetoptCandidate> = votes
        .into_iter()
        .map(|(target, (opts, total))| SetoptCandidate {
            target,
            distinct_options: opts.len(),
            total_calls: total,
        })
        .collect();
    out.sort_by(|a, b| {
        b.distinct_options
            .cmp(&a.distinct_options)
            .then(b.total_calls.cmp(&a.total_calls))
            .then(a.target.cmp(&b.target))
    });
    out
}

/// Find `curl_easy_setopt` in the executable bytes `text` mapped at `text_va`.
///
/// Pure over bytes so it is unit-tested without a process. Returns the target
/// reached by the most distinct options, provided it clears a floor and, when a
/// runner-up exists, wins by a margin; the full tally is logged either way.
pub fn locate_setopt(text: &[u8], text_va: u64) -> Option<u64> {
    /// Fewest distinct options a real `curl_easy_setopt` is set with.
    const MIN_DISTINCT: usize = 3;
    /// How far the winner must lead the runner-up to be unambiguous.
    const MARGIN: usize = 2;

    let cands = setopt_candidates(text, text_va);
    for c in &cands {
        debug!(
            target = format_args!("{:#x}", c.target),
            distinct = c.distinct_options,
            total = c.total_calls,
            "curl_easy_setopt candidate"
        );
    }
    let best = cands.first()?;
    if best.distinct_options < MIN_DISTINCT {
        warn!(
            distinct = best.distinct_options,
            "no curl_easy_setopt candidate set enough distinct options; giving up"
        );
        return None;
    }
    if let Some(second) = cands.get(1)
        && best.distinct_options < second.distinct_options + MARGIN
    {
        warn!(
            best = format_args!("{:#x}", best.target),
            best_distinct = best.distinct_options,
            second = format_args!("{:#x}", second.target),
            second_distinct = second.distinct_options,
            "curl_easy_setopt vote is close; picking the deterministic winner"
        );
    }
    Some(best.target)
}

/// Accumulates `curl_easy_setopt` calls per handle into REST requests.
///
/// libcurl reuses a handle, setting options before each transfer. A request's
/// URL is set once per transfer, so a new `CURLOPT_URL` on a handle finalizes
/// the previous request on that handle.
#[derive(Debug, Default)]
pub struct CurlTracker {
    open: std::collections::HashMap<u64, Partial>,
    done: Vec<RestExchange>,
    seq: u64,
}

#[derive(Debug, Clone, Default)]
struct Partial {
    ts_ms: u64,
    method: Option<String>,
    url: String,
    headers: Vec<Header>,
    body: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl CurlTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A `CURLOPT_URL` was set on `handle`. Starts a new request, finalizing any
    /// previous one on the same handle.
    pub fn on_url(&mut self, handle: u64, url: String, ts_ms: u64) {
        self.flush(handle);
        self.open.insert(
            handle,
            Partial {
                ts_ms,
                url,
                ..Default::default()
            },
        );
    }

    /// A `CURLOPT_CUSTOMREQUEST` (explicit method) was set.
    pub fn on_method(&mut self, handle: u64, method: String) {
        if let Some(p) = self.open.get_mut(&handle) {
            p.method = Some(method);
        }
    }

    /// A `CURLOPT_POST` flag was set (method is POST unless overridden).
    pub fn on_post(&mut self, handle: u64) {
        if let Some(p) = self.open.get_mut(&handle) {
            p.method.get_or_insert_with(|| "POST".to_string());
        }
    }

    /// A body was set (`CURLOPT_POSTFIELDS`/`COPYPOSTFIELDS`).
    pub fn on_body(&mut self, handle: u64, body: Vec<u8>) {
        if let Some(p) = self.open.get_mut(&handle) {
            p.method.get_or_insert_with(|| "POST".to_string());
            p.body = Some(body);
        }
    }

    /// Response bytes delivered to libcurl's write callback for `handle`.
    pub fn on_response(&mut self, handle: u64, data: &[u8]) {
        if let Some(p) = self.open.get_mut(&handle) {
            p.response.extend_from_slice(data);
        }
    }

    /// One header line from the `CURLOPT_HTTPHEADER` list.
    pub fn on_header(&mut self, handle: u64, line: &str) {
        if let Some(p) = self.open.get_mut(&handle)
            && let Some((name, value)) = line.split_once(':')
        {
            p.headers.push(Header {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            });
        }
    }

    /// Finalize the request in flight on `handle`, if any.
    pub fn flush(&mut self, handle: u64) {
        if let Some(p) = self.open.remove(&handle) {
            self.seq += 1;
            self.done.push(finish(self.seq, p));
        }
    }

    /// Finalize every request still in flight and return them in order.
    pub fn into_requests(mut self) -> Vec<RestExchange> {
        let handles: Vec<u64> = self.open.keys().copied().collect();
        for h in handles {
            self.flush(h);
        }
        self.done.sort_by_key(|e| e.seq);
        self.done
    }
}

fn finish(seq: u64, p: Partial) -> RestExchange {
    let (host, target) = split_url(&p.url);
    let (path, query) = http::split_target(&target);
    let method = p.method.unwrap_or_else(|| "GET".to_string());
    let (request_params, request_body_text) = match p.body {
        None => (Vec::new(), None),
        Some(b) => match String::from_utf8(b) {
            Ok(t) if http::is_form(&p.headers, &t) => (http::parse_form(&t), None),
            Ok(t) => (Vec::new(), Some(t)),
            Err(e) => (
                Vec::new(),
                Some(http::binary_placeholder(e.into_bytes().len())),
            ),
        },
    };
    let response_body = if p.response.is_empty() {
        None
    } else {
        Some(match std::str::from_utf8(&p.response) {
            Ok(t) => t.to_string(),
            Err(_) => http::binary_placeholder(p.response.len()),
        })
    };
    RestExchange {
        seq,
        ts_ms: p.ts_ms,
        method,
        host,
        target,
        path,
        query,
        request_headers: p.headers,
        request_params,
        request_body_text,
        response_body,
    }
}

/// Split a full URL into (host, target) where target is path plus query.
fn split_url(url: &str) -> (String, String) {
    let after_scheme = url.split_once("://").map(|x| x.1).unwrap_or(url);
    match after_scheme.split_once('/') {
        None => (after_scheme.to_string(), "/".to_string()),
        Some((host, rest)) => (host.to_string(), format!("/{rest}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::QueryParam;

    const TEXT_VA: u64 = 0x140001000;

    /// Emit a `curl_easy_setopt(handle, option, value)` call whose `call`
    /// targets `setopt_va`.
    fn emit_setopt(out: &mut Vec<u8>, at_va: u64, option: u32, setopt_va: u64) {
        // mov edx, option
        out.push(0xBA);
        out.extend_from_slice(&option.to_le_bytes());
        // mov r8, rsi   (some arg shuffling, 3 bytes)
        out.extend_from_slice(&[0x4C, 0x8B, 0xC6]);
        // call rel32
        let call_va = at_va + 8;
        let rel = (setopt_va as i64 - (call_va as i64 + 5)) as i32;
        out.push(0xE8);
        out.extend_from_slice(&rel.to_le_bytes());
    }

    /// Emit `count` sites reaching `setopt_va`, cycling through distinct options.
    fn emit_sites(text: &mut Vec<u8>, options: &[u32], setopt_va: u64) {
        for &opt in options {
            let at = TEXT_VA + text.len() as u64;
            emit_setopt(text, at, opt, setopt_va);
            text.extend_from_slice(&[0x90; 4]);
        }
    }

    #[test]
    fn locates_setopt_by_the_widest_distinct_option_vote() {
        // The real function is reached by many distinct options; a game wrapper
        // by only a few. The widest distinct-option vote wins by a clear margin.
        let real = 0x1400d0000;
        let wrapper = 0x1400e9999;
        let mut text = Vec::new();
        text.extend_from_slice(&[0x90; 16]);
        emit_sites(&mut text, &[10002, 10015, 10023, 10036, 20011, 10001], real);
        emit_sites(&mut text, &[10002, 10015], wrapper);
        assert_eq!(locate_setopt(&text, TEXT_VA), Some(real));
    }

    #[test]
    fn a_single_option_target_is_rejected_as_too_thin() {
        // One lone `mov edx, <opt>; call` is not enough to trust a target.
        let mut text = Vec::new();
        emit_sites(&mut text, &[10002], 0x1400d0000);
        assert_eq!(locate_setopt(&text, TEXT_VA), None);
    }

    #[test]
    fn a_tie_breaks_to_the_lowest_address_deterministically() {
        // Two targets, each reached by the same three distinct options: the
        // lower address wins, and it wins the same way every run.
        let low = 0x1400a0000;
        let high = 0x1400f0000;
        let mut text = Vec::new();
        emit_sites(&mut text, &[10002, 10015, 10023], high);
        emit_sites(&mut text, &[10002, 10015, 10023], low);
        assert_eq!(locate_setopt(&text, TEXT_VA), Some(low));
    }

    #[test]
    fn a_method_option_sets_the_verb_on_the_open_request() {
        let mut t = CurlTracker::new();
        let h = 0x55;
        t.on_url(h, "https://h/game/x".into(), 1);
        t.on_method(h, "PUT".into());
        let reqs = t.into_requests();
        assert_eq!(reqs[0].method, "PUT");
        // A method set on an unknown handle is a no-op (no request in flight).
        let mut t2 = CurlTracker::new();
        t2.on_method(0x99, "DELETE".into());
        assert!(t2.into_requests().is_empty());
    }

    #[test]
    fn tracker_builds_a_request_from_options() {
        let mut t = CurlTracker::new();
        let h = 0xABCD;
        t.on_url(
            h,
            "https://aoe-api.worldsedgelink.com/game/automatch2/polling".into(),
            5,
        );
        t.on_post(h);
        t.on_header(h, "Content-Type: application/x-www-form-urlencoded");
        t.on_body(h, b"callNum=1&relayRegion=eastus".to_vec());
        let reqs = t.into_requests();
        assert_eq!(reqs.len(), 1);
        let e = &reqs[0];
        assert_eq!(e.method, "POST");
        assert_eq!(e.host, "aoe-api.worldsedgelink.com");
        assert_eq!(e.path, "/game/automatch2/polling");
        assert_eq!(
            e.request_params,
            vec![
                QueryParam {
                    name: "callNum".into(),
                    value: "1".into()
                },
                QueryParam {
                    name: "relayRegion".into(),
                    value: "eastus".into()
                },
            ]
        );
    }

    #[test]
    fn response_bytes_attach_to_the_open_request() {
        let mut t = CurlTracker::new();
        let h = 0xABCD;
        t.on_url(h, "https://h/game/Leaderboard/get".into(), 1);
        t.on_response(h, b"[0,");
        t.on_response(h, b"\"ok\"]");
        let reqs = t.into_requests();
        assert_eq!(reqs[0].response_body.as_deref(), Some("[0,\"ok\"]"));
    }

    #[test]
    fn a_new_url_on_a_reused_handle_finalizes_the_previous_request() {
        let mut t = CurlTracker::new();
        let h = 1;
        t.on_url(h, "https://h/game/a".into(), 1);
        t.on_url(h, "https://h/game/b".into(), 2); // reuse: flushes /game/a
        let reqs = t.into_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].path, "/game/a");
        assert_eq!(reqs[1].path, "/game/b");
    }
}
