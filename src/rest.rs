//! WinHTTP capture: correlating WinHTTP calls into HTTP requests.
//!
//! WinHTTP carries the game's Xbox/PlayFab/telemetry traffic (its TLS is
//! SChannel, invisible to an OpenSSL hook; the RLink REST API goes through
//! libcurl instead — see [`crate::curl`]). The plaintext is available at the
//! WinHTTP API boundary, spread across several calls:
//!
//! - `WinHttpConnect` gives the host.
//! - `WinHttpOpenRequest` gives the verb and path.
//! - `WinHttpSendRequest` gives the request headers and body.
//!
//! Those calls happen in order on the sending thread as it builds a request, so
//! host and (verb, path) are tracked **per thread** and combined at
//! `WinHttpSendRequest` into one [`RestExchange`]. The response, though, is
//! matched by the request handle (`hRequest`), so a `WinHttpReadData` served on
//! a different pool thread still attaches to the right request. This reads no
//! memory and calls no OS API, so it is unit-tested with synthetic event
//! sequences; the OS layer only feeds it decoded arguments.

use crate::http::{self, Header, QueryParam};
use serde::Serialize;

/// One HTTP request reconstructed from WinHTTP calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestExchange {
    pub seq: u64,
    pub ts_ms: u64,
    pub method: String,
    pub host: String,
    /// The request target as passed to `WinHttpOpenRequest` (path plus query).
    pub target: String,
    pub path: String,
    pub query: Vec<QueryParam>,
    pub request_headers: Vec<Header>,
    /// Form-urlencoded request body parsed into parameters, when it is a form.
    pub request_params: Vec<QueryParam>,
    /// The request body as text when it is not form-urlencoded (e.g. JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_text: Option<String>,
    /// The response body, accumulated from `WinHttpReadData`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}

/// The whole WinHTTP capture, serialized to `rest.json` on close.
#[derive(Debug, Clone, Serialize)]
pub struct RestCapture {
    pub pid: i32,
    pub requests: Vec<RestExchange>,
}

impl RestCapture {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("rest capture serializes")
    }

    pub fn write_json(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        w.write_all(self.to_json().as_bytes())?;
        w.write_all(b"\n")
    }
}

/// The request a thread is currently building from `WinHttpConnect` /
/// `WinHttpOpenRequest`, before `WinHttpSendRequest` commits it.
#[derive(Debug, Clone, Default)]
struct ThreadState {
    host: String,
    verb: String,
    target: String,
}

/// Correlates WinHTTP entry calls into requests. The host/verb/target are built
/// up per thread (those calls run in sequence on the sending thread), but the
/// response is matched by the request handle, so a `WinHttpReadData` served on a
/// different pool thread (async WinHTTP) still attaches to the right request.
#[derive(Debug, Default)]
pub struct WinHttpTracker {
    by_thread: std::collections::HashMap<i32, ThreadState>,
    requests: Vec<RestExchange>,
    /// Response bytes, one accumulator per entry in `requests`.
    responses: Vec<Vec<u8>>,
    /// Request-handle (`hRequest`) to the index in `requests` it produced.
    by_handle: std::collections::HashMap<u64, usize>,
    seq: u64,
}

impl WinHttpTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// `WinHttpConnect(host)` on this thread. The host stays current for the
    /// thread's later requests until it connects again.
    pub fn on_connect(&mut self, tid: i32, host: String) {
        self.by_thread.entry(tid).or_default().host = host;
    }

    /// `WinHttpOpenRequest(verb, target)` on this thread.
    pub fn on_open_request(&mut self, tid: i32, verb: String, target: String) {
        let st = self.by_thread.entry(tid).or_default();
        st.verb = verb;
        st.target = target;
    }

    /// `WinHttpSendRequest(hRequest, …)` on this thread carried these header
    /// bytes and body. Emits one request from the thread's current host and
    /// target, keyed by `handle` (`hRequest`) for later response matching.
    pub fn on_send_request(
        &mut self,
        tid: i32,
        handle: u64,
        headers: &str,
        body: &[u8],
        ts_ms: u64,
    ) {
        let Some(st) = self.by_thread.get(&tid) else {
            return;
        };
        if st.target.is_empty() {
            return; // a send with no preceding OpenRequest we saw
        }
        let (path, query) = http::split_target(&st.target);
        let request_headers = parse_headers(headers);
        let (request_params, request_body_text) = decode_body(&request_headers, body);
        self.seq += 1;
        let idx = self.requests.len();
        self.requests.push(RestExchange {
            seq: self.seq,
            ts_ms,
            method: st.verb.clone(),
            host: st.host.clone(),
            target: st.target.clone(),
            path,
            query,
            request_headers,
            request_params,
            request_body_text,
            response_body: None,
        });
        self.responses.push(Vec::new());
        if handle != 0 {
            self.by_handle.insert(handle, idx);
        }
    }

    /// `WinHttpReadData` on `handle` (`hRequest`) returned `data`. Appended to
    /// the request that handle produced.
    pub fn on_read_data(&mut self, handle: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if let Some(&idx) = self.by_handle.get(&handle)
            && let Some(buf) = self.responses.get_mut(idx)
        {
            buf.extend_from_slice(data);
        }
    }

    /// The capture so far, response bodies decoded.
    pub fn into_capture(mut self, pid: i32) -> RestCapture {
        for (req, resp) in self.requests.iter_mut().zip(self.responses.iter()) {
            if !resp.is_empty() {
                req.response_body = Some(match std::str::from_utf8(resp) {
                    Ok(t) => t.to_string(),
                    Err(_) => http::binary_placeholder(resp.len()),
                });
            }
        }
        RestCapture {
            pid,
            requests: self.requests,
        }
    }
}

fn decode_body(headers: &[Header], body: &[u8]) -> (Vec<QueryParam>, Option<String>) {
    if body.is_empty() {
        return (Vec::new(), None);
    }
    match std::str::from_utf8(body) {
        Ok(text) if http::is_form(headers, text) => (http::parse_form(text), None),
        Ok(text) => (Vec::new(), Some(text.to_string())),
        Err(_) => (Vec::new(), Some(http::binary_placeholder(body.len()))),
    }
}

/// Parse CRLF-separated `Name: Value` headers.
fn parse_headers(headers: &str) -> Vec<Header> {
    headers
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some(Header {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_connect_open_send_into_one_request() {
        let mut t = WinHttpTracker::new();
        let tid = 7;
        t.on_connect(tid, "aoe-api.worldsedgelink.com".into());
        t.on_open_request(tid, "POST".into(), "/game/automatch2/polling".into());
        t.on_send_request(
            tid,
            0x1111,
            "Content-Type: application/x-www-form-urlencoded\r\n",
            b"callNum=123&relayRegion=eastus&matchTypes=%5B20%2C21%5D",
            42,
        );

        let cap = t.into_capture(9);
        assert_eq!(cap.requests.len(), 1);
        let e = &cap.requests[0];
        assert_eq!(e.method, "POST");
        assert_eq!(e.host, "aoe-api.worldsedgelink.com");
        assert_eq!(e.path, "/game/automatch2/polling");
        assert_eq!(e.ts_ms, 42);
        assert_eq!(
            e.request_params,
            vec![
                QueryParam {
                    name: "callNum".into(),
                    value: "123".into()
                },
                QueryParam {
                    name: "relayRegion".into(),
                    value: "eastus".into()
                },
                QueryParam {
                    name: "matchTypes".into(),
                    value: "[20,21]".into()
                },
            ]
        );
    }

    #[test]
    fn read_data_attaches_the_response_to_the_last_request() {
        let mut t = WinHttpTracker::new();
        let tid = 7;
        let h = 0x2222;
        t.on_connect(tid, "aoe-api.worldsedgelink.com".into());
        t.on_open_request(tid, "POST".into(), "/game/login/platformlogin".into());
        t.on_send_request(tid, h, "", b"callNum=0", 1);
        // Response arrives in two WinHttpReadData chunks, matched by handle.
        t.on_read_data(h, b"[0,");
        t.on_read_data(h, br#""token"]"#);
        let cap = t.into_capture(1);
        assert_eq!(
            cap.requests[0].response_body.as_deref(),
            Some(r#"[0,"token"]"#)
        );
    }

    #[test]
    fn read_data_for_an_unknown_handle_is_ignored() {
        let mut t = WinHttpTracker::new();
        t.on_read_data(0x9999, b"orphan");
        assert!(t.into_capture(1).requests.is_empty());
    }

    #[test]
    fn a_response_on_another_thread_still_matches_by_handle() {
        // Async WinHTTP: the read completes on a different (pool) thread than the
        // one that sent, but the request handle is the same.
        let mut t = WinHttpTracker::new();
        t.on_connect(1, "h".into());
        t.on_open_request(1, "GET".into(), "/game/x".into());
        t.on_send_request(1, 0xABC, "", b"", 0);
        // The read is keyed by the request handle, not the sending thread.
        t.on_read_data(0xABC, b"body");
        assert_eq!(
            t.into_capture(1).requests[0].response_body.as_deref(),
            Some("body")
        );
    }

    #[test]
    fn a_second_request_reuses_the_thread_host() {
        let mut t = WinHttpTracker::new();
        let tid = 3;
        t.on_connect(tid, "aoe-api.worldsedgelink.com".into());
        t.on_open_request(tid, "POST".into(), "/game/login/platformlogin".into());
        t.on_send_request(tid, 0x10, "", b"accountType=STEAM&callNum=0", 1);
        // Keep-alive: no new connect, another request on the same host.
        t.on_open_request(tid, "POST".into(), "/game/advertisement/host".into());
        t.on_send_request(tid, 0x20, "", b"hostid=1&maxplayers=8", 2);

        let cap = t.into_capture(1);
        assert_eq!(cap.requests.len(), 2);
        assert_eq!(cap.requests[0].path, "/game/login/platformlogin");
        assert_eq!(cap.requests[1].path, "/game/advertisement/host");
        assert_eq!(cap.requests[1].host, "aoe-api.worldsedgelink.com");
        assert_eq!(cap.requests[1].seq, 2);
    }

    #[test]
    fn query_in_the_target_is_split_out() {
        let mut t = WinHttpTracker::new();
        t.on_connect(1, "h".into());
        t.on_open_request(1, "GET".into(), "/x?a=1&b=two".into());
        t.on_send_request(1, 0x1, "", b"", 0);
        let e = &t.into_capture(1).requests[0];
        assert_eq!(e.path, "/x");
        assert_eq!(
            e.query,
            vec![
                QueryParam {
                    name: "a".into(),
                    value: "1".into()
                },
                QueryParam {
                    name: "b".into(),
                    value: "two".into()
                },
            ]
        );
    }

    #[test]
    fn a_json_body_is_kept_as_text_not_parsed_as_form() {
        let mut t = WinHttpTracker::new();
        t.on_connect(1, "h".into());
        t.on_open_request(1, "POST".into(), "/x".into());
        t.on_send_request(
            1,
            0x1,
            "Content-Type: application/json\r\n",
            br#"{"a":1}"#,
            0,
        );
        let e = &t.into_capture(1).requests[0];
        assert_eq!(e.request_body_text.as_deref(), Some(r#"{"a":1}"#));
        assert!(e.request_params.is_empty());
    }

    #[test]
    fn a_send_without_a_preceding_open_request_is_ignored() {
        let mut t = WinHttpTracker::new();
        t.on_connect(1, "h".into());
        t.on_send_request(1, 0x1, "", b"x=1", 0);
        assert!(t.into_capture(1).requests.is_empty());
    }
}
