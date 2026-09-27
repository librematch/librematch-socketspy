//! Best-effort parsing of a captured cleartext buffer as HTTP/1.x.
//!
//! One `SSL_write`/`SSL_read` buffer is not guaranteed to be one whole HTTP
//! message: it can be headers only, headers plus body, or a fragment. The
//! parser therefore reads what it can and never fails hard — a buffer that does
//! not look like HTTP returns `None`, and the caller records it as raw bytes.
//!
//! The goal is the lobby REST traffic (libcurl, HTTP/1.1): method, endpoint,
//! query parameters, headers and body. Binary streams (a WebSocket frame after
//! the upgrade, or HTTP/2) are not HTTP/1 and are left to the raw path.

use serde::Serialize;

/// A parsed HTTP/1.x message: a request or a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HttpMessage {
    Request {
        method: String,
        /// The full request target, query string included.
        target: String,
        /// The path with the query string removed.
        path: String,
        /// Query parameters, decoded from the target.
        query: Vec<QueryParam>,
        version: String,
        headers: Vec<Header>,
        body: Body,
    },
    Response {
        status: u16,
        reason: String,
        version: String,
        headers: Vec<Header>,
        body: Body,
    },
}

/// One HTTP header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// One query parameter, kept as an ordered pair so duplicate keys are not lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
}

/// A message body, decoded as far as it usefully can be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Body {
    /// No body bytes followed the headers.
    Empty,
    /// UTF-8 text (JSON, form data, plain text).
    Text { text: String },
    /// Non-text bytes; recorded by length and a short hex preview.
    Binary { len: usize, head_hex: String },
}

/// The HTTP/2 connection preface. gRPC traffic starts with these exact bytes.
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Recognized methods, used to decide whether a buffer begins a request.
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Parse a captured buffer as one HTTP/1.x message, or `None` if it is not one.
pub fn parse(bytes: &[u8]) -> Option<HttpMessage> {
    let split = find_header_end(bytes)?;
    let head = &bytes[..split];
    let body_bytes = &bytes[split + 4..];

    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let start_line = lines.next()?;

    let headers: Vec<Header> = lines
        .filter(|l| !l.is_empty())
        .filter_map(parse_header_line)
        .collect();
    let body = decode_body(body_bytes);

    if start_line.starts_with("HTTP/") {
        parse_status_line(start_line, headers, body)
    } else {
        parse_request_line(start_line, headers, body)
    }
}

/// Offset of the `\r\n\r\n` that ends the header block.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_header_line(line: &str) -> Option<Header> {
    let (name, value) = line.split_once(':')?;
    Some(Header {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
    })
}

fn parse_request_line(line: &str, headers: Vec<Header>, body: Body) -> Option<HttpMessage> {
    let mut parts = line.split(' ');
    let method = parts.next()?.to_string();
    if !METHODS.contains(&method.as_str()) {
        return None;
    }
    let target = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/") {
        return None;
    }
    let (path, query) = split_target(&target);
    Some(HttpMessage::Request {
        method,
        target,
        path,
        query,
        version,
        headers,
        body,
    })
}

fn parse_status_line(line: &str, headers: Vec<Header>, body: Body) -> Option<HttpMessage> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?.to_string();
    let status = parts.next()?.parse::<u16>().ok()?;
    let reason = parts.next().unwrap_or("").to_string();
    Some(HttpMessage::Response {
        status,
        reason,
        version,
        headers,
        body,
    })
}

/// Split a request target into its path and its decoded query parameters.
pub fn split_target(target: &str) -> (String, Vec<QueryParam>) {
    match target.split_once('?') {
        None => (target.to_string(), Vec::new()),
        Some((path, query)) => (path.to_string(), parse_form(query)),
    }
}

/// Parse `a=b&c=d` into parameters, decoding `%XX` and `+`. Shared by the query
/// string, the WinHTTP body, and the libcurl body.
pub fn parse_form(s: &str) -> Vec<QueryParam> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            QueryParam {
                name: percent_decode(name),
                value: percent_decode(value),
            }
        })
        .collect()
}

/// True if a request body should be read as form-urlencoded: either the
/// `Content-Type` says so, or it looks like `a=b&…` and is not obviously JSON.
pub fn is_form(headers: &[Header], body: &str) -> bool {
    let declared = headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-type")
            && h.value
                .to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
    });
    declared || (body.contains('=') && !body.starts_with(['{', '[']))
}

/// Placeholder recorded for a body or response that is not valid UTF-8.
pub fn binary_placeholder(len: usize) -> String {
    format!("<{len} binary bytes>")
}

/// Decode `%XX` escapes and `+` in a query component. Invalid escapes are left
/// as written rather than dropped, so nothing is silently lost.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_body(body: &[u8]) -> Body {
    if body.is_empty() {
        return Body::Empty;
    }
    match std::str::from_utf8(body) {
        Ok(text) => Body::Text {
            text: text.to_string(),
        },
        Err(_) => {
            let head: Vec<u8> = body.iter().take(32).copied().collect();
            Body::Binary {
                len: body.len(),
                head_hex: hex(&head),
            }
        }
    }
}

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_get_with_query_parameters() {
        let raw = b"GET /game/replay/setReplayData?matchid=42&sequenceid=7 HTTP/1.1\r\n\
            Host: relay.example\r\nContent-Length: 0\r\n\r\n";
        let msg = parse(raw).unwrap();
        let HttpMessage::Request {
            method,
            path,
            query,
            version,
            headers,
            body,
            ..
        } = msg
        else {
            panic!("expected request");
        };
        assert_eq!(method, "GET");
        assert_eq!(path, "/game/replay/setReplayData");
        assert_eq!(version, "HTTP/1.1");
        assert_eq!(
            query,
            vec![
                QueryParam {
                    name: "matchid".into(),
                    value: "42".into()
                },
                QueryParam {
                    name: "sequenceid".into(),
                    value: "7".into()
                },
            ]
        );
        assert!(
            headers
                .iter()
                .any(|h| h.name == "Host" && h.value == "relay.example")
        );
        assert_eq!(body, Body::Empty);
    }

    #[test]
    fn parses_a_post_with_a_json_body() {
        let raw = b"POST /game/advertisement/host HTTP/1.1\r\n\
            Content-Type: application/json\r\n\r\n{\"region\":\"westeurope\"}";
        let msg = parse(raw).unwrap();
        let HttpMessage::Request { method, body, .. } = msg else {
            panic!("expected request");
        };
        assert_eq!(method, "POST");
        assert_eq!(
            body,
            Body::Text {
                text: "{\"region\":\"westeurope\"}".into()
            }
        );
    }

    #[test]
    fn parses_a_response_status_line() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let msg = parse(raw).unwrap();
        let HttpMessage::Response {
            status,
            reason,
            body,
            ..
        } = msg
        else {
            panic!("expected response");
        };
        assert_eq!(status, 200);
        assert_eq!(reason, "OK");
        assert_eq!(body, Body::Text { text: "hi".into() });
    }

    #[test]
    fn decodes_percent_and_plus_in_query() {
        let raw = b"GET /s?q=a%20b+c&e=%ZZ HTTP/1.1\r\n\r\n";
        let HttpMessage::Request { query, .. } = parse(raw).unwrap() else {
            panic!();
        };
        assert_eq!(
            query[0],
            QueryParam {
                name: "q".into(),
                value: "a b c".into()
            }
        );
        // An invalid escape survives verbatim rather than being dropped.
        assert_eq!(
            query[1],
            QueryParam {
                name: "e".into(),
                value: "%ZZ".into()
            }
        );
    }

    #[test]
    fn a_binary_body_is_recorded_by_length_and_preview() {
        let mut raw = b"POST /x HTTP/1.1\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0xff, 0x00, 0x01, 0x80]);
        let HttpMessage::Request { body, .. } = parse(&raw).unwrap() else {
            panic!();
        };
        assert_eq!(
            body,
            Body::Binary {
                len: 4,
                head_hex: "ff000180".into()
            }
        );
    }

    #[test]
    fn non_http_bytes_return_none() {
        assert!(parse(&[0x82, 0x7e, 0x01, 0x2c]).is_none()); // a WebSocket frame
        assert!(parse(b"not http at all").is_none());
    }

    #[test]
    fn a_websocket_upgrade_request_still_parses_as_http() {
        let raw = b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let HttpMessage::Request { headers, .. } = parse(raw).unwrap() else {
            panic!();
        };
        assert!(
            headers
                .iter()
                .any(|h| h.name == "Upgrade" && h.value == "websocket")
        );
    }
}
