//! The capture store: one record per observed TLS buffer, exported as a
//! structured JSON document on close.
//!
//! Time is passed in, never read from the clock here, so a test is reproducible
//! (rule: reproducible). The tracer passes real milliseconds; a test passes
//! fixed ones.

use crate::http::{self, HttpMessage};
use serde::Serialize;

/// Which side of the TLS connection a buffer was seen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Plaintext the client handed to `SSL_write` (client → server).
    Send,
    /// Plaintext the client received from `SSL_read` (server → client).
    Recv,
}

/// The decoded shape of one captured buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decoded", rename_all = "snake_case")]
pub enum Decoded {
    /// A parsed HTTP/1.x message (the RelicLink REST traffic and the
    /// WebSocket-upgrade handshake).
    Http(HttpMessage),
    /// The start of an HTTP/2 connection (gRPC).
    Http2Preface,
    /// A text payload that is not HTTP: typically a JSON operation carried
    /// inside a WebSocket frame (the multiplayer game API). Kept whole.
    Text { text: String },
    /// Binary bytes: a WebSocket frame header or binary frame, a TLS record
    /// fragment. Kept whole as hex so the WSS game-server protocol is analyzable.
    Binary { len: usize, hex: String },
}

impl Decoded {
    /// Decode a captured buffer: HTTP/2 preface, then HTTP/1.x, then whole text,
    /// otherwise whole binary. Nothing is dropped — WebSocket frames are kept as
    /// text or binary in full.
    pub fn of(bytes: &[u8]) -> Decoded {
        if bytes.starts_with(http::HTTP2_PREFACE) {
            return Decoded::Http2Preface;
        }
        if let Some(msg) = http::parse(bytes) {
            return Decoded::Http(msg);
        }
        if let Some(text) = as_text(bytes) {
            return Decoded::Text { text };
        }
        Decoded::Binary {
            len: bytes.len(),
            hex: http::hex(bytes),
        }
    }
}

/// Return the buffer as text if it is valid UTF-8 that is mostly printable.
/// This surfaces the JSON operations the WebSocket carries while leaving binary
/// frames (which contain many control bytes) to the binary path.
fn as_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.is_empty() {
        return None;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .count();
    // Require nearly all characters to be printable to call it text.
    if printable * 10 >= s.chars().count() * 9 {
        Some(s.to_string())
    } else {
        None
    }
}

/// One captured buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    /// 1-based order of capture.
    pub seq: u64,
    /// Milliseconds since capture start, passed in by the caller.
    pub ts_ms: u64,
    pub direction: Direction,
    /// Total plaintext length of the buffer.
    pub len: usize,
    #[serde(flatten)]
    pub decoded: Decoded,
}

/// The whole capture, serialized on close.
#[derive(Debug, Clone, Serialize)]
pub struct Capture {
    /// The traced process id.
    pub pid: i32,
    pub records: Vec<Record>,
}

impl Capture {
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            records: Vec::new(),
        }
    }

    /// Add one observed buffer. `ts_ms` is milliseconds since capture start.
    pub fn record(&mut self, direction: Direction, ts_ms: u64, bytes: &[u8]) {
        let seq = self.records.len() as u64 + 1;
        self.records.push(Record {
            seq,
            ts_ms,
            direction,
            len: bytes.len(),
            decoded: Decoded::of(bytes),
        });
    }

    /// The structured JSON document, pretty-printed.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("capture serializes")
    }

    /// Write the JSON document to a writer.
    pub fn write_json(&self, mut w: impl std::io::Write) -> std::io::Result<()> {
        w.write_all(self.to_json().as_bytes())?;
        w.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Body;

    #[test]
    fn records_carry_sequence_and_injected_time() {
        let mut cap = Capture::new(1234);
        cap.record(Direction::Send, 0, b"GET /a HTTP/1.1\r\n\r\n");
        cap.record(Direction::Recv, 15, b"HTTP/1.1 204 No Content\r\n\r\n");
        assert_eq!(cap.records.len(), 2);
        assert_eq!(cap.records[0].seq, 1);
        assert_eq!(cap.records[0].ts_ms, 0);
        assert_eq!(cap.records[1].seq, 2);
        assert_eq!(cap.records[1].direction, Direction::Recv);
    }

    #[test]
    fn classifies_http_grpc_text_and_binary() {
        assert!(matches!(
            Decoded::of(b"GET /a HTTP/1.1\r\n\r\n"),
            Decoded::Http(HttpMessage::Request { .. })
        ));
        assert!(matches!(
            Decoded::of(http::HTTP2_PREFACE),
            Decoded::Http2Preface
        ));
        // A JSON operation carried in a WebSocket frame is surfaced as text.
        assert!(matches!(
            Decoded::of(br#"{"operation":1,"ackCount":1}"#),
            Decoded::Text { .. }
        ));
        // A binary WebSocket frame header is kept whole as hex.
        assert!(matches!(
            Decoded::of(&[0x82, 0x7e, 0x01, 0x2c]),
            Decoded::Binary { len: 4, .. }
        ));
    }

    #[test]
    fn json_export_is_structured_and_parseable() {
        let mut cap = Capture::new(42);
        cap.record(
            Direction::Send,
            5,
            b"POST /game/advertisement/host?v=1 HTTP/1.1\r\n\
              Content-Type: application/json\r\n\r\n{\"region\":\"eu\"}",
        );
        let json = cap.to_json();
        // Round-trips as JSON and carries the fields a later parser needs.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["pid"], 42);
        let rec = &v["records"][0];
        assert_eq!(rec["direction"], "send");
        assert_eq!(rec["type"], "request");
        assert_eq!(rec["method"], "POST");
        assert_eq!(rec["path"], "/game/advertisement/host");
        assert_eq!(rec["query"][0]["name"], "v");
        assert_eq!(rec["body"]["kind"], "text");
    }

    #[test]
    fn body_json_is_captured_as_text_for_later_parsing() {
        let mut cap = Capture::new(1);
        cap.record(Direction::Recv, 0, b"HTTP/1.1 200 OK\r\n\r\n{\"a\":1}");
        let Decoded::Http(HttpMessage::Response { body, .. }) = &cap.records[0].decoded else {
            panic!("expected response");
        };
        assert_eq!(
            *body,
            Body::Text {
                text: "{\"a\":1}".into()
            }
        );
    }
}
