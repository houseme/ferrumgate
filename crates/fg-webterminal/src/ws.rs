//! WebSocket protocol (WP-61 §3.2/§3.3): text frames carry JSON control
//! messages, binary frames carry raw terminal output. The contract is the
//! upstream one and is shared with the Docker container terminal (WP-60),
//! which reuses this layer.
//!
//! Browser → server: `{"t":"i","d":"…"}` input, `{"t":"r","c":…,"r":…}`
//! resize, `{"t":"p"}` heartbeat ping.
//! Server → browser: `{"t":"s","d":"<sessionId>"}` session started (sent
//! after create and after every attach), `{"t":"n","d":"…"}` notice,
//! `{"t":"x","d":"reason"}` session exit, `{"t":"p"}` heartbeat reply.

use serde::{Deserialize, Serialize};

/// Message type tags (WP-61 §3.4 table: `s`/`n`/`x`/`p`/`i`/`r`).
pub mod tags {
    /// Server → client: session started (`d` = session id).
    pub const STARTED: char = 's';
    /// Server → client: notice (`d` = text).
    pub const NOTICE: char = 'n';
    /// Server → client: session exited (`d` = reason).
    pub const EXIT: char = 'x';
    /// Both directions: heartbeat (the server replies to `p` with `p`).
    pub const PING: char = 'p';
    /// Client → server: input (`d` = keystrokes).
    pub const INPUT: char = 'i';
    /// Client → server: resize (`c` = cols, `r` = rows).
    pub const RESIZE: char = 'r';
}

/// A message received from a browser client (a text frame's JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMsg {
    /// Keyboard input (`d` holds the raw keystrokes).
    Input(String),
    /// Terminal window resize.
    Resize { cols: u16, rows: u16 },
    /// Heartbeat ping; answered with [`ServerMsg::Pong`].
    Ping,
}

/// A message sent to a browser client (as a text frame's JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ServerMsg {
    /// The session id, sent after creation and after each attach.
    Started(String),
    /// A human readable notice.
    Notice(String),
    /// The session exited; the reason closes the exchange.
    Exit(String),
    /// Heartbeat reply.
    Pong,
}

/// Why [`decode`] refused a text frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// The frame is not valid JSON or does not match a known shape.
    Malformed(String),
    /// The `t` tag is known to be client-only or unknown: the frame is
    /// ignored (WP-61 §6 `ws_unknown_message_ignored_or_closed`).
    UnknownType(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed message: {detail}"),
            Self::UnknownType(tag) => write!(f, "unknown message type {tag:?}"),
        }
    }
}

/// The raw wire shapes (tagged by `t`; kept internal to the protocol).
/// Optional fields are omitted so the frames match the documented shapes
/// exactly (`{"t":"p"}`, `{"t":"r","c":…,"r":…}`).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    t: char,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    d: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    c: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    r: u16,
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

/// Decodes one text frame. Unknown `t` tags are reported as
/// [`ProtocolError::UnknownType`] so the caller can ignore them (or close
/// the socket); JSON and shape errors are [`ProtocolError::Malformed`].
pub fn decode(text: &str) -> Result<ClientMsg, ProtocolError> {
    if text.len() > crate::model::limits::WS_MESSAGE_MAX_BYTES {
        return Err(ProtocolError::Malformed("message too large".into()));
    }
    let wire: Wire =
        serde_json::from_str(text).map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    match wire.t {
        tags::INPUT => Ok(ClientMsg::Input(wire.d)),
        tags::RESIZE => Ok(ClientMsg::Resize {
            cols: wire.c,
            rows: wire.r,
        }),
        tags::PING => Ok(ClientMsg::Ping),
        // Server-only tags and unknown tags never come from a client.
        _ => Err(ProtocolError::UnknownType(wire.t.to_string())),
    }
}

/// Encodes a server message into one text frame's JSON payload.
pub fn encode(message: &ServerMsg) -> String {
    let wire = match message {
        ServerMsg::Started(id) => Wire {
            t: tags::STARTED,
            d: id.clone(),
            c: 0,
            r: 0,
        },
        ServerMsg::Notice(text) => Wire {
            t: tags::NOTICE,
            d: text.clone(),
            c: 0,
            r: 0,
        },
        ServerMsg::Exit(reason) => Wire {
            t: tags::EXIT,
            d: reason.clone(),
            c: 0,
            r: 0,
        },
        ServerMsg::Pong => Wire {
            t: tags::PING,
            d: String::new(),
            c: 0,
            r: 0,
        },
    };
    serde_json::to_string(&wire).unwrap_or_else(|_| "{\"t\":\"p\"}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_encode_decode_roundtrip() {
        // Server messages keep the upstream shapes exactly.
        assert_eq!(
            encode(&ServerMsg::Started("abc123".into())),
            r#"{"t":"s","d":"abc123"}"#
        );
        assert_eq!(encode(&ServerMsg::Pong), r#"{"t":"p"}"#);
        assert_eq!(
            encode(&ServerMsg::Exit("done".into())),
            r#"{"t":"x","d":"done"}"#
        );
        assert_eq!(
            encode(&ServerMsg::Notice("准备就绪".into())),
            r#"{"t":"n","d":"准备就绪"}"#
        );
        // Client messages decode from the upstream shapes (d/c/r optional
        // per message type).
        assert_eq!(
            decode(r#"{"t":"i","d":"ls\n"}"#).expect("input"),
            ClientMsg::Input("ls\n".into())
        );
        assert_eq!(
            decode(r#"{"t":"r","c":120,"r":40}"#).expect("resize"),
            ClientMsg::Resize {
                cols: 120,
                rows: 40
            }
        );
        assert_eq!(decode(r#"{"t":"p"}"#).expect("ping"), ClientMsg::Ping);
    }

    #[test]
    fn ws_unknown_message_ignored_or_closed() {
        // A server-only tag from a client is recognized as ignorable.
        let error = decode(r#"{"t":"s","d":"forged"}"#).expect_err("server tag");
        assert_eq!(error, ProtocolError::UnknownType("s".into()));
        let error = decode(r#"{"t":"q"}"#).expect_err("unknown tag");
        assert_eq!(error, ProtocolError::UnknownType("q".into()));
        assert!(error.to_string().contains('q'));
        // Broken JSON is a malformed frame.
        assert!(matches!(
            decode("not json"),
            Err(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            decode(r#"{"t":"i","d":123}"#),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn ws_oversized_text_frames_are_malformed() {
        let huge = format!(
            r#"{{"t":"i","d":"{}"}}"#,
            "x".repeat(crate::model::limits::WS_MESSAGE_MAX_BYTES + 1)
        );
        assert!(matches!(
            decode(&huge),
            Err(ProtocolError::Malformed(detail)) if detail.contains("too large")
        ));
    }
}
