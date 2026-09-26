//! WebSocket framing (RFC 6455), for capturing and, later, crafting frames (WS.a).
//!
//! A WebSocket is not request/response: after the `101` handshake the connection is a
//! long-lived, bidirectional stream of frames. The proxy relays those bytes verbatim — it
//! never re-serialises them, so nothing a tester or a server sent is normalised — and feeds
//! a copy to a [`FrameParser`] per direction to record what went by. This module is that
//! parser: it reads frames without a conforming library, so a deliberately odd frame is
//! observed rather than rejected.
//!
//! # Hostile input is bounded here
//!
//! A frame's length is declared by the peer, up to 63 bits. Believing it would let a server
//! announce an 8-exabyte frame and exhaust memory, so the parser refuses a frame whose
//! declared payload exceeds the configured cap — the same discipline the HTTP/1.x body
//! reader and the h2 decoder keep. And it never loops: each call either consumes a whole
//! frame or reports that more bytes are needed.
//!
//! # Masking is evidence
//!
//! A client's frames must be masked and a server's must not (RFC 6455 §5.1). The parser
//! records what it *observed* rather than normalising it, because a client that does not
//! mask, or a server that does, is a finding — not a detail to smooth over.

use bytes::BytesMut;

use hexora_types::error::{HexoraError, ProtocolError, Result};

/// A WebSocket opcode (the low nibble of the first byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A continuation of the previous data message.
    Continuation,
    /// A UTF-8 text message.
    Text,
    /// A binary message.
    Binary,
    /// Connection close.
    Close,
    /// A ping.
    Ping,
    /// A pong.
    Pong,
    /// A reserved or unknown opcode, preserved as-is rather than rejected.
    Other(u8),
}

impl Opcode {
    /// Reads an opcode from its 4-bit value.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0f {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            other => Opcode::Other(other),
        }
    }

    /// The 4-bit wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
            Opcode::Other(v) => v & 0x0f,
        }
    }

    /// Whether this is a control frame (close, ping, pong, or a reserved control opcode).
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong) || matches!(self, Opcode::Other(v) if v >= 0x8)
    }
}

/// One parsed WebSocket frame, its payload already unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The FIN bit: the last frame of a message.
    pub fin: bool,
    /// RSV1 — set by `permessage-deflate` for a compressed message; recorded so a
    /// compressed frame can be told apart before that extension is supported (WS.e).
    pub rsv1: bool,
    /// The opcode.
    pub opcode: Opcode,
    /// Whether the frame was masked on the wire. Client frames must be; server frames must
    /// not. Kept as observed.
    pub masked: bool,
    /// The payload, unmasked.
    pub payload: Vec<u8>,
}

/// A streaming frame parser: bytes are pushed as they arrive and whole frames pulled out.
#[derive(Debug)]
pub struct FrameParser {
    buf: BytesMut,
    max_payload: usize,
}

impl FrameParser {
    /// A parser that refuses any single frame whose declared payload exceeds `max_payload`.
    pub fn new(max_payload: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_payload,
        }
    }

    /// Accumulates received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Parses and consumes the next complete frame, or `Ok(None)` if more bytes are needed.
    ///
    /// An error means the declared frame is larger than the cap — a refusal, not a parse
    /// failure, since the bytes on the wire are whatever the peer sent. Every other input is
    /// either a frame or "need more"; the parser never loops and never reads out of bounds.
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        let buf = &self.buf[..];
        if buf.len() < 2 {
            return Ok(None);
        }

        let first = buf[0];
        let fin = first & 0x80 != 0;
        let rsv1 = first & 0x40 != 0;
        let opcode = Opcode::from_u8(first);

        let second = buf[1];
        let masked = second & 0x80 != 0;
        let short_len = (second & 0x7f) as usize;

        // Header: 2 bytes + extended length + optional 4-byte mask key.
        let mut offset = 2;
        let payload_len = match short_len {
            126 => {
                if buf.len() < offset + 2 {
                    return Ok(None);
                }
                let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
                offset += 2;
                len
            }
            127 => {
                if buf.len() < offset + 8 {
                    return Ok(None);
                }
                let len = u64::from_be_bytes([
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]);
                offset += 8;
                // Refuse before allocating: a 63-bit length is not a reason to try.
                if len > self.max_payload as u64 {
                    return Err(oversized(len));
                }
                len as usize
            }
            n => n,
        };

        if payload_len > self.max_payload {
            return Err(oversized(payload_len as u64));
        }

        let mask_key = if masked {
            if buf.len() < offset + 4 {
                return Ok(None);
            }
            let key = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
            offset += 4;
            Some(key)
        } else {
            None
        };

        let total = offset + payload_len;
        if buf.len() < total {
            return Ok(None);
        }

        let mut payload = buf[offset..total].to_vec();
        if let Some(key) = mask_key {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
        }

        // Consume the frame's bytes now that it is whole.
        let _ = self.buf.split_to(total);

        Ok(Some(Frame {
            fin,
            rsv1,
            opcode,
            masked,
            payload,
        }))
    }
}

fn oversized(len: u64) -> HexoraError {
    HexoraError::Protocol(ProtocolError::Malformed {
        protocol: "WebSocket",
        reason: format!("a frame declared a {len}-byte payload, past the limit"),
    })
}

/// Serialises a frame to the wire.
///
/// Used by the injector (WS.d) and to re-mask a client frame when relaying. Masking is
/// applied when `mask_key` is `Some`; a client frame must carry one, a server frame must
/// not. Nothing else is validated — the caller decides what to send.
pub fn encode(frame: &Frame, mask_key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.payload.len() + 14);

    let mut first = frame.opcode.as_u8();
    if frame.fin {
        first |= 0x80;
    }
    if frame.rsv1 {
        first |= 0x40;
    }
    out.push(first);

    let masked_bit = if mask_key.is_some() { 0x80 } else { 0 };
    let len = frame.payload.len();
    if len < 126 {
        out.push(masked_bit | len as u8);
    } else if len <= u16::MAX as usize {
        out.push(masked_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(masked_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    match mask_key {
        Some(key) => {
            out.extend_from_slice(&key);
            for (i, byte) in frame.payload.iter().enumerate() {
                out.push(byte ^ key[i % 4]);
            }
        }
        None => out.extend_from_slice(&frame.payload),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parse_all(bytes: &[u8]) -> Vec<Frame> {
        let mut parser = FrameParser::new(1 << 20);
        parser.push(bytes);
        let mut frames = Vec::new();
        while let Ok(Some(frame)) = parser.next_frame() {
            frames.push(frame);
        }
        frames
    }

    #[test]
    fn an_unmasked_text_frame_round_trips() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            opcode: Opcode::Text,
            masked: false,
            payload: b"hello".to_vec(),
        };
        let bytes = encode(&frame, None);
        assert_eq!(parse_all(&bytes), vec![frame]);
    }

    #[test]
    fn a_masked_client_frame_is_unmasked_and_recorded_as_masked() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            opcode: Opcode::Binary,
            masked: true,
            payload: b"\x00\x01\x02payload".to_vec(),
        };
        let bytes = encode(&frame, Some([0xa1, 0xb2, 0xc3, 0xd4]));
        let parsed = parse_all(&bytes);
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].masked, "the mask bit is recorded as observed");
        assert_eq!(parsed[0].payload, frame.payload, "the payload is unmasked");
    }

    #[test]
    fn a_16_and_64_bit_length_are_read() {
        for len in [200usize, 70_000] {
            let frame = Frame {
                fin: true,
                rsv1: false,
                opcode: Opcode::Binary,
                masked: false,
                payload: vec![0x5a; len],
            };
            let bytes = encode(&frame, None);
            let parsed = parse_all(&bytes);
            assert_eq!(parsed.len(), 1, "len {len}");
            assert_eq!(parsed[0].payload.len(), len);
        }
    }

    #[test]
    fn a_frame_split_across_pushes_is_reassembled() {
        let frame = Frame {
            fin: true,
            rsv1: false,
            opcode: Opcode::Text,
            masked: false,
            payload: b"split me".to_vec(),
        };
        let bytes = encode(&frame, None);
        let mut parser = FrameParser::new(1 << 20);

        parser.push(&bytes[..3]);
        assert!(parser.next_frame().unwrap().is_none(), "incomplete: need more");
        parser.push(&bytes[3..]);
        assert_eq!(parser.next_frame().unwrap().unwrap(), frame);
    }

    #[test]
    fn control_frames_and_rsv1_are_recognised() {
        assert!(Opcode::Ping.is_control());
        assert!(Opcode::Close.is_control());
        assert!(!Opcode::Text.is_control());

        let frame = Frame {
            fin: true,
            rsv1: true, // permessage-deflate marker
            opcode: Opcode::Text,
            masked: false,
            payload: b"z".to_vec(),
        };
        let bytes = encode(&frame, None);
        assert!(parse_all(&bytes)[0].rsv1, "a compressed frame is flagged");
    }

    #[test]
    fn an_oversized_frame_is_refused_not_allocated() {
        let mut parser = FrameParser::new(1024);
        // 64-bit length header announcing a huge payload; no payload bytes follow.
        let mut header = vec![0x82, 127];
        header.extend_from_slice(&(1u64 << 40).to_be_bytes());
        parser.push(&header);
        assert!(parser.next_frame().is_err(), "a huge declared length is refused");
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_or_loop(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut parser = FrameParser::new(1 << 16);
            parser.push(&bytes);
            // Pull frames until it stops making progress; must terminate and never panic.
            let mut guard = 0;
            loop {
                match parser.next_frame() {
                    Ok(Some(_)) => { guard += 1; prop_assert!(guard < 4096); }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}
