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

use std::time::Duration;

use base64::Engine as _;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use nullhawk_types::error::{NetworkError, NullhawkError, ProtocolError, Result};
use nullhawk_types::http::HttpService;
use nullhawk_types::limits::Limits;

use crate::tls::TlsConfig;

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
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
            || matches!(self, Opcode::Other(v) if v >= 0x8)
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
            let key = [
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ];
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

fn oversized(len: u64) -> NullhawkError {
    NullhawkError::Protocol(ProtocolError::Malformed {
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

/// A byte stream a WebSocket connection can own, plain or TLS.
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A live WebSocket connection Nullhawk opened as a client — the engine behind the WebSocket
/// repeater (WS.d).
///
/// It performs the `101` handshake, then holds the connection open so a tester can send a
/// message on demand and read what comes back, rather than the request/response of the rest
/// of the tool. Frames it sends are masked, as a client's must be.
pub struct WsConnection {
    stream: Box<dyn Duplex>,
    parser: FrameParser,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection").finish_non_exhaustive()
    }
}

/// Opens a WebSocket to `service` at `path`, returning the live connection.
///
/// The handshake is a real `GET` with the WebSocket headers and a fresh key; a server that
/// answers anything but `101 Switching Protocols` is an error. The response's
/// `Sec-WebSocket-Accept` is not recomputed and checked — a deliberate first cut: the `101`
/// and the upgrade are the signal a tester is sending into, and strict verification is not
/// needed to send. Nothing here is a scope decision; the caller checks scope before opening.
pub async fn connect(
    service: &HttpService,
    path: &str,
    tls: &TlsConfig,
    limits: &Limits,
) -> Result<WsConnection> {
    let key = base64::engine::general_purpose::STANDARD.encode(fresh_key());
    let target = if path.is_empty() { "/" } else { path };
    let handshake = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        service.authority()
    );

    let tcp = TcpStream::connect((service.host.as_str(), service.port))
        .await
        .map_err(|e| NullhawkError::Network(NetworkError::Io(e.to_string())))?;
    let mut stream: Box<dyn Duplex> = if service.secure {
        let (tls_stream, _info) = crate::tls::handshake(tcp, &service.host, tls, limits).await?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    stream
        .write_all(handshake.as_bytes())
        .await
        .map_err(|e| NullhawkError::Network(NetworkError::Io(e.to_string())))?;
    stream.flush().await.ok();

    let (head, rest) = read_response_head(&mut stream, limits).await?;
    if parse_status(&head) != Some(101) {
        return Err(NullhawkError::Protocol(ProtocolError::Malformed {
            protocol: "WebSocket",
            reason: "the server did not accept the WebSocket upgrade (no 101)".to_string(),
        }));
    }

    let mut parser = FrameParser::new(limits.max_body_bytes.min(usize::MAX as u64) as usize);
    parser.push(&rest); // frames the server sent alongside the 101
    Ok(WsConnection { stream, parser })
}

impl WsConnection {
    /// Sends one message frame, masked as a client frame must be.
    pub async fn send(&mut self, opcode: Opcode, payload: &[u8]) -> Result<()> {
        let bytes = encode(
            &Frame {
                fin: true,
                rsv1: false,
                opcode,
                masked: true,
                payload: payload.to_vec(),
            },
            Some(fresh_mask()),
        );
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| NullhawkError::Network(NetworkError::Io(e.to_string())))?;
        self.stream.flush().await.ok();
        Ok(())
    }

    /// Sends a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.send(Opcode::Text, text.as_bytes()).await
    }

    /// Sends a fully controlled frame — the WebSocket analogue of a raw send (WS.e).
    ///
    /// Every field is the tester's: FIN, the reserved bits, the opcode (including reserved
    /// or invalid ones), and whether it is masked. `mask` of `None` sends an *unmasked*
    /// client frame, which the protocol forbids and a conforming library will not emit — and
    /// which is exactly the thing a tester wants to send to see what a server does with it.
    pub async fn send_frame(&mut self, frame: &Frame, mask: Option<[u8; 4]>) -> Result<()> {
        let bytes = encode(frame, mask);
        self.send_raw(&bytes).await
    }

    /// Writes bytes to the connection verbatim — a frame the tester encoded by hand, with a
    /// length that lies or a shape no encoder would produce.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.stream
            .write_all(bytes)
            .await
            .map_err(|e| NullhawkError::Network(NetworkError::Io(e.to_string())))?;
        self.stream.flush().await.ok();
        Ok(())
    }

    /// Reads the next frame, or `None` when the connection closes or `timeout` elapses with
    /// nothing more to read.
    pub async fn recv(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.parser.next_frame()? {
                return Ok(Some(frame));
            }
            let mut buf = [0u8; 8192];
            let read = tokio::time::timeout(timeout, self.stream.read(&mut buf)).await;
            let n = match read {
                Ok(Ok(0)) => return Ok(None), // closed
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(NullhawkError::Network(NetworkError::Io(e.to_string()))),
                Err(_) => return Ok(None), // timed out: nothing more for now
            };
            self.parser.push(&buf[..n]);
        }
    }

    /// Sends a close frame.
    pub async fn close(&mut self) -> Result<()> {
        let _ = self.send(Opcode::Close, &[]).await;
        Ok(())
    }
}

/// Inflates a `permessage-deflate` message payload (RFC 7692), bounded against a bomb.
///
/// The extension compresses a message with raw DEFLATE and drops the final `00 00 ff ff` of
/// the last block; the receiver appends them back and inflates, which is what this does. It
/// is a *per-message* inflate — it does not carry the LZ77 window across messages, so it is
/// correct for a `no_context_takeover` session and for the first message of any session, and
/// a caller must not assume more. Output is bounded by [`Limits::check_decompression`], so a
/// tiny compressed frame cannot expand without limit.
///
/// It is exposed as a primitive rather than applied automatically on receipt: whether a
/// frame is compressed depends on a negotiation the frame itself does not carry, and
/// silently inflating one that used context takeover would produce wrong bytes. The `rsv1`
/// bit flags a compressed frame; the caller decides.
pub fn inflate(compressed: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut input = compressed.to_vec();
    input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);

    // A raw-DEFLATE decompressor driven by hand rather than the `read` adapter: the block a
    // permessage-deflate sender emits is not marked final, so a decoder that insists on a
    // complete stream rejects it. This stops when the input is consumed and no more output
    // is produced, which is the message boundary the extension defines.
    let mut decoder = Decompress::new(false);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let consumed_before = decoder.total_in() as usize;
        let produced_before = decoder.total_out();
        let status = decoder
            .decompress(&input[consumed_before..], &mut buf, FlushDecompress::Sync)
            .map_err(|e| {
                NullhawkError::Protocol(ProtocolError::DecodeFailed {
                    encoding: "permessage-deflate".to_string(),
                    reason: e.to_string(),
                })
            })?;
        let produced = (decoder.total_out() - produced_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        // Refuse a decompression bomb as it expands, not after.
        limits.check_decompression(compressed.len() as u64, out.len() as u64)?;

        if status == Status::StreamEnd {
            break;
        }
        // No progress — all input consumed and nothing more produced — is the end of the
        // message for a sync-flushed block.
        if decoder.total_in() as usize == consumed_before && produced == 0 {
            break;
        }
    }
    Ok(out)
}

/// Drives the frame parser over arbitrary bytes. Public only for the fuzz target; the
/// property is that it never panics, loops or reads out of bounds on any input.
#[doc(hidden)]
pub fn fuzz_parse_frames(bytes: &[u8]) {
    let mut parser = FrameParser::new(1 << 20);
    parser.push(bytes);
    while let Ok(Some(_)) = parser.next_frame() {}
}

/// Runs the permessage-deflate inflater over arbitrary bytes. Public only for the fuzz
/// target; the property is that it never panics or runs unbounded on any input.
#[doc(hidden)]
pub fn fuzz_inflate(bytes: &[u8]) {
    let _ = inflate(bytes, &Limits::default());
}

/// Reads a response head (through the blank line), returning it and any bytes past it.
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    limits: &Limits,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = BytesMut::new();
    let deadline = tokio::time::Instant::now() + limits.read_head_timeout;
    loop {
        if let Some(end) = crate::parse::find_head_end(&buf) {
            let rest = buf.split_off(end);
            return Ok((buf.to_vec(), rest.to_vec()));
        }
        limits.check_header_size(buf.len())?;
        let before = buf.len();
        buf.resize(before + 4096, 0);
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf[before..]))
            .await
            .map_err(|_| {
                NullhawkError::Network(NetworkError::Timeout {
                    phase: nullhawk_types::error::TimeoutPhase::ReadResponseHead,
                    elapsed: limits.read_head_timeout,
                })
            })?
            .map_err(|e| NullhawkError::Network(NetworkError::Io(e.to_string())))?;
        buf.truncate(before + n);
        if n == 0 {
            return Err(NullhawkError::Protocol(ProtocolError::Malformed {
                protocol: "WebSocket",
                reason: "the server closed the connection during the handshake".to_string(),
            }));
        }
    }
}

/// Reads the status code from a response head's first line.
fn parse_status(head: &[u8]) -> Option<u16> {
    std::str::from_utf8(head)
        .ok()?
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// A 16-byte handshake key. Time-derived rather than crypto-random: a client key need only
/// be present and distinct, and the server echoes it via `Sec-WebSocket-Accept`.
fn fresh_key() -> [u8; 16] {
    let seed = seed();
    let mut key = [0u8; 16];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = (seed.rotate_left((i as u32) * 8) as u8) ^ (i as u8).wrapping_mul(31);
    }
    key
}

/// A 4-byte masking key, likewise time-derived.
fn fresh_mask() -> [u8; 4] {
    (seed() as u32 ^ (seed() as u32).rotate_left(13)).to_ne_bytes()
}

fn seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
        assert!(
            parser.next_frame().unwrap().is_none(),
            "incomplete: need more"
        );
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
        assert!(
            parser.next_frame().is_err(),
            "a huge declared length is refused"
        );
    }

    /// A local WebSocket echo server: accepts one connection, answers 101, and echoes each
    /// text frame back as an unmasked server frame.
    async fn ws_echo_server() -> u16 {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read the handshake head, then accept.
            let mut buf = BytesMut::new();
            let mut scratch = [0u8; 4096];
            loop {
                let n = socket.read(&mut scratch).await.unwrap();
                buf.extend_from_slice(&scratch[..n]);
                if crate::parse::find_head_end(&buf).is_some() || n == 0 {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n",
                )
                .await
                .unwrap();

            // Echo frames.
            let mut parser = FrameParser::new(1 << 20);
            loop {
                if let Ok(Some(frame)) = parser.next_frame() {
                    if frame.opcode == Opcode::Text {
                        let reply = encode(
                            &Frame {
                                fin: true,
                                rsv1: false,
                                opcode: Opcode::Text,
                                masked: false,
                                payload: frame.payload,
                            },
                            None,
                        );
                        let _ = socket.write_all(&reply).await;
                        let _ = socket.flush().await;
                    }
                    continue;
                }
                let n = match socket.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                parser.push(&scratch[..n]);
            }
        });
        port
    }

    #[tokio::test]
    async fn the_client_connects_sends_and_receives() {
        let port = ws_echo_server().await;
        let service = HttpService::new("127.0.0.1", port, false);

        let mut connection = connect(
            &service,
            "/echo",
            &TlsConfig::verified(),
            &Limits::default(),
        )
        .await
        .expect("the client completes the handshake");

        connection.send_text("hello over websocket").await.unwrap();

        let frame = connection
            .recv(std::time::Duration::from_secs(2))
            .await
            .unwrap()
            .expect("the echo comes back");
        assert_eq!(frame.opcode, Opcode::Text);
        assert_eq!(frame.payload, b"hello over websocket");
        assert!(!frame.masked, "a server frame is not masked");

        connection.close().await.unwrap();
    }

    /// Compresses a payload the way a `permessage-deflate` sender does: raw DEFLATE with the
    /// final `00 00 ff ff` dropped.
    fn deflate_for_test(data: &[u8]) -> Vec<u8> {
        use flate2::{Compress, Compression, FlushCompress};
        let mut compress = Compress::new(Compression::default(), false);
        let mut out = vec![0u8; data.len() + 64];
        compress
            .compress(data, &mut out, FlushCompress::Sync)
            .unwrap();
        out.truncate(compress.total_out() as usize);
        if out.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
            out.truncate(out.len() - 4);
        }
        out
    }

    #[test]
    fn permessage_deflate_round_trips() {
        let payload = b"the quick brown fox jumps over the lazy dog, repeatedly repeatedly";
        let compressed = deflate_for_test(payload);
        assert!(compressed.len() < payload.len(), "it actually compressed");
        let restored = inflate(&compressed, &Limits::default()).unwrap();
        assert_eq!(restored, payload);
    }

    #[test]
    fn an_inflate_bomb_is_refused() {
        // A megabyte of zeros compresses to almost nothing; inflating it under a small cap
        // must be refused as it expands rather than exhausting memory.
        let compressed = deflate_for_test(&vec![0u8; 1024 * 1024]);
        let limits = Limits {
            max_decompressed_bytes: 64 * 1024,
            ..Default::default()
        };
        assert!(inflate(&compressed, &limits).is_err());
    }

    #[tokio::test]
    async fn an_unmasked_client_frame_can_be_sent() {
        // A client frame must be masked; a conforming library will not send an unmasked one.
        // The frame-level path can, which is how a tester probes what a server does with it.
        let port = ws_echo_server().await;
        let service = HttpService::new("127.0.0.1", port, false);
        let mut connection = connect(&service, "/", &TlsConfig::verified(), &Limits::default())
            .await
            .unwrap();

        connection
            .send_frame(
                &Frame {
                    fin: true,
                    rsv1: false,
                    opcode: Opcode::Text,
                    masked: false,
                    payload: b"unmasked and forbidden".to_vec(),
                },
                None, // no mask key — an unmasked client frame
            )
            .await
            .unwrap();

        let echoed = connection
            .recv(std::time::Duration::from_secs(2))
            .await
            .unwrap()
            .expect("the echo server read the unmasked frame");
        assert_eq!(echoed.payload, b"unmasked and forbidden");
    }

    #[tokio::test]
    async fn a_server_that_does_not_upgrade_is_an_error() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 4096];
            let _ = socket.read(&mut scratch).await;
            let _ = socket
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let service = HttpService::new("127.0.0.1", port, false);
        let error = connect(&service, "/", &TlsConfig::verified(), &Limits::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "protocol");
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_or_loop(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let mut parser = FrameParser::new(1 << 16);
            parser.push(&bytes);
            // Pull frames until it stops making progress; must terminate and never panic.
            let mut guard = 0;
            while let Ok(Some(_)) = parser.next_frame() {
                guard += 1;
                prop_assert!(guard < 4096);
            }
        }

        #[test]
        fn inflating_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            // Garbage is an error, valid deflate is bounded output — neither panics or hangs.
            let _ = inflate(&bytes, &Limits::default());
        }
    }
}
