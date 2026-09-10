//! Chunked transfer decoding.
//!
//! Chunked framing is where a great many desync attacks live, because the chunk-size
//! line is parsed slightly differently by almost every implementation. Does a leading
//! `+` count? A `0x` prefix? Whitespace before the size? Does a chunk extension
//! terminate at the semicolon or swallow the rest of the line? Front-end and back-end
//! disagreeing on any of those is a smuggling primitive.
//!
//! So this decoder follows the same rule as the head parser: **permissive but loud**.
//! It accepts the odd spellings a lenient server would, and records each one as a
//! [`Quirk`] so the tester learns the target's parser is unusual — which is the actual
//! finding — rather than getting a generic decode error.
//!
//! It refuses only where continuing would produce a body that is not what the server
//! sent, since a wrong body becomes a wrong finding.
//!
//! # Incremental by construction
//!
//! [`Decoder`] is a state machine fed whatever bytes have arrived so far. That is what
//! lets the proxy forward a chunk the moment it is complete instead of waiting for the
//! terminating chunk — a server can legitimately stream for minutes, and buffering the
//! whole response first would make Hexora useless for anything long-lived.
//!
//! [`decode`] is the one-shot convenience wrapper, built on the same state machine so
//! there is only ever one parser to get right.

use bytes::{Buf, Bytes, BytesMut};
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{Header, Headers};
use hexora_types::limits::Limits;

use crate::parse::Quirk;

/// Where the decoder is in the chunked grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Reading a chunk-size line.
    Size,
    /// Copying chunk data; this many bytes still to come.
    Data { remaining: usize },
    /// Expecting the CRLF that follows chunk data.
    DataTerminator,
    /// Reading trailer fields up to the blank line.
    Trailers,
    /// The terminating chunk and its trailers have been consumed.
    Done,
}

/// An incremental chunked-body decoder.
#[derive(Debug)]
pub struct Decoder {
    state: State,
    quirks: Vec<Quirk>,
    trailers: Headers,
    produced: u64,
    truncated: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// A decoder positioned at the first chunk-size line.
    pub fn new() -> Self {
        Self {
            state: State::Size,
            quirks: Vec::new(),
            trailers: Headers::new(),
            produced: 0,
            truncated: false,
        }
    }

    /// Consumes as much of `buf` as forms complete chunk data, returning the decoded
    /// bytes. Whatever cannot yet be interpreted is left in `buf` for next time.
    ///
    /// Returning empty is normal, and simply means "need more bytes".
    pub fn push(&mut self, buf: &mut BytesMut, limits: &Limits) -> Result<Bytes> {
        let mut out = BytesMut::new();

        loop {
            match self.state {
                State::Done => break,

                State::Size => {
                    let Some((line, consumed)) = take_line(buf) else {
                        break;
                    };
                    let (size, extension) = parse_chunk_size(&line, &mut self.quirks)?;
                    buf.advance(consumed);
                    if extension {
                        push_once(&mut self.quirks, Quirk::ChunkExtension);
                    }
                    self.state = if size == 0 {
                        State::Trailers
                    } else {
                        let size = usize::try_from(size).map_err(|_| {
                            HexoraError::LimitExceeded(
                                hexora_types::error::LimitError::BodyTooLarge {
                                    limit: limits.max_body_bytes,
                                },
                            )
                        })?;
                        State::Data { remaining: size }
                    };
                }

                State::Data { remaining } => {
                    if buf.is_empty() {
                        break;
                    }

                    // Enforced here rather than after the body is assembled: a server
                    // that streams forever must be cut off while it is streaming.
                    let room = limits.max_body_bytes.saturating_sub(self.produced);
                    if room == 0 {
                        self.truncated = true;
                        self.state = State::Done;
                        break;
                    }

                    let take = remaining.min(buf.len()).min(room as usize);
                    out.extend_from_slice(&buf[..take]);
                    buf.advance(take);
                    self.produced += take as u64;

                    self.state = match remaining - take {
                        0 => State::DataTerminator,
                        left => State::Data { remaining: left },
                    };
                }

                State::DataTerminator => match buf.first() {
                    None => break,
                    Some(b'\r') => {
                        if buf.len() < 2 {
                            break;
                        }
                        // A lone CR followed by something else is malformed, but the
                        // byte count already told us where the chunk ended.
                        if buf[1] == b'\n' {
                            buf.advance(2);
                        } else {
                            push_once(&mut self.quirks, Quirk::MissingChunkTerminator);
                            buf.advance(1);
                        }
                        self.state = State::Size;
                    }
                    Some(b'\n') => {
                        push_once(&mut self.quirks, Quirk::BareLf);
                        buf.advance(1);
                        self.state = State::Size;
                    }
                    Some(_) => {
                        push_once(&mut self.quirks, Quirk::MissingChunkTerminator);
                        self.state = State::Size;
                    }
                },

                State::Trailers => {
                    let Some((line, consumed)) = take_line(buf) else {
                        break;
                    };
                    buf.advance(consumed);

                    if line.is_empty() {
                        if !self.trailers.is_empty() {
                            push_once(&mut self.quirks, Quirk::TrailerFields);
                        }
                        self.state = State::Done;
                        break;
                    }

                    if self.trailers.len() >= limits.max_header_count {
                        return Err(HexoraError::LimitExceeded(
                            hexora_types::error::LimitError::HeadersTooLarge {
                                limit: limits.max_header_count,
                            },
                        ));
                    }
                    match line.iter().position(|b| *b == b':') {
                        Some(colon) => self.trailers.append(Header {
                            name: String::from_utf8_lossy(trim_ascii(&line[..colon])).into_owned(),
                            value: Bytes::copy_from_slice(trim_ascii(&line[colon + 1..])),
                        }),
                        None => push_once(&mut self.quirks, Quirk::HeaderWithoutColon),
                    }
                }
            }
        }

        Ok(out.freeze())
    }

    /// Whether the terminating chunk has been consumed.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Whether a limit stopped decoding early.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Deviations seen so far.
    pub fn quirks(&self) -> &[Quirk] {
        &self.quirks
    }

    /// Trailer fields, populated once decoding is done.
    pub fn trailers(&self) -> &Headers {
        &self.trailers
    }

    /// Records a quirk observed by the caller rather than by the parser.
    pub fn note(&mut self, quirk: Quirk) {
        push_once(&mut self.quirks, quirk);
    }
}

/// The result of decoding a complete chunked body in one go.
#[derive(Debug, Clone)]
pub struct DecodedChunks {
    /// The reassembled body.
    pub body: Bytes,
    /// Trailer fields that followed the terminating chunk.
    pub trailers: Headers,
    /// Deviations worth telling the tester about.
    pub quirks: Vec<Quirk>,
    /// Whether a resource limit stopped decoding early.
    pub truncated: bool,
    /// How many input bytes the chunked framing consumed.
    ///
    /// Bytes beyond this were not part of this message — on a keep-alive connection
    /// they belong to the next response, and if none was requested their presence is
    /// itself a smuggling signal.
    pub consumed: usize,
}

/// Decodes a complete chunked body from `input`.
///
/// Returns `Ok(None)` when the input ends mid-message and more bytes are needed, so
/// the caller can read again rather than guessing.
pub fn decode(input: &[u8], limits: &Limits) -> Result<Option<DecodedChunks>> {
    let mut decoder = Decoder::new();
    let mut buf = BytesMut::from(input);
    let body = decoder.push(&mut buf, limits)?;

    if !decoder.is_done() && !decoder.truncated() {
        return Ok(None);
    }

    let consumed = input.len() - buf.len();
    if !buf.is_empty() {
        decoder.note(Quirk::DataAfterFinalChunk);
    }

    Ok(Some(DecodedChunks {
        body,
        trailers: decoder.trailers().clone(),
        quirks: decoder.quirks().to_vec(),
        truncated: decoder.truncated(),
        consumed,
    }))
}

/// Returns a complete line and how many bytes it occupied, terminator included.
fn take_line(buf: &BytesMut) -> Option<(Vec<u8>, usize)> {
    let lf = buf.iter().position(|b| *b == b'\n')?;
    let end = if lf > 0 && buf[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };
    Some((buf[..end].to_vec(), lf + 1))
}

/// Parses a chunk-size line, returning the size and whether an extension was present.
fn parse_chunk_size(line: &[u8], quirks: &mut Vec<Quirk>) -> Result<(u64, bool)> {
    let (size_part, extension) = match line.iter().position(|b| *b == b';') {
        Some(i) => (&line[..i], true),
        None => (line, false),
    };

    let trimmed = trim_ascii(size_part);
    if trimmed.len() != size_part.len() {
        // RFC 9112 allows no whitespace here. Servers that tolerate it disagree with
        // servers that do not, which is the whole game.
        push_once(quirks, Quirk::WhitespaceInChunkSize);
    }
    if trimmed.is_empty() {
        return Err(malformed("empty chunk size"));
    }

    // A `+`/`-` sign or an `0x` prefix is not valid hex per RFC 9112, but some parsers
    // accept them. Refusing outright would hide the target's leniency; accepting
    // silently would hide it too. So: accept, and say so.
    let mut digits = trimmed;
    if matches!(digits.first(), Some(b'+') | Some(b'-')) {
        push_once(quirks, Quirk::SignedChunkSize);
        digits = &digits[1..];
    }
    if digits.len() > 2 && digits[..2].eq_ignore_ascii_case(b"0x") {
        push_once(quirks, Quirk::PrefixedChunkSize);
        digits = &digits[2..];
    }
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(malformed(&format!(
            "invalid chunk size {:?}",
            String::from_utf8_lossy(trimmed)
        )));
    }
    if digits.len() > 1 && digits[0] == b'0' {
        push_once(quirks, Quirk::LeadingZeroChunkSize);
    }

    let text = std::str::from_utf8(digits).map_err(|_| malformed("non-ASCII chunk size"))?;
    let size = u64::from_str_radix(text, 16)
        .map_err(|_| malformed(&format!("chunk size {text:?} does not fit in 64 bits")))?;

    Ok((size, extension))
}

fn push_once(quirks: &mut Vec<Quirk>, quirk: Quirk) {
    if !quirks.contains(&quirk) {
        quirks.push(quirk);
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn malformed(reason: &str) -> HexoraError {
    HexoraError::Protocol(ProtocolError::InvalidChunkedEncoding(reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_ok(input: &[u8]) -> DecodedChunks {
        decode(input, &Limits::default())
            .expect("decoding should not error")
            .expect("input should be complete")
    }

    // -------------------------------------------------------------- happy path

    #[test]
    fn decodes_a_simple_chunked_body() {
        let result = decode_ok(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello world");
        assert!(result.trailers.is_empty());
        assert!(!result.truncated);
        assert!(result.quirks.is_empty(), "{:?}", result.quirks);
    }

    #[test]
    fn decodes_an_empty_body() {
        assert!(decode_ok(b"0\r\n\r\n").body.is_empty());
    }

    #[test]
    fn handles_a_chunk_size_needing_several_hex_digits() {
        let payload = vec![b'A'; 0x1a4];
        let mut input = format!("{:x}\r\n", payload.len()).into_bytes();
        input.extend_from_slice(&payload);
        input.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decode_ok(&input).body.len(), 0x1a4);
    }

    #[test]
    fn uppercase_hex_sizes_are_accepted() {
        assert_eq!(decode_ok(b"A\r\n0123456789\r\n0\r\n\r\n").body.len(), 10);
    }

    #[test]
    fn binary_chunk_data_survives() {
        let result = decode_ok(b"4\r\n\x00\xff\xfe\x01\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), &[0x00, 0xff, 0xfe, 0x01]);
    }

    #[test]
    fn chunk_data_containing_crlf_is_not_mistaken_for_framing() {
        // The length governs, not the content — otherwise a body containing CRLF
        // would desync the decoder.
        let result = decode_ok(b"7\r\na\r\nb\r\nc\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"a\r\nb\r\nc");
    }

    // ------------------------------------------------------------- incremental

    #[test]
    fn decoding_one_byte_at_a_time_gives_the_same_answer() {
        // The property that makes streaming safe: an arbitrary split of the input
        // must not change the output.
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n";
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();

        for byte in input {
            buf.extend_from_slice(&[*byte]);
            out.extend_from_slice(&decoder.push(&mut buf, &Limits::default()).unwrap());
        }

        assert!(decoder.is_done());
        assert_eq!(out, b"hello world");
        assert_eq!(decoder.trailers().get("X-T").unwrap().value_lossy(), "1");
    }

    #[test]
    fn every_split_point_produces_the_same_body() {
        let input = b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
        for split in 0..input.len() {
            let mut decoder = Decoder::new();
            let mut buf = BytesMut::from(&input[..split]);
            let mut out = Vec::new();
            out.extend_from_slice(&decoder.push(&mut buf, &Limits::default()).unwrap());
            buf.extend_from_slice(&input[split..]);
            out.extend_from_slice(&decoder.push(&mut buf, &Limits::default()).unwrap());

            assert!(decoder.is_done(), "split at {split} did not complete");
            assert_eq!(out, b"abcdef", "split at {split} changed the body");
        }
    }

    #[test]
    fn a_chunk_is_emitted_before_the_body_is_complete() {
        // The point of streaming: usable output before the terminating chunk.
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::from(&b"5\r\nhello\r\n"[..]);
        let first = decoder.push(&mut buf, &Limits::default()).unwrap();
        assert_eq!(first.as_ref(), b"hello");
        assert!(!decoder.is_done(), "more chunks may still follow");
    }

    #[test]
    fn incomplete_input_asks_for_more_rather_than_guessing() {
        for partial in [
            &b"5\r\nhel"[..],
            &b"5\r\nhello"[..],
            &b"5\r\nhello\r\n"[..],
            &b"5\r\nhello\r\n0\r\n"[..],
            &b"5"[..],
            &b""[..],
        ] {
            assert!(
                decode(partial, &Limits::default()).unwrap().is_none(),
                "{:?} should be incomplete",
                String::from_utf8_lossy(partial)
            );
        }
    }

    // ----------------------------------------------------------------- quirks

    #[test]
    fn chunk_extensions_are_accepted_and_flagged() {
        let result = decode_ok(b"5;name=value\r\nhello\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::ChunkExtension));
    }

    #[test]
    fn bare_lf_framing_is_accepted_and_flagged() {
        let result = decode_ok(b"5\nhello\n0\n\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::BareLf));
        assert!(Quirk::BareLf.is_smuggling_signal());
    }

    #[test]
    fn whitespace_around_the_size_is_accepted_and_flagged() {
        let result = decode_ok(b"5 \r\nhello\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::WhitespaceInChunkSize));
    }

    #[test]
    fn a_signed_chunk_size_is_accepted_and_flagged() {
        let result = decode_ok(b"+5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::SignedChunkSize));
    }

    #[test]
    fn an_0x_prefixed_chunk_size_is_accepted_and_flagged() {
        let result = decode_ok(b"0x5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::PrefixedChunkSize));
    }

    #[test]
    fn a_leading_zero_chunk_size_is_accepted_and_flagged() {
        let result = decode_ok(b"05\r\nhello\r\n0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::LeadingZeroChunkSize));
    }

    #[test]
    fn trailers_are_captured_and_flagged() {
        let result = decode_ok(b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert_eq!(
            result.trailers.get("X-Checksum").unwrap().value_lossy(),
            "abc"
        );
        assert!(result.quirks.contains(&Quirk::TrailerFields));
    }

    #[test]
    fn data_after_the_final_chunk_is_flagged() {
        // The smuggled-prefix signature: bytes nobody asked for, after the terminator.
        let result = decode_ok(b"0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n");
        assert!(result.quirks.contains(&Quirk::DataAfterFinalChunk));
        assert!(Quirk::DataAfterFinalChunk.is_smuggling_signal());
    }

    #[test]
    fn a_missing_chunk_terminator_is_flagged_but_decodes() {
        let result = decode_ok(b"5\r\nhello0\r\n\r\n");
        assert_eq!(result.body.as_ref(), b"hello");
        assert!(result.quirks.contains(&Quirk::MissingChunkTerminator));
    }

    #[test]
    fn consumed_reports_where_this_message_ended() {
        let input = b"5\r\nhello\r\n0\r\n\r\nLEFTOVER";
        let result = decode_ok(input);
        assert_eq!(&input[result.consumed..], b"LEFTOVER");
    }

    // ---------------------------------------------------------------- refusal

    #[test]
    fn a_non_hex_chunk_size_is_refused() {
        for input in [
            &b"zz\r\nhello\r\n0\r\n\r\n"[..],
            &b"\r\nhello\r\n0\r\n\r\n"[..],
            &b"5g\r\nhello\r\n0\r\n\r\n"[..],
        ] {
            let err = decode(input, &Limits::default()).unwrap_err();
            assert_eq!(
                err.code(),
                "protocol",
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn an_overlong_chunk_size_is_refused_rather_than_wrapping() {
        let err = decode(b"FFFFFFFFFFFFFFFFFF\r\n", &Limits::default()).unwrap_err();
        assert_eq!(err.code(), "protocol");
    }

    #[test]
    fn an_oversized_body_is_truncated_and_reported() {
        let limits = Limits {
            max_body_bytes: 8,
            ..Default::default()
        };
        let result = decode(
            b"20\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n",
            &limits,
        )
        .unwrap()
        .unwrap();
        assert!(result.truncated);
        assert!(result.body.len() <= 8);
    }

    #[test]
    fn a_body_streaming_forever_is_cut_off_mid_stream() {
        // No terminating chunk ever arrives. The limit, not the server, ends it.
        let limits = Limits {
            max_body_bytes: 1024,
            ..Default::default()
        };
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::new();

        for _ in 0..100 {
            buf.extend_from_slice(b"64\r\n");
            buf.extend_from_slice(&[b'A'; 0x64]);
            buf.extend_from_slice(b"\r\n");
            decoder.push(&mut buf, &limits).unwrap();
            if decoder.truncated() {
                break;
            }
        }
        assert!(decoder.truncated(), "an endless stream must be stopped");
    }

    #[test]
    fn too_many_trailers_are_refused() {
        let limits = Limits {
            max_header_count: 3,
            ..Default::default()
        };
        let mut input = b"0\r\n".to_vec();
        for i in 0..50 {
            input.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        input.extend_from_slice(b"\r\n");
        let err = decode(&input, &limits).unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[test]
    fn decoding_never_panics_on_arbitrary_input() {
        let inputs: [&[u8]; 9] = [
            b"",
            b"\r\n",
            b"0",
            b"0\r\n",
            b";\r\n",
            b"-\r\n",
            b"0x\r\n",
            b"\xff\xfe\x00",
            b"1\r\n\xff\r\n0\r\n\r\n",
        ];
        for input in inputs {
            let _ = decode(input, &Limits::default());
        }
    }
}
