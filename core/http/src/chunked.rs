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

use bytes::{Bytes, BytesMut};
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{Header, Headers};
use hexora_types::limits::Limits;

use crate::parse::Quirk;

/// The result of decoding a chunked body.
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
    /// Bytes beyond this in the buffer were not part of this message — on a keep-alive
    /// connection they belong to the next response, and if none was requested their
    /// presence is itself a smuggling signal.
    pub consumed: usize,
}

/// Decodes a complete chunked body from `input`.
///
/// Returns `Ok(None)` when the input ends mid-message and more bytes are needed, so
/// the caller can read again rather than guessing.
pub fn decode(input: &[u8], limits: &Limits) -> Result<Option<DecodedChunks>> {
    let mut cursor = 0usize;
    let mut body = BytesMut::new();
    let mut quirks: Vec<Quirk> = Vec::new();
    let mut truncated = false;

    loop {
        let Some((line, after_line)) = read_line(input, cursor) else {
            return Ok(None);
        };

        let (size, extension) = parse_chunk_size(line, &mut quirks)?;

        if extension && !quirks.contains(&Quirk::ChunkExtension) {
            quirks.push(Quirk::ChunkExtension);
        }

        if size == 0 {
            let Some((trailers, consumed)) = read_trailers(input, after_line, limits, &mut quirks)?
            else {
                return Ok(None);
            };

            if consumed < input.len() && !quirks.contains(&Quirk::DataAfterFinalChunk) {
                // Bytes after the terminator on a connection with no pipelined request
                // outstanding are the classic smuggled-prefix signature.
                quirks.push(Quirk::DataAfterFinalChunk);
            }

            return Ok(Some(DecodedChunks {
                body: body.freeze(),
                trailers,
                quirks,
                truncated,
                consumed,
            }));
        }

        // Bound the chunk before allocating for it: the size is attacker-controlled.
        let size = usize::try_from(size).map_err(|_| {
            HexoraError::LimitExceeded(hexora_types::error::LimitError::BodyTooLarge {
                limit: limits.max_body_bytes,
            })
        })?;
        if body.len() as u64 + size as u64 > limits.max_body_bytes {
            body.truncate(limits.max_body_bytes as usize);
            truncated = true;
            return Ok(Some(DecodedChunks {
                body: body.freeze(),
                trailers: Headers::new(),
                quirks,
                truncated,
                consumed: input.len(),
            }));
        }

        let end = after_line + size;
        if input.len() < end {
            return Ok(None);
        }
        body.extend_from_slice(&input[after_line..end]);

        // The chunk data is followed by CRLF. A server that omits it is a differential
        // worth noting, but the byte count already told us where the chunk ended.
        cursor = match input.get(end..end + 2) {
            Some(b"\r\n") => end + 2,
            Some([b'\n', _]) | Some([b'\n']) => {
                push_once(&mut quirks, Quirk::BareLf);
                end + 1
            }
            Some(_) => {
                push_once(&mut quirks, Quirk::MissingChunkTerminator);
                end
            }
            None => return Ok(None),
        };
    }
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

/// Reads trailer fields after the terminating chunk, up to the blank line.
fn read_trailers(
    input: &[u8],
    mut cursor: usize,
    limits: &Limits,
    quirks: &mut Vec<Quirk>,
) -> Result<Option<(Headers, usize)>> {
    let mut trailers = Headers::new();

    loop {
        let Some((line, next)) = read_line(input, cursor) else {
            return Ok(None);
        };
        cursor = next;

        if line.is_empty() {
            if !trailers.is_empty() {
                push_once(quirks, Quirk::TrailerFields);
            }
            return Ok(Some((trailers, cursor)));
        }

        if trailers.len() >= limits.max_header_count {
            return Err(HexoraError::LimitExceeded(
                hexora_types::error::LimitError::HeadersTooLarge {
                    limit: limits.max_header_count,
                },
            ));
        }

        if let Some(colon) = line.iter().position(|b| *b == b':') {
            trailers.append(Header {
                name: String::from_utf8_lossy(trim_ascii(&line[..colon])).into_owned(),
                value: Bytes::copy_from_slice(trim_ascii(&line[colon + 1..])),
            });
        } else {
            push_once(quirks, Quirk::HeaderWithoutColon);
        }
    }
}

/// Returns the line starting at `from` and the offset just past its terminator.
fn read_line(input: &[u8], from: usize) -> Option<(&[u8], usize)> {
    let rest = input.get(from..)?;
    let lf = rest.iter().position(|b| *b == b'\n')?;
    let end = if lf > 0 && rest[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };
    Some((&rest[..end], from + lf + 1))
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
        let result = decode_ok(b"0\r\n\r\n");
        assert!(result.body.is_empty());
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

    // ---------------------------------------------------------------- partial

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
