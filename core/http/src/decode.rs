//! Content decoding: gzip, deflate and brotli.
//!
//! # Why this is a security boundary, not plumbing
//!
//! The compressed bytes come from the target. Compression is the cheapest asymmetric
//! attack there is — a few kilobytes on the wire can become tens of gigabytes in the
//! reader's memory — and a security tool is expected to point itself at systems that
//! might do that deliberately.
//!
//! So decoding never runs to completion and then checks the size. It runs in bounded
//! steps, and [`Limits::check_decompression`] is consulted after **every** step. A
//! bomb is stopped while it is expanding, not after.
//!
//! The two-sided check matters: an absolute cap alone lets a slow bomb through under
//! the ceiling, and a ratio alone flags legitimate documents that happen to compress
//! well. Both together are what distinguishes them.
//!
//! # Known gap
//!
//! The decoded body replaces the compressed one, so the original wire bytes are not
//! retained. That is at odds with Hexora's "preserve the wire" principle and is
//! deliberate only until M3, where the traffic store keeps both: the compressed form
//! as it arrived, and the decoded form for searching and matching.

use std::io::Read;

use bytes::Bytes;
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::limits::Limits;

/// Bytes pulled from the decoder before each limit check.
///
/// Small enough that a bomb cannot get far between checks, large enough that ordinary
/// bodies do not pay for thousands of round trips.
const STEP: usize = 64 * 1024;

/// A content coding Hexora can reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    /// RFC 1952 gzip.
    Gzip,
    /// `deflate`, which servers send both zlib-wrapped and raw.
    Deflate,
    /// RFC 7932 brotli.
    Brotli,
    /// Explicitly no coding. Valid in a `Content-Encoding` list and worth keeping so
    /// the header can be reported faithfully.
    Identity,
}

impl Coding {
    /// Parses a single coding token, case-insensitively.
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "identity" | "" => Some(Self::Identity),
            _ => None,
        }
    }
}

/// The outcome of decoding a body.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// The decoded bytes.
    pub body: Bytes,
    /// Codings that were reversed, in the order applied.
    pub applied: Vec<Coding>,
    /// Whether a limit stopped decoding early.
    pub truncated: bool,
}

/// Reverses the codings named in a `Content-Encoding` header value.
///
/// Codings are listed in the order they were applied, so they are reversed
/// right-to-left. An unrecognised coding is an error rather than a silent pass-through:
/// returning still-encoded bytes labelled as a body would make every downstream match
/// and measurement wrong.
pub fn decode_body(content_encoding: &str, body: &[u8], limits: &Limits) -> Result<Decoded> {
    let tokens: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    let mut codings = Vec::with_capacity(tokens.len());
    for token in &tokens {
        match Coding::parse(token) {
            Some(coding) => codings.push(coding),
            None => {
                return Err(HexoraError::Protocol(ProtocolError::UnsupportedEncoding(
                    (*token).to_string(),
                )))
            }
        }
    }

    let mut current = Bytes::copy_from_slice(body);
    let mut applied = Vec::new();
    let mut truncated = false;

    for coding in codings.iter().rev() {
        if *coding == Coding::Identity {
            continue;
        }
        let (decoded, cut) = decode_one(*coding, &current, limits)?;
        current = decoded;
        truncated |= cut;
        applied.push(*coding);
        if truncated {
            // No point unwrapping further layers of a body we already cut short: the
            // result would be garbage presented as content.
            break;
        }
    }

    applied.reverse();
    Ok(Decoded {
        body: current,
        applied,
        truncated,
    })
}

fn decode_one(coding: Coding, input: &[u8], limits: &Limits) -> Result<(Bytes, bool)> {
    let reader: Box<dyn Read> = match coding {
        Coding::Gzip => Box::new(flate2::read::MultiGzDecoder::new(input)),
        // Servers labelled `deflate` send raw deflate about as often as they send the
        // zlib wrapper RFC 9110 actually specifies, so try zlib and fall back.
        Coding::Deflate => {
            if let Ok(result) = read_bounded(
                &mut flate2::read::ZlibDecoder::new(input),
                input.len() as u64,
                limits,
            ) {
                return Ok(result);
            }
            Box::new(flate2::read::DeflateDecoder::new(input))
        }
        Coding::Brotli => Box::new(brotli::Decompressor::new(input, STEP)),
        Coding::Identity => return Ok((Bytes::copy_from_slice(input), false)),
    };

    let mut reader = reader;
    read_bounded(&mut reader, input.len() as u64, limits)
}

/// Pulls from `reader` in bounded steps, checking limits after each one.
fn read_bounded(
    reader: &mut dyn Read,
    compressed_len: u64,
    limits: &Limits,
) -> Result<(Bytes, bool)> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; STEP];

    loop {
        let read = reader.read(&mut chunk).map_err(|e| {
            HexoraError::Protocol(ProtocolError::DecodeFailed {
                encoding: "content-encoding".to_string(),
                reason: e.to_string(),
            })
        })?;
        if read == 0 {
            return Ok((Bytes::from(out), false));
        }
        out.extend_from_slice(&chunk[..read]);

        // The whole point: checked while expanding, not after.
        if let Err(e) = limits.check_decompression(compressed_len, out.len() as u64) {
            tracing::warn!(
                compressed = compressed_len,
                decompressed = out.len(),
                "stopped decoding: {e}"
            );
            out.truncate(limits.max_decompressed_bytes as usize);
            return Ok((Bytes::from(out), true));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn brotli_encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        writer.write_all(data).unwrap();
        drop(writer);
        out
    }

    // ---------------------------------------------------------------- codings

    #[test]
    fn decodes_gzip() {
        let decoded = decode_body("gzip", &gzip(b"hello world"), &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"hello world");
        assert_eq!(decoded.applied, vec![Coding::Gzip]);
        assert!(!decoded.truncated);
    }

    #[test]
    fn decodes_deflate_with_a_zlib_wrapper() {
        let decoded = decode_body("deflate", &zlib(b"hello world"), &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"hello world");
    }

    #[test]
    fn decodes_brotli() {
        let decoded =
            decode_body("br", &brotli_encode(b"hello world"), &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"hello world");
        assert_eq!(decoded.applied, vec![Coding::Brotli]);
    }

    #[test]
    fn an_empty_content_encoding_leaves_the_body_alone() {
        let decoded = decode_body("", b"plain", &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"plain");
        assert!(decoded.applied.is_empty());
    }

    #[test]
    fn identity_is_a_no_op() {
        let decoded = decode_body("identity", b"plain", &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"plain");
    }

    #[test]
    fn coding_names_are_case_insensitive() {
        let decoded = decode_body("GZIP", &gzip(b"x"), &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"x");
    }

    #[test]
    fn stacked_codings_are_reversed_in_the_right_order() {
        // Applied gzip first, then brotli, so Content-Encoding lists "gzip, br".
        let stacked = brotli_encode(&gzip(b"layered"));
        let decoded = decode_body("gzip, br", &stacked, &Limits::default()).unwrap();
        assert_eq!(decoded.body.as_ref(), b"layered");
        assert_eq!(decoded.applied, vec![Coding::Gzip, Coding::Brotli]);
    }

    #[test]
    fn an_unknown_coding_is_refused_rather_than_passed_through() {
        // Returning still-encoded bytes as if they were content would make every
        // downstream match wrong.
        let err = decode_body("exotic-thing", b"data", &Limits::default()).unwrap_err();
        assert_eq!(err.code(), "protocol");
        assert!(err.to_string().contains("exotic-thing"), "{err}");
    }

    #[test]
    fn corrupt_compressed_data_is_a_decode_error_not_a_panic() {
        let err = decode_body("gzip", b"this is not gzip at all", &Limits::default()).unwrap_err();
        assert_eq!(err.code(), "protocol");
    }

    // ------------------------------------------------------------------ bombs

    #[test]
    fn a_decompression_bomb_is_stopped_while_expanding() {
        // ~10 MB of zeroes compresses to a few kilobytes: a ratio far past the cap.
        let bomb = gzip(&vec![0u8; 10 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "test premise: the input is small");

        let limits = Limits {
            max_decompressed_bytes: 1024 * 1024,
            ..Default::default()
        };
        let decoded = decode_body("gzip", &bomb, &limits).unwrap();

        assert!(decoded.truncated, "the bomb must be reported as cut short");
        assert!(
            decoded.body.len() <= limits.max_decompressed_bytes as usize,
            "{} bytes got past a {} byte cap",
            decoded.body.len(),
            limits.max_decompressed_bytes
        );
    }

    #[test]
    fn an_ordinary_compressible_document_is_not_mistaken_for_a_bomb() {
        // Real HTML compresses perhaps 5-10x. Flagging that would make the protection
        // useless in practice.
        let html = "<html><body>".to_string()
            + &"<p>content paragraph</p>".repeat(2000)
            + "</body></html>";
        let decoded = decode_body("gzip", &gzip(html.as_bytes()), &Limits::default()).unwrap();
        assert!(!decoded.truncated, "a normal page must decode fully");
        assert_eq!(decoded.body.len(), html.len());
    }

    #[test]
    fn a_bomb_hidden_under_another_coding_is_still_stopped() {
        let bomb = brotli_encode(&gzip(&vec![0u8; 8 * 1024 * 1024]));
        let limits = Limits {
            max_decompressed_bytes: 256 * 1024,
            ..Default::default()
        };
        let decoded = decode_body("gzip, br", &bomb, &limits).unwrap();
        assert!(decoded.truncated, "the inner bomb must still be caught");
        assert!(
            decoded.body.len() <= limits.max_decompressed_bytes as usize,
            "{} bytes got past a {} byte cap",
            decoded.body.len(),
            limits.max_decompressed_bytes
        );
        // Both layers were attempted: the brotli wrapper is tiny, so the limit only
        // bites once the gzip underneath starts expanding.
        assert_eq!(decoded.applied, vec![Coding::Gzip, Coding::Brotli]);
    }

    #[test]
    fn coding_parsing_accepts_the_aliases_servers_actually_send() {
        assert_eq!(Coding::parse("x-gzip"), Some(Coding::Gzip));
        assert_eq!(Coding::parse(" BR "), Some(Coding::Brotli));
        assert_eq!(Coding::parse("identity"), Some(Coding::Identity));
        assert_eq!(Coding::parse("snappy"), None);
    }
}
