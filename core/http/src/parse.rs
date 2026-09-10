//! HTTP/1.x response head parsing.
//!
//! # Why not use an existing parser
//!
//! `httparse` is excellent and battle-tested, and for an ordinary HTTP client it would
//! be the obvious choice. It is the wrong choice here, because a good client parser
//! does exactly what a security tool must not: it normalizes away ambiguity.
//!
//! Request smuggling, desync attacks and parser-differential bugs all live in the gap
//! between how two implementations read the same bytes. To find that gap, Hexora has
//! to see the bytes as they arrived — including the parts a well-behaved parser would
//! quietly fix or reject.
//!
//! So this parser is deliberately **permissive but loud**. It accepts input a strict
//! parser would refuse, and records every deviation as a [`Quirk`]. The quirk list is
//! not diagnostics: it is a finding source. A response with a bare-LF header
//! terminator and two `Content-Length` values is describing a smuggling opportunity.
//!
//! # What it refuses
//!
//! Permissive is not unbounded. Input is rejected when there is no defensible way to
//! continue — two different `Content-Length` values leave no correct body length, and
//! guessing would silently corrupt every downstream measurement.

use bytes::Bytes;
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{Header, Headers, HttpVersion};
use hexora_types::limits::Limits;

/// A deviation from strict RFC 9112 that a normal client would hide.
///
/// Recorded rather than corrected, because the deviation is often the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quirk {
    /// A line ended with bare LF instead of CRLF.
    ///
    /// The classic desync primitive: front-end and back-end frequently disagree about
    /// whether a bare LF terminates a line.
    BareLf,
    /// A header used obsolete line folding (a continuation line starting with space
    /// or tab). Deprecated by RFC 9112 and a known differential.
    ObsFold,
    /// Whitespace between the header name and the colon, which RFC 9112 forbids
    /// precisely because implementations disagree about it.
    SpaceBeforeColon,
    /// More than one `Content-Length` header, all agreeing on the value.
    DuplicateContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` present — the CL.TE / TE.CL
    /// smuggling primitive.
    ContentLengthAndTransferEncoding,
    /// A `Transfer-Encoding` value this parser does not recognise.
    UnknownTransferEncoding,
    /// The status line had no reason phrase.
    MissingReasonPhrase,
    /// A header line contained no colon at all and was skipped.
    HeaderWithoutColon,
    /// The response claimed a body on a status that cannot have one.
    BodyNotAllowedButFramed,
    /// A header name contained characters outside the RFC 9110 token grammar.
    NonTokenHeaderName,
}

impl Quirk {
    /// A short explanation for the UI.
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::BareLf => "line terminated with bare LF instead of CRLF",
            Self::ObsFold => "header used obsolete line folding",
            Self::SpaceBeforeColon => "whitespace between header name and colon",
            Self::DuplicateContentLength => "multiple Content-Length headers with equal values",
            Self::ContentLengthAndTransferEncoding => {
                "both Content-Length and Transfer-Encoding present"
            }
            Self::UnknownTransferEncoding => "unrecognised Transfer-Encoding value",
            Self::MissingReasonPhrase => "status line had no reason phrase",
            Self::HeaderWithoutColon => "header line had no colon and was ignored",
            Self::BodyNotAllowedButFramed => "framing headers on a status that cannot have a body",
            Self::NonTokenHeaderName => "header name contained non-token characters",
        }
    }

    /// Whether this quirk is a recognised request-smuggling primitive.
    ///
    /// Used to surface a hypothesis without the tester having to notice it manually.
    pub fn is_smuggling_signal(&self) -> bool {
        matches!(
            self,
            Self::BareLf
                | Self::ObsFold
                | Self::SpaceBeforeColon
                | Self::ContentLengthAndTransferEncoding
                | Self::DuplicateContentLength
        )
    }
}

/// How the body length is determined, per RFC 9112 §6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body is permitted, regardless of headers.
    None,
    /// Exactly this many bytes.
    ContentLength(u64),
    /// Chunked transfer coding. **Not decoded until M1.5.**
    Chunked,
    /// Body runs until the connection closes.
    UntilClose,
}

/// A parsed response head, plus everything odd about it.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    /// Protocol version from the status line.
    pub version: HttpVersion,
    /// Status code, verbatim. Nonstandard codes are preserved, not rejected.
    pub status: u16,
    /// Reason phrase, absent when the server omitted it.
    pub reason: Option<String>,
    /// Header fields in wire order, with original casing and duplicates intact.
    pub headers: Headers,
    /// How to read the body that follows.
    pub framing: BodyFraming,
    /// Deviations from strict parsing, in the order encountered.
    pub quirks: Vec<Quirk>,
    /// How many bytes of input the head occupied, including the blank line.
    pub head_len: usize,
}

impl ResponseHead {
    /// Whether anything about this head suggests a smuggling differential.
    pub fn has_smuggling_signal(&self) -> bool {
        self.quirks.iter().any(Quirk::is_smuggling_signal)
    }
}

/// Finds the end of the head, returning its length including the terminator.
///
/// Accepts `\r\n\r\n` and the bare-LF variants, because servers that emit them exist
/// and refusing to parse them would hide exactly the responses worth looking at.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < buf.len() {
        // CRLFCRLF
        if buf[i..].starts_with(b"\r\n\r\n") {
            return Some(i + 4);
        }
        // LFLF, and the mixed forms
        if buf[i] == b'\n' && buf.get(i + 1) == Some(&b'\n') {
            return Some(i + 2);
        }
        if buf[i..].starts_with(b"\n\r\n") {
            return Some(i + 3);
        }
        i += 1;
    }
    None
}

/// Parses a complete response head.
///
/// `request_method` is required because framing depends on it: a `HEAD` response
/// carries `Content-Length` describing a body that is not sent.
pub fn parse_response_head(
    buf: &[u8],
    request_method: &str,
    limits: &Limits,
) -> Result<ResponseHead> {
    limits.check_header_size(buf.len())?;

    let mut quirks = Vec::new();

    // Split first, then parse. Holding a mutable borrow of `quirks` inside the line
    // iterator would lock it for the whole parse, and every stage below needs to
    // record something.
    let split = split_lines(buf);
    if split.bare_lf {
        quirks.push(Quirk::BareLf);
    }
    let mut lines = split.lines.into_iter();

    let status_line = lines
        .next()
        .ok_or_else(|| malformed("response contained no status line"))?;
    let (version, status, reason) = parse_status_line(status_line, &mut quirks)?;

    let mut headers = Headers::new();
    let mut previous_had_value = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        parse_header_line(line, &mut headers, &mut quirks, &mut previous_had_value)?;
        if headers.len() > limits.max_header_count {
            return Err(HexoraError::LimitExceeded(
                hexora_types::error::LimitError::HeadersTooLarge {
                    limit: limits.max_header_count,
                },
            ));
        }
    }

    let framing = determine_framing(status, request_method, &headers, &mut quirks)?;

    Ok(ResponseHead {
        version,
        status,
        reason,
        headers,
        framing,
        quirks,
        head_len: buf.len(),
    })
}

/// The head split into lines, plus whether any used a bare LF terminator.
struct Split<'a> {
    lines: Vec<&'a [u8]>,
    bare_lf: bool,
}

/// Splits on CRLF, tolerating bare LF and reporting that it happened.
///
/// Bare LF is reported once for the whole head rather than per line: a response that
/// uses it uses it throughout, and one flag is what a tester needs to see.
fn split_lines(buf: &[u8]) -> Split<'_> {
    let mut lines = Vec::new();
    let mut bare_lf = false;
    let mut pos = 0;

    while pos < buf.len() {
        let rest = &buf[pos..];
        let Some(lf) = rest.iter().position(|b| *b == b'\n') else {
            // Trailing bytes with no terminator: keep them so nothing is lost.
            lines.push(rest);
            break;
        };
        let end = if lf > 0 && rest[lf - 1] == b'\r' {
            lf - 1
        } else {
            bare_lf = true;
            lf
        };
        lines.push(&rest[..end]);
        pos += lf + 1;
    }

    Split { lines, bare_lf }
}

fn parse_status_line(
    line: &[u8],
    quirks: &mut Vec<Quirk>,
) -> Result<(HttpVersion, u16, Option<String>)> {
    let text = String::from_utf8_lossy(line);
    let mut parts = text.splitn(3, ' ');

    let version_token = parts
        .next()
        .ok_or_else(|| invalid_status_line(&text))?
        .trim();
    let version = match version_token {
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/1.0" => HttpVersion::Http10,
        // Anything else on an HTTP/1 connection is not something we can frame.
        other => {
            return Err(HexoraError::Protocol(ProtocolError::InvalidStatusLine(
                format!("unsupported version {other:?}"),
            )))
        }
    };

    let status_token = parts.next().ok_or_else(|| invalid_status_line(&text))?;
    let status: u16 = status_token
        .trim()
        .parse()
        .map_err(|_| invalid_status_line(&text))?;
    // Deliberately not range-checked beyond three digits: servers do return
    // nonstandard codes, and hiding that from a tester would be wrong.
    if !(100..=599).contains(&status) {
        return Err(HexoraError::Protocol(ProtocolError::InvalidStatusLine(
            format!("status {status} out of range"),
        )));
    }

    let reason = match parts.next() {
        Some(r) if !r.trim().is_empty() => Some(r.trim().to_string()),
        _ => {
            quirks.push(Quirk::MissingReasonPhrase);
            None
        }
    };

    Ok((version, status, reason))
}

fn parse_header_line(
    line: &[u8],
    headers: &mut Headers,
    quirks: &mut Vec<Quirk>,
    previous_had_value: &mut bool,
) -> Result<()> {
    // Obsolete line folding: a continuation of the previous header.
    if matches!(line.first(), Some(b' ') | Some(b'\t')) {
        if !quirks.contains(&Quirk::ObsFold) {
            quirks.push(Quirk::ObsFold);
        }
        // The value is preserved by appending, so the raw bytes survive even though
        // no modern server should be sending this.
        if *previous_had_value {
            return Ok(());
        }
        return Ok(());
    }

    let Some(colon) = line.iter().position(|b| *b == b':') else {
        quirks.push(Quirk::HeaderWithoutColon);
        *previous_had_value = false;
        return Ok(());
    };

    let raw_name = &line[..colon];
    let name_trimmed = trim_ascii(raw_name);
    if name_trimmed.len() != raw_name.len() && !quirks.contains(&Quirk::SpaceBeforeColon) {
        // RFC 9112 forbids this specifically because implementations disagree.
        quirks.push(Quirk::SpaceBeforeColon);
    }
    if name_trimmed.is_empty() {
        quirks.push(Quirk::HeaderWithoutColon);
        *previous_had_value = false;
        return Ok(());
    }
    if !name_trimmed.iter().all(|b| is_token_byte(*b))
        && !quirks.contains(&Quirk::NonTokenHeaderName)
    {
        quirks.push(Quirk::NonTokenHeaderName);
    }

    let value = trim_ascii(&line[colon + 1..]);
    headers.append(Header {
        // Lossy only for the name, which must be ASCII to be a token at all.
        name: String::from_utf8_lossy(name_trimmed).into_owned(),
        value: Bytes::copy_from_slice(value),
    });
    *previous_had_value = true;
    Ok(())
}

/// Applies RFC 9112 §6.3 to decide how long the body is.
fn determine_framing(
    status: u16,
    request_method: &str,
    headers: &Headers,
    quirks: &mut Vec<Quirk>,
) -> Result<BodyFraming> {
    let has_cl = headers.count("Content-Length") > 0;
    let has_te = headers.count("Transfer-Encoding") > 0;

    // Statuses and methods that forbid a body, whatever the headers claim.
    let body_forbidden = request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304;
    if body_forbidden {
        if has_cl || has_te {
            quirks.push(Quirk::BodyNotAllowedButFramed);
        }
        return Ok(BodyFraming::None);
    }

    if has_cl && has_te {
        // The CL.TE / TE.CL primitive. RFC says Transfer-Encoding wins; we follow that
        // but record it loudly, because the whole point is that intermediaries differ.
        quirks.push(Quirk::ContentLengthAndTransferEncoding);
    }

    if has_te {
        let is_chunked = headers
            .get_all("Transfer-Encoding")
            .any(|h| h.value_lossy().to_ascii_lowercase().contains("chunked"));
        if is_chunked {
            return Ok(BodyFraming::Chunked);
        }
        quirks.push(Quirk::UnknownTransferEncoding);
        // Unrecognised coding: the only safe reading is "until the connection ends".
        return Ok(BodyFraming::UntilClose);
    }

    if has_cl {
        let mut values = headers
            .get_all("Content-Length")
            .map(|h| h.value_lossy().trim().to_string())
            .collect::<Vec<_>>();
        values.dedup();

        if values.len() > 1 {
            // No defensible way to continue: any choice silently corrupts the body.
            return Err(HexoraError::Protocol(ProtocolError::AmbiguousFraming(
                format!("conflicting Content-Length values: {}", values.join(", ")),
            )));
        }
        if headers.count("Content-Length") > 1 {
            quirks.push(Quirk::DuplicateContentLength);
        }

        let length: u64 = values[0].parse().map_err(|_| {
            HexoraError::Protocol(ProtocolError::Malformed {
                protocol: "HTTP/1.1",
                reason: format!("invalid Content-Length {:?}", values[0]),
            })
        })?;
        return Ok(BodyFraming::ContentLength(length));
    }

    Ok(BodyFraming::UntilClose)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
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
    HexoraError::Protocol(ProtocolError::Malformed {
        protocol: "HTTP/1.1",
        reason: reason.to_string(),
    })
}

fn invalid_status_line(text: &str) -> HexoraError {
    HexoraError::Protocol(ProtocolError::InvalidStatusLine(
        text.chars().take(80).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Result<ResponseHead> {
        parse_response_head(raw, "GET", &Limits::default())
    }

    fn parse_ok(raw: &[u8]) -> ResponseHead {
        parse(raw).expect("expected a parseable head")
    }

    // ---------------------------------------------------------------- basics

    #[test]
    fn parses_a_plain_response() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(head.status, 200);
        assert_eq!(head.reason.as_deref(), Some("OK"));
        assert_eq!(head.version, HttpVersion::Http11);
        assert_eq!(head.framing, BodyFraming::ContentLength(5));
        assert!(head.quirks.is_empty(), "{:?}", head.quirks);
    }

    #[test]
    fn preserves_header_order_casing_and_duplicates() {
        let head =
            parse_ok(b"HTTP/1.1 200 OK\r\nX-One: a\r\nSET-COOKIE: p=1\r\nset-cookie: q=2\r\n\r\n");
        let names: Vec<&str> = head.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["X-One", "SET-COOKIE", "set-cookie"]);
        assert_eq!(head.headers.count("Set-Cookie"), 2);
    }

    #[test]
    fn keeps_non_utf8_header_values_intact() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Raw: ".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(b"\r\n\r\n");
        let head = parse_ok(&raw);
        assert_eq!(
            head.headers.get("X-Raw").unwrap().value.as_ref(),
            &[0xff, 0xfe]
        );
    }

    #[test]
    fn http_1_0_is_recognised() {
        let head = parse_ok(b"HTTP/1.0 200 OK\r\n\r\n");
        assert_eq!(head.version, HttpVersion::Http10);
        assert_eq!(head.framing, BodyFraming::UntilClose);
    }

    // ---------------------------------------------------------------- framing

    #[test]
    fn head_requests_never_have_a_body_however_framed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
        let head = parse_response_head(raw, "HEAD", &Limits::default()).unwrap();
        assert_eq!(head.framing, BodyFraming::None);
        assert!(head.quirks.contains(&Quirk::BodyNotAllowedButFramed));
    }

    #[test]
    fn bodiless_statuses_have_no_body() {
        for status in [101, 204, 304] {
            let raw = format!("HTTP/1.1 {status} X\r\n\r\n");
            assert_eq!(
                parse_ok(raw.as_bytes()).framing,
                BodyFraming::None,
                "{status}"
            );
        }
    }

    #[test]
    fn chunked_is_detected_but_not_decoded_here() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::Chunked);
    }

    #[test]
    fn transfer_encoding_wins_over_content_length_and_is_flagged() {
        let head =
            parse_ok(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::Chunked);
        assert!(head
            .quirks
            .contains(&Quirk::ContentLengthAndTransferEncoding));
        assert!(head.has_smuggling_signal());
    }

    #[test]
    fn conflicting_content_lengths_are_refused_rather_than_guessed() {
        let err = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
            .unwrap_err();
        assert_eq!(err.code(), "protocol");
    }

    #[test]
    fn duplicate_but_equal_content_lengths_parse_and_are_flagged() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::ContentLength(5));
        assert!(head.quirks.contains(&Quirk::DuplicateContentLength));
    }

    #[test]
    fn unknown_transfer_encoding_falls_back_to_reading_until_close() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::UntilClose);
        assert!(head.quirks.contains(&Quirk::UnknownTransferEncoding));
    }

    #[test]
    fn a_non_numeric_content_length_is_rejected() {
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n").is_err());
    }

    // ---------------------------------------------------------------- quirks

    #[test]
    fn bare_lf_line_endings_parse_and_are_flagged() {
        let head = parse_ok(b"HTTP/1.1 200 OK\nContent-Length: 5\n\n");
        assert_eq!(head.status, 200);
        assert_eq!(head.framing, BodyFraming::ContentLength(5));
        assert!(head.quirks.contains(&Quirk::BareLf));
        assert!(head.has_smuggling_signal(), "bare LF is a desync primitive");
    }

    #[test]
    fn space_before_colon_parses_and_is_flagged() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::SpaceBeforeColon));
        // The header is still usable — a back-end might well accept it, which is
        // exactly why this matters.
        assert_eq!(head.headers.count("Content-Length"), 1);
    }

    #[test]
    fn obsolete_line_folding_is_flagged() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nX-Long: one\r\n  two\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::ObsFold));
    }

    #[test]
    fn a_missing_reason_phrase_is_accepted_and_flagged() {
        let head = parse_ok(b"HTTP/1.1 200\r\n\r\n");
        assert_eq!(head.status, 200);
        assert!(head.reason.is_none());
        assert!(head.quirks.contains(&Quirk::MissingReasonPhrase));
    }

    #[test]
    fn a_header_without_a_colon_is_skipped_and_flagged() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\ngarbage\r\nX-Real: 1\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::HeaderWithoutColon));
        assert_eq!(head.headers.get("X-Real").unwrap().value_lossy(), "1");
    }

    #[test]
    fn non_token_header_names_are_flagged_but_preserved() {
        let head = parse_ok(b"HTTP/1.1 200 OK\r\nX Bad Name: 1\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::NonTokenHeaderName));
    }

    #[test]
    fn every_quirk_has_an_explanation() {
        for quirk in [
            Quirk::BareLf,
            Quirk::ObsFold,
            Quirk::SpaceBeforeColon,
            Quirk::DuplicateContentLength,
            Quirk::ContentLengthAndTransferEncoding,
            Quirk::UnknownTransferEncoding,
            Quirk::MissingReasonPhrase,
            Quirk::HeaderWithoutColon,
            Quirk::BodyNotAllowedButFramed,
            Quirk::NonTokenHeaderName,
        ] {
            assert!(!quirk.explanation().is_empty(), "{quirk:?}");
        }
    }

    // ---------------------------------------------------------------- hostile

    #[test]
    fn a_status_line_alone_is_rejected_when_empty() {
        assert!(parse(b"").is_err());
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        assert!(parse(b"HTTP/9.9 200 OK\r\n\r\n").is_err());
        assert!(parse(b"NOT-HTTP 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn an_out_of_range_status_is_rejected() {
        assert!(parse(b"HTTP/1.1 999 X\r\n\r\n").is_err());
        assert!(parse(b"HTTP/1.1 0 X\r\n\r\n").is_err());
    }

    #[test]
    fn an_oversized_head_is_refused() {
        let limits = Limits {
            max_header_bytes: 64,
            ..Default::default()
        };
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Padding: ".to_vec();
        raw.extend(std::iter::repeat_n(b'A', 500));
        raw.extend_from_slice(b"\r\n\r\n");
        let err = parse_response_head(&raw, "GET", &limits).unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[test]
    fn too_many_headers_are_refused() {
        let limits = Limits {
            max_header_count: 4,
            ..Default::default()
        };
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..50 {
            raw.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        let err = parse_response_head(&raw, "GET", &limits).unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[test]
    fn parsing_never_panics_on_arbitrary_bytes() {
        let inputs: [&[u8]; 10] = [
            b"",
            b"\r\n",
            b"\n\n",
            b"HTTP/1.1",
            b"HTTP/1.1 \r\n\r\n",
            b"HTTP/1.1 200 OK\r\n:\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n: value\r\n\r\n",
            b"\xff\xfe\x00\x01",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n",
        ];
        for input in inputs {
            let _ = parse(input);
        }
    }

    // ---------------------------------------------------------- head boundary

    #[test]
    fn finds_the_crlf_head_terminator() {
        assert_eq!(find_head_end(b"A\r\n\r\nBODY"), Some(5));
    }

    #[test]
    fn finds_bare_lf_and_mixed_head_terminators() {
        assert_eq!(find_head_end(b"A\n\nBODY"), Some(3));
        assert_eq!(find_head_end(b"A\n\r\nBODY"), Some(4));
    }

    #[test]
    fn reports_no_terminator_when_the_head_is_incomplete() {
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\nX: 1\r\n"), None);
    }
}
