//! The raw editing surface.
//!
//! A repeater is a text editor that happens to speak HTTP. The tester sees the request
//! as bytes, changes the bytes, and sends the bytes. That round trip is this module.
//!
//! # Nothing is corrected
//!
//! Every other tool in this category "helps". Burp updates `Content-Length` for you by
//! default; most HTTP libraries add a `Host` header, re-case field names, reorder
//! fields and collapse duplicates. Each of those is a reasonable default for a client
//! library and fatal for a security tool: the request that gets sent is no longer the
//! request that was written, and a smuggling or normalization test becomes a test of
//! the tool instead of the target.
//!
//! So [`parse`] corrects nothing. A `Content-Length` that disagrees with the body is
//! sent as written; a missing `Host` stays missing; duplicate `Transfer-Encoding`
//! headers survive. What the module does instead is *notice* — [`Draft::warnings`]
//! reports every inconsistency it can see, so the difference between "deliberate" and
//! "typo" stays with the person who can tell them apart.
//!
//! # One thing that is not byte-exact
//!
//! A request is parsed into [`HttpRequest`], which stores fields rather than bytes, and
//! is re-serialized with CRLF line endings on the way out. An editor that saves LF-only
//! text will therefore have its request sent with CRLF. The parse records a
//! [`Quirk::BareLf`] and [`Draft::warnings`] says so plainly. Sending a bare-LF request
//! byte-for-byte needs a raw send path that bypasses the message model, which does not
//! exist yet.

use hexora_http::{find_head_end, parse_request_head, Quirk, RequestTarget};
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{HttpRequest, HttpService};
use hexora_types::limits::Limits;

/// Renders a request as the bytes that will go on the wire.
///
/// This is exactly what [`hexora_http::serialize_request`] sends, so what the tester
/// edits is what the target receives — not a pretty-printed approximation of it.
pub fn render(request: &HttpRequest) -> Vec<u8> {
    hexora_http::serialize_request(request)
}

/// Parses edited bytes back into a request aimed at `service`.
///
/// `service` supplies host, port and scheme, because those are a property of the
/// connection rather than of the text: a tester editing `Host:` to something else is
/// usually testing routing, and must not thereby redirect the TCP connection. An
/// absolute-form request line overrides it, since there the text *is* stating a
/// destination.
pub fn parse(bytes: &[u8], service: HttpService, limits: &Limits) -> Result<ParsedRequest> {
    let head_len = find_head_end(bytes).ok_or_else(|| {
        HexoraError::Protocol(ProtocolError::Malformed {
            protocol: "HTTP/1.1",
            // Named precisely, because this is the mistake every editor makes: the
            // blank line separating head from body is easy to delete by accident.
            reason: "the request has no blank line ending the header block".to_string(),
        })
    })?;

    let head = parse_request_head(&bytes[..head_len], limits)?;
    let body = bytes[head_len..].to_vec();

    // An absolute-form target names its own destination; anything else inherits the
    // one the caller supplied.
    let (service, path) = match &head.target {
        RequestTarget::Absolute {
            secure,
            host,
            port,
            path,
        } => (HttpService::new(host, *port, *secure), path.clone()),
        RequestTarget::Origin { path } => (service, path.clone()),
        RequestTarget::Authority { host, port } => (service, format!("{host}:{port}")),
        RequestTarget::Asterisk => (service, "*".to_string()),
    };

    let request = HttpRequest {
        service,
        method: head.method.clone(),
        path,
        version: head.version,
        headers: head.headers.clone(),
        body: bytes::Bytes::from(body),
    };

    Ok(ParsedRequest {
        request,
        quirks: head.quirks,
    })
}

/// A request parsed from edited text, plus what was odd about it.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// The request, exactly as written.
    pub request: HttpRequest,
    /// Deviations the parser noticed. Not errors — several are the point.
    pub quirks: Vec<Quirk>,
}

/// Something worth telling the tester about a request they wrote.
///
/// Deliberately not an error. Every one of these can be intentional, and a tool that
/// refused them would be useless for the work they exist to support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// `Content-Length` does not match the number of body bytes present.
    ContentLengthMismatch {
        /// What the header claims.
        declared: u64,
        /// What is actually there.
        actual: u64,
    },
    /// A body is present but nothing frames it, so a server will read zero bytes.
    UnframedBody {
        /// How many bytes will be ignored.
        bytes: u64,
    },
    /// No `Host` header. HTTP/1.1 requires one; its absence is a routing test.
    MissingHost,
    /// The `Host` header disagrees with the host being connected to.
    HostDiffersFromConnection {
        /// What the header says.
        header: String,
        /// Where the bytes are actually going.
        connection: String,
    },
    /// The parser noticed something structurally odd.
    Quirk(Quirk),
    /// The text used bare LF line endings, which will be sent as CRLF.
    LineEndingsNormalized,
    /// The draft is in raw mode: these bytes go out untouched.
    ///
    /// Not a complaint. It is here because the other warnings on this list describe
    /// things Hexora would normally correct, and in raw mode it will not correct any
    /// of them — which is the single most important thing a tester can know about the
    /// request they are about to send.
    RawMode,
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContentLengthMismatch { declared, actual } => write!(
                f,
                "Content-Length says {declared} but the body is {actual} bytes; \
                 sending it as written"
            ),
            Self::UnframedBody { bytes } => write!(
                f,
                "{bytes} bytes of body with no Content-Length or Transfer-Encoding; \
                 the server will not read them"
            ),
            Self::MissingHost => write!(f, "no Host header"),
            Self::HostDiffersFromConnection { header, connection } => write!(
                f,
                "Host is {header} but the connection goes to {connection}"
            ),
            Self::Quirk(quirk) => write!(f, "{quirk:?}"),
            Self::LineEndingsNormalized => write!(
                f,
                "the text uses bare LF line endings; it will be sent with CRLF"
            ),
            Self::RawMode => write!(
                f,
                "raw mode: sent exactly as written; nothing above is corrected"
            ),
        }
    }
}

impl Warning {
    /// Whether this warning points at a request-smuggling or routing differential.
    ///
    /// Used to sort warnings, not to suppress them: these are the ones a tester most
    /// wants to see, whether they put them there on purpose or not.
    pub fn is_smuggling_signal(&self) -> bool {
        match self {
            Self::Quirk(quirk) => quirk.is_smuggling_signal(),
            Self::ContentLengthMismatch { .. } | Self::HostDiffersFromConnection { .. } => true,
            _ => false,
        }
    }
}

/// Everything questionable about a request, without changing any of it.
pub fn inspect(request: &HttpRequest, quirks: &[Quirk]) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let actual = request.body.len() as u64;

    let declared: Option<u64> = request
        .headers
        .get("Content-Length")
        .and_then(|h| h.value_lossy().trim().parse().ok());
    let chunked = request.headers.count("Transfer-Encoding") > 0;

    match declared {
        Some(declared) if declared != actual => {
            warnings.push(Warning::ContentLengthMismatch { declared, actual });
        }
        None if actual > 0 && !chunked => {
            warnings.push(Warning::UnframedBody { bytes: actual });
        }
        _ => {}
    }

    match host_header(request) {
        None => warnings.push(Warning::MissingHost),
        Some(header) => {
            let connection = request.service.authority();
            // Compared case-insensitively, and only when a port is not implied — an
            // omitted default port is not a differential, it is just shorthand.
            if !header.eq_ignore_ascii_case(&connection)
                && !header.eq_ignore_ascii_case(&request.service.host)
            {
                warnings.push(Warning::HostDiffersFromConnection { header, connection });
            }
        }
    }

    for quirk in quirks {
        if matches!(quirk, Quirk::BareLf) {
            warnings.push(Warning::LineEndingsNormalized);
        } else {
            warnings.push(Warning::Quirk(*quirk));
        }
    }

    warnings.sort_by_key(|w| !w.is_smuggling_signal());
    warnings
}

/// The `Host` header value, trimmed, if the request carries one.
fn host_header(request: &HttpRequest) -> Option<String> {
    request
        .headers
        .get("Host")
        .map(|h| h.value_lossy().trim().to_string())
}

#[cfg(test)]
mod tests {
    use hexora_types::http::Header;

    use super::*;

    fn service() -> HttpService {
        HttpService::new("example.com", 443, true)
    }

    fn parse_str(text: &str) -> ParsedRequest {
        parse(text.as_bytes(), service(), &Limits::default()).unwrap()
    }

    #[test]
    fn a_request_survives_a_render_and_parse_round_trip() {
        let mut original = HttpRequest::get(service(), "/search?q=1");
        original.headers.append(Header::new("x-lower", "a"));
        original.headers.append(Header::new("X-Upper", "b"));

        let rendered = render(&original);
        let parsed = parse(&rendered, service(), &Limits::default()).unwrap();

        assert_eq!(
            render(&parsed.request),
            rendered,
            "the bytes must not drift"
        );
    }

    #[test]
    fn header_order_casing_and_duplicates_survive_editing() {
        // The whole reason a tester uses a repeater instead of curl.
        let parsed = parse_str(
            "GET / HTTP/1.1\r\n\
             Host: example.com\r\n\
             x-dup: first\r\n\
             X-Dup: second\r\n\
             aCcEpT: */*\r\n\r\n",
        );
        let text = String::from_utf8(render(&parsed.request)).unwrap();
        assert!(text.contains("x-dup: first"), "{text}");
        assert!(text.contains("X-Dup: second"), "{text}");
        assert!(text.contains("aCcEpT: */*"), "{text}");
        assert!(
            text.find("x-dup").unwrap() < text.find("X-Dup").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn the_body_is_taken_verbatim_including_binary() {
        let mut raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0x00, 0xff, 0x0d, 0x0a]);
        let parsed = parse(&raw, service(), &Limits::default()).unwrap();
        assert_eq!(&parsed.request.body[..], &[0x00, 0xff, 0x0d, 0x0a]);
    }

    #[test]
    fn a_wrong_content_length_is_reported_not_corrected() {
        // The single most important behaviour in this module. Burp fixes this by
        // default and thereby destroys the test case.
        let parsed =
            parse_str("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\n\r\nshort");
        let text = String::from_utf8(render(&parsed.request)).unwrap();
        assert!(text.contains("Content-Length: 999"), "{text}");

        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(
            warnings.contains(&Warning::ContentLengthMismatch {
                declared: 999,
                actual: 5,
            }),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_missing_host_is_reported_not_invented() {
        let parsed = parse_str("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n");
        assert!(!String::from_utf8(render(&parsed.request))
            .unwrap()
            .contains("Host:"));
        assert!(inspect(&parsed.request, &parsed.quirks).contains(&Warning::MissingHost));
    }

    #[test]
    fn editing_host_does_not_redirect_the_connection() {
        // A tester changing Host is testing virtual-host routing. Following it would
        // silently send the request somewhere else — possibly out of scope.
        let parsed = parse_str("GET / HTTP/1.1\r\nHost: internal.corp\r\n\r\n");
        assert_eq!(parsed.request.service.host, "example.com");

        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                Warning::HostDiffersFromConnection { header, .. } if header == "internal.corp"
            )),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_absolute_form_target_does_name_its_own_destination() {
        // Unlike Host, an absolute-form request line is a statement about where the
        // request goes, so it is honoured.
        let parsed = parse_str("GET http://other.example:8080/x HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(parsed.request.service.host, "other.example");
        assert_eq!(parsed.request.service.port, 8080);
        assert!(!parsed.request.service.secure);
    }

    #[test]
    fn a_deliberately_ambiguous_request_parses_and_is_flagged() {
        let parsed = parse_str(
            "POST / HTTP/1.1\r\n\
             Host: example.com\r\n\
             Content-Length: 6\r\n\
             Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        let text = String::from_utf8(render(&parsed.request)).unwrap();
        assert!(text.contains("Content-Length: 6"), "{text}");
        assert!(text.contains("Transfer-Encoding: chunked"), "{text}");

        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(
            warnings.iter().any(Warning::is_smuggling_signal),
            "{warnings:?}"
        );
    }

    #[test]
    fn smuggling_signals_are_listed_first() {
        let parsed = parse_str("POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\nx");
        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(warnings[0].is_smuggling_signal(), "{warnings:?}");
    }

    #[test]
    fn an_unframed_body_is_reported_because_the_server_will_ignore_it() {
        let parsed = parse_str("POST / HTTP/1.1\r\nHost: example.com\r\n\r\nkey=value");
        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(
            warnings.contains(&Warning::UnframedBody { bytes: 9 }),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_correctly_framed_request_produces_no_noise() {
        // Warnings only mean something if they are rare.
        let parsed =
            parse_str("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 9\r\n\r\nkey=value");
        assert!(
            inspect(&parsed.request, &parsed.quirks).is_empty(),
            "{:?}",
            inspect(&parsed.request, &parsed.quirks)
        );
    }

    #[test]
    fn an_omitted_default_port_in_host_is_not_a_differential() {
        let parsed = parse_str("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(inspect(&parsed.request, &parsed.quirks).is_empty());
    }

    #[test]
    fn lf_only_text_parses_and_says_it_will_be_sent_as_crlf() {
        let parsed = parse_str("GET / HTTP/1.1\nHost: example.com\n\n");
        let warnings = inspect(&parsed.request, &parsed.quirks);
        assert!(
            warnings.contains(&Warning::LineEndingsNormalized),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_missing_blank_line_says_which_line_is_missing() {
        let err = parse(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n",
            service(),
            &Limits::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("blank line"), "{err}");
    }

    #[test]
    fn an_arbitrary_method_is_accepted() {
        // Testing needs methods no enum would contain.
        let parsed = parse_str("FROBNICATE / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(parsed.request.method, "FROBNICATE");
    }
}
