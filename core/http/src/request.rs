//! HTTP/1.x request head parsing.
//!
//! The response parser exists so Hexora can see what a target sent. This one exists
//! for the opposite reason: it reads requests *arriving at the proxy*, which is the
//! message a front-end and a back-end can disagree about — and that disagreement is
//! what request smuggling is.
//!
//! A proxy also sees request forms an origin server never does. An absolute-form
//! target carries its own authority, which may disagree with the `Host` header, and
//! which of the two wins is implementation-defined. Collapsing them into one string,
//! as an ordinary server-side parser does, would throw away the very thing worth
//! noticing.
//!
//! Same rule as everywhere else in this crate: accept what a lenient implementation
//! would, and record each deviation as a [`Quirk`].

use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{Headers, HttpService, HttpVersion};
use hexora_types::limits::Limits;

use crate::parse::{parse_header_line, split_lines, BodyFraming, Quirk};

/// What a request line pointed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTarget {
    /// `/path?query` — what an origin server normally receives.
    Origin {
        /// The path, verbatim.
        path: String,
    },
    /// `http://host/path` — what a proxy normally receives.
    Absolute {
        /// Whether the scheme was `https`.
        secure: bool,
        /// Host from the target's own authority.
        host: String,
        /// Port, defaulted from the scheme when absent.
        port: u16,
        /// The path, verbatim.
        path: String,
    },
    /// `host:port` — the form used by `CONNECT`.
    Authority {
        /// The host to tunnel to.
        host: String,
        /// The port to tunnel to.
        port: u16,
    },
    /// `*` — used by `OPTIONS`.
    Asterisk,
}

impl RequestTarget {
    /// The authority named by the target itself, if it carries one.
    pub fn authority(&self) -> Option<String> {
        match self {
            Self::Absolute {
                host, port, secure, ..
            } => Some(if *port == default_port(*secure) {
                host.clone()
            } else {
                format!("{host}:{port}")
            }),
            Self::Authority { host, port } => Some(format!("{host}:{port}")),
            Self::Origin { .. } | Self::Asterisk => None,
        }
    }

    /// The path to forward, in origin form.
    pub fn path(&self) -> &str {
        match self {
            Self::Origin { path } | Self::Absolute { path, .. } => path,
            Self::Authority { .. } => "",
            Self::Asterisk => "*",
        }
    }

    /// The service this target names, for an absolute-form or authority-form target.
    pub fn service(&self) -> Option<HttpService> {
        match self {
            Self::Absolute {
                secure, host, port, ..
            } => Some(HttpService::new(host, *port, *secure)),
            Self::Authority { host, port } => Some(HttpService::new(host, *port, true)),
            _ => None,
        }
    }
}

fn default_port(secure: bool) -> u16 {
    if secure {
        443
    } else {
        80
    }
}

/// A parsed request head.
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// The method, verbatim. Not an enum: testing needs arbitrary methods.
    pub method: String,
    /// What the request line pointed at.
    pub target: RequestTarget,
    /// The protocol version.
    pub version: HttpVersion,
    /// Header fields in wire order, casing and duplicates preserved.
    pub headers: Headers,
    /// How long the request body is.
    pub framing: BodyFraming,
    /// Deviations from strict parsing.
    pub quirks: Vec<Quirk>,
}

impl RequestHead {
    /// Whether anything here suggests a smuggling or routing differential.
    pub fn has_smuggling_signal(&self) -> bool {
        self.quirks.iter().any(Quirk::is_smuggling_signal)
    }

    /// Whether this is a `CONNECT` request.
    pub fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }

    /// The `Host` header value, if present.
    pub fn host_header(&self) -> Option<String> {
        self.headers
            .get("Host")
            .map(|h| h.value_lossy().trim().to_string())
    }

    /// Where this request should be forwarded.
    ///
    /// Prefers the target's own authority, falling back to `Host`. When the two
    /// disagree a [`Quirk::HostMismatchWithTarget`] has already been recorded — this
    /// picks one so the request can be forwarded, it does not resolve the ambiguity.
    pub fn destination(&self, assume_secure: bool) -> Result<HttpService> {
        if let Some(service) = self.target.service() {
            return Ok(service);
        }
        let host = self.host_header().ok_or_else(|| {
            HexoraError::Protocol(ProtocolError::Malformed {
                protocol: "HTTP/1.1",
                reason: "request has neither an absolute target nor a Host header".to_string(),
            })
        })?;
        let (host, port) = split_authority(&host, default_port(assume_secure))?;
        Ok(HttpService::new(host, port, assume_secure))
    }
}

/// Parses a complete request head.
pub fn parse_request_head(buf: &[u8], limits: &Limits) -> Result<RequestHead> {
    limits.check_header_size(buf.len())?;

    let mut quirks = Vec::new();
    let split = split_lines(buf);
    if split.bare_lf {
        quirks.push(Quirk::BareLf);
    }
    let mut lines = split.lines.into_iter();

    let request_line = lines
        .next()
        .ok_or_else(|| malformed("request contained no request line"))?;
    let (method, target, version) = parse_request_line(request_line)?;

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

    check_host(&target, &headers, version, &mut quirks);
    let framing = request_framing(&headers, &mut quirks)?;

    Ok(RequestHead {
        method,
        target,
        version,
        headers,
        framing,
        quirks,
    })
}

fn parse_request_line(line: &[u8]) -> Result<(String, RequestTarget, HttpVersion)> {
    let text = String::from_utf8_lossy(line);
    let mut parts = text.split(' ').filter(|p| !p.is_empty());

    let method = parts
        .next()
        .ok_or_else(|| malformed("empty request line"))?
        .to_string();
    let target_text = parts
        .next()
        .ok_or_else(|| malformed("request line has no target"))?;

    // A missing version means HTTP/0.9, which nothing speaks any more; treating it as
    // 1.0 is what lenient servers do.
    let version = match parts.next().unwrap_or("HTTP/1.0").trim() {
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/1.0" | "HTTP/0.9" => HttpVersion::Http10,
        other => {
            return Err(HexoraError::Protocol(ProtocolError::Malformed {
                protocol: "HTTP/1.1",
                reason: format!("unsupported request version {other:?}"),
            }))
        }
    };

    Ok((method, parse_request_target(target_text)?, version))
}

/// Parses a request target in any of the four RFC 9112 forms.
pub fn parse_request_target(text: &str) -> Result<RequestTarget> {
    if text == "*" {
        return Ok(RequestTarget::Asterisk);
    }
    if text.starts_with('/') {
        return Ok(RequestTarget::Origin {
            path: text.to_string(),
        });
    }

    if let Some((scheme, rest)) = text.split_once("://") {
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            other => {
                return Err(HexoraError::Protocol(ProtocolError::Malformed {
                    protocol: "HTTP/1.1",
                    reason: format!("unsupported scheme {other:?} in request target"),
                }))
            }
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = split_authority(authority, default_port(secure))?;
        return Ok(RequestTarget::Absolute {
            secure,
            host,
            port,
            path,
        });
    }

    // Authority form: what CONNECT uses.
    let (host, port) = split_authority(text, 443)?;
    Ok(RequestTarget::Authority { host, port })
}

fn split_authority(authority: &str, default: u16) -> Result<(String, u16)> {
    if authority.is_empty() {
        return Err(malformed("request target has an empty authority"));
    }
    // Take the last colon so a bracketed IPv6 literal survives.
    match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => {
            let port = authority[i + 1..].parse::<u16>().map_err(|_| {
                malformed(&format!(
                    "invalid port {:?} in request target",
                    &authority[i + 1..]
                ))
            })?;
            Ok((authority[..i].to_string(), port))
        }
        _ => Ok((authority.to_string(), default)),
    }
}

/// Records the routing differentials a proxy is uniquely placed to notice.
fn check_host(
    target: &RequestTarget,
    headers: &Headers,
    version: HttpVersion,
    quirks: &mut Vec<Quirk>,
) {
    let count = headers.count("Host");
    if count > 1 {
        quirks.push(Quirk::MultipleHostHeaders);
    }
    if count == 0 && version == HttpVersion::Http11 {
        quirks.push(Quirk::MissingHostHeader);
    }

    if let (Some(from_target), Some(header)) = (target.authority(), headers.get("Host")) {
        let header = header.value_lossy().trim().to_ascii_lowercase();
        if !header.is_empty() && header != from_target.to_ascii_lowercase() {
            quirks.push(Quirk::HostMismatchWithTarget);
        }
    }
}

/// Applies RFC 9112 §6.3 to a request body.
fn request_framing(headers: &Headers, quirks: &mut Vec<Quirk>) -> Result<BodyFraming> {
    let cl = headers.count("Content-Length");
    let te = headers.count("Transfer-Encoding");

    if cl > 0 && te > 0 {
        // On the request side this is the CL.TE primitive itself, not merely a hint.
        quirks.push(Quirk::ContentLengthAndTransferEncoding);
    }

    if te > 0 {
        let chunked = headers
            .get_all("Transfer-Encoding")
            .any(|h| h.value_lossy().to_ascii_lowercase().contains("chunked"));
        if chunked {
            return Ok(BodyFraming::Chunked);
        }
        quirks.push(Quirk::UnknownTransferEncoding);
        // Unlike a response, a request has no "until the connection closes" option —
        // the client is still waiting for an answer. With no readable length the only
        // safe reading is that there is no body.
        return Ok(BodyFraming::None);
    }

    if cl > 0 {
        let mut values: Vec<String> = headers
            .get_all("Content-Length")
            .map(|h| h.value_lossy().trim().to_string())
            .collect();
        values.dedup();
        if values.len() > 1 {
            return Err(HexoraError::Protocol(ProtocolError::AmbiguousFraming(
                format!("conflicting Content-Length values: {}", values.join(", ")),
            )));
        }
        if cl > 1 {
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

    Ok(BodyFraming::None)
}

fn malformed(reason: &str) -> HexoraError {
    HexoraError::Protocol(ProtocolError::Malformed {
        protocol: "HTTP/1.1",
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Result<RequestHead> {
        parse_request_head(raw, &Limits::default())
    }

    fn parse_ok(raw: &[u8]) -> RequestHead {
        parse(raw).expect("expected a parseable request")
    }

    // ------------------------------------------------------------------ forms

    #[test]
    fn parses_an_origin_form_request() {
        let head = parse_ok(b"GET /a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(head.method, "GET");
        assert_eq!(
            head.target,
            RequestTarget::Origin {
                path: "/a?b=c".into()
            }
        );
        assert_eq!(head.version, HttpVersion::Http11);
        assert!(head.quirks.is_empty(), "{:?}", head.quirks);
    }

    #[test]
    fn parses_an_absolute_form_request_as_a_proxy_receives_it() {
        let head = parse_ok(b"GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(
            head.target,
            RequestTarget::Absolute {
                secure: false,
                host: "example.com".into(),
                port: 80,
                path: "/a".into()
            }
        );
        assert_eq!(head.destination(false).unwrap().host, "example.com");
    }

    #[test]
    fn parses_an_authority_form_connect() {
        let head = parse_ok(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        assert!(head.is_connect());
        assert_eq!(
            head.target,
            RequestTarget::Authority {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parses_asterisk_form() {
        let head = parse_ok(b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(head.target, RequestTarget::Asterisk);
        assert_eq!(head.target.path(), "*");
    }

    #[test]
    fn an_explicit_port_is_kept_and_a_default_is_inferred() {
        let head =
            parse_ok(b"GET http://example.com:8080/ HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
        assert_eq!(head.destination(false).unwrap().port, 8080);

        let head = parse_ok(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let service = head.destination(false).unwrap();
        assert_eq!(service.port, 443);
        assert!(service.secure);
    }

    #[test]
    fn a_request_without_an_absolute_target_falls_back_to_host() {
        let head = parse_ok(b"GET /a HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
        let service = head.destination(false).unwrap();
        assert_eq!(service.host, "example.com");
        assert_eq!(service.port, 8080);
    }

    #[test]
    fn the_path_is_not_normalized() {
        // The odd spellings are the interesting ones; they must survive verbatim.
        for path in ["/a/../b", "/%2e%2e/b", "//double", "/a%20b"] {
            let raw = format!("GET {path} HTTP/1.1\r\nHost: h\r\n\r\n");
            assert_eq!(parse_ok(raw.as_bytes()).target.path(), path);
        }
    }

    // ---------------------------------------------------- routing differentials

    #[test]
    fn two_host_headers_are_flagged_as_a_routing_differential() {
        let head =
            parse_ok(b"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::MultipleHostHeaders));
        assert!(
            head.has_smuggling_signal(),
            "two hops picking different Host headers is how a request reaches an \
             unauthorised back-end"
        );
    }

    #[test]
    fn a_host_disagreeing_with_the_target_is_flagged() {
        let head =
            parse_ok(b"GET http://real.example.com/ HTTP/1.1\r\nHost: fake.example.com\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::HostMismatchWithTarget));
        assert!(head.has_smuggling_signal());
    }

    #[test]
    fn a_matching_host_and_target_are_not_flagged() {
        let head = parse_ok(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(
            !head.quirks.contains(&Quirk::HostMismatchWithTarget),
            "{:?}",
            head.quirks
        );
    }

    #[test]
    fn a_missing_host_on_http_1_1_is_flagged() {
        let head = parse_ok(b"GET / HTTP/1.1\r\n\r\n");
        assert!(head.quirks.contains(&Quirk::MissingHostHeader));
    }

    #[test]
    fn a_missing_host_on_http_1_0_is_fine() {
        let head = parse_ok(b"GET / HTTP/1.0\r\n\r\n");
        assert!(!head.quirks.contains(&Quirk::MissingHostHeader));
    }

    // ---------------------------------------------------------------- framing

    #[test]
    fn a_content_length_body_is_framed() {
        let head = parse_ok(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::ContentLength(9));
    }

    #[test]
    fn a_chunked_request_body_is_framed() {
        let head = parse_ok(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(head.framing, BodyFraming::Chunked);
    }

    #[test]
    fn cl_te_on_a_request_is_the_smuggling_primitive_itself() {
        let head = parse_ok(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(head.framing, BodyFraming::Chunked);
        assert!(head
            .quirks
            .contains(&Quirk::ContentLengthAndTransferEncoding));
        assert!(head.has_smuggling_signal());
    }

    #[test]
    fn conflicting_content_lengths_are_refused() {
        let err =
            parse(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
                .unwrap_err();
        assert_eq!(err.code(), "protocol");
    }

    #[test]
    fn a_request_with_no_framing_headers_has_no_body() {
        assert_eq!(
            parse_ok(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").framing,
            BodyFraming::None
        );
    }

    // ---------------------------------------------------------------- hostile

    #[test]
    fn bare_lf_request_framing_is_accepted_and_flagged() {
        let head = parse_ok(b"GET / HTTP/1.1\nHost: h\n\n");
        assert_eq!(head.method, "GET");
        assert!(head.quirks.contains(&Quirk::BareLf));
    }

    #[test]
    fn header_order_casing_and_duplicates_survive() {
        let head = parse_ok(b"GET / HTTP/1.1\r\nHost: h\r\nX-One: 1\r\nx-one: 2\r\n\r\n");
        assert_eq!(head.headers.count("X-One"), 2);
        let names: Vec<&str> = head.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Host", "X-One", "x-one"]);
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        assert!(parse(b"GET / HTTP/9.9\r\nHost: h\r\n\r\n").is_err());
    }

    #[test]
    fn an_unsupported_scheme_is_refused() {
        assert!(parse(b"GET ftp://example.com/ HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    }

    #[test]
    fn an_invalid_port_is_refused() {
        assert!(parse(b"GET http://example.com:99999/ HTTP/1.1\r\nHost: h\r\n\r\n").is_err());
    }

    #[test]
    fn parsing_never_panics_on_arbitrary_bytes() {
        let inputs: [&[u8]; 10] = [
            b"",
            b"\r\n",
            b"GET",
            b"GET \r\n",
            b"GET / \r\n",
            b" / HTTP/1.1\r\n\r\n",
            b"GET http:// HTTP/1.1\r\n\r\n",
            b"CONNECT : HTTP/1.1\r\n\r\n",
            b"\xff\xfe\x00\x01",
            b"GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ];
        for input in inputs {
            let _ = parse(input);
        }
    }
}
