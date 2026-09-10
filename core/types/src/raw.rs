//! Requests sent as bytes, not as a message.
//!
//! [`HttpRequest`] is a *model*: fields, a header list, a body. Serializing it
//! produces a well-formed request — which is the right answer almost everywhere and
//! the wrong one here. A tester who writes a request line ending in a bare LF, or two
//! `Content-Length` headers that disagree, or a header name with a space before the
//! colon, means exactly that. A tool that quietly repaired it would be testing
//! something nobody asked about and reporting the result as though it were the answer.
//!
//! So there are two ways to send, and they are named:
//!
//! ```text
//! RequestSource::Structured(HttpRequest)   serialize the model, add framing if absent
//! RequestSource::Raw(RawRequest)           write these bytes, unchanged
//! ```
//!
//! Nothing switches between them implicitly. Converting a structured request to raw
//! is an explicit act with a visible result — the bytes appear, and from then on they
//! are what gets sent.
//!
//! # Raw is not a way around scope
//!
//! [`RawRequest`] carries the [`HttpService`] it is addressed to and can always be
//! asked for its request target, because the scope guard needs both and a request
//! whose destination cannot be established is refused rather than sent. Reading the
//! request line to answer that question does not rewrite it: inspection and
//! normalization are different things, and only the second is forbidden here.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::HexoraError;
use crate::http::{HttpRequest, HttpService};

/// The largest raw request Hexora will send.
///
/// Raw mode exists to let a tester write unusual HTTP, not to make Hexora a generator
/// of arbitrarily large writes. The bound is generous enough for any hand-written
/// request and any captured one worth editing.
pub const MAX_RAW_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// How a request reaches the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestMode {
    /// Serialized from [`HttpRequest`]. Framing headers may be added if absent, and
    /// line endings are normalized to CRLF, because that is what serializing a model
    /// means.
    Structured,
    /// Written byte for byte. Nothing is added, removed, reordered or re-cased.
    Raw,
}

impl RequestMode {
    /// The word stored in the database and shown in the interface.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Structured => "structured",
            Self::Raw => "raw",
        }
    }

    /// Parses the stored form, defaulting to structured for rows written before raw
    /// mode existed.
    pub fn parse(value: &str) -> Self {
        match value {
            "raw" => Self::Raw,
            _ => Self::Structured,
        }
    }
}

/// A request the tester wrote as bytes.
///
/// Not a `String`: a raw request may contain any byte, including invalid UTF-8 and
/// NUL, and a type that could not hold those would quietly rule out the tests raw
/// mode exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    /// Where the bytes are sent. Never derived from the bytes themselves at send
    /// time — the connection target is a separate decision from what is written on
    /// it, which is exactly the distinction an absolute-form request line blurs.
    pub service: HttpService,
    /// The bytes, exactly as supplied.
    pub bytes: Bytes,
}

impl RawRequest {
    /// Wraps bytes for sending, refusing anything whose destination cannot be
    /// established.
    ///
    /// The checks are deliberately few, and none of them is about well-formedness:
    /// raw mode is for malformed requests. What must hold is that Hexora can answer
    /// "where is this going?" — because the scope guard asks, and a request that
    /// cannot answer must not be sent.
    pub fn new(service: HttpService, bytes: impl Into<Bytes>) -> crate::Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(HexoraError::invalid_input(
                "raw",
                "a raw request cannot be empty",
            ));
        }
        if bytes.len() > MAX_RAW_REQUEST_BYTES {
            return Err(HexoraError::invalid_input(
                "raw",
                format!(
                    "a raw request may be at most {MAX_RAW_REQUEST_BYTES} bytes; this \
                     one is {}",
                    bytes.len()
                ),
            ));
        }

        let raw = Self { service, bytes };
        // Asked once, here, so every later caller can rely on the answer existing.
        raw.request_line().ok_or_else(|| {
            HexoraError::invalid_input(
                "raw",
                "the first line is not a readable request line, so there is no way to \
                 tell what this request asks for. Scope is checked against the target, \
                 and a request nobody can scope is refused rather than sent",
            )
        })?;
        Ok(raw)
    }

    /// The request line, split into method, target and version.
    ///
    /// Read-only, and tolerant: the line is split on ASCII spaces and nothing is
    /// validated beyond there being a method and a target. A version that reads
    /// `HTTP/9.9`, a method of `GET\t`, a target with a space in it percent-decoded
    /// by hand — all of that is somebody's test, and none of it is this function's
    /// business.
    pub fn request_line(&self) -> Option<RequestLine> {
        let end = self
            .bytes
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(self.bytes.len());
        let line = &self.bytes[..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        let mut parts = line.splitn(3, |b| *b == b' ');
        let method = parts.next()?;
        let target = parts.next()?;
        if method.is_empty() || target.is_empty() {
            return None;
        }
        Some(RequestLine {
            method: String::from_utf8_lossy(method).into_owned(),
            target: String::from_utf8_lossy(target).into_owned(),
            version: parts
                .next()
                .map(|v| String::from_utf8_lossy(v).into_owned()),
        })
    }

    /// The method, for the history table.
    pub fn method(&self) -> String {
        self.request_line()
            .map(|line| line.method)
            .unwrap_or_default()
    }

    /// The path the scope guard is checked against.
    ///
    /// An absolute-form target (`GET http://host/p HTTP/1.1`) is reduced to its path,
    /// because that is what a scope rule matches. The *authority* in such a target is
    /// deliberately not used to choose the connection: the destination is
    /// [`Self::service`], set by whoever built the request, so a target rewritten to
    /// point somewhere else cannot redirect the socket.
    pub fn scope_path(&self) -> String {
        let target = self
            .request_line()
            .map(|line| line.target)
            .unwrap_or_else(|| "/".to_string());
        path_of_target(&target)
    }

    /// The URL this request is understood to address, for logs and the history table.
    pub fn url(&self) -> String {
        format!("{}{}", self.service.origin(), self.scope_path())
    }

    /// Where the head ends and the body begins, if the head is terminated at all.
    ///
    /// Both CRLFCRLF and LFLF are recognised, because a hand-written request often
    /// uses the second and refusing to find its body would make raw mode useless for
    /// exactly the messages it exists for.
    pub fn head_end(&self) -> Option<usize> {
        let bytes = &self.bytes[..];
        for i in 0..bytes.len() {
            if bytes[i..].starts_with(b"\r\n\r\n") {
                return Some(i + 4);
            }
            if bytes[i..].starts_with(b"\n\n") {
                return Some(i + 2);
            }
        }
        None
    }

    /// The head bytes, verbatim, including the request line and the terminator.
    pub fn head(&self) -> Bytes {
        match self.head_end() {
            Some(end) => self.bytes.slice(..end),
            None => self.bytes.clone(),
        }
    }

    /// The body bytes, verbatim.
    pub fn body(&self) -> Bytes {
        match self.head_end() {
            Some(end) => self.bytes.slice(end..),
            None => Bytes::new(),
        }
    }
}

/// A request line, as read rather than as validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    /// The method, verbatim.
    pub method: String,
    /// The request target, verbatim.
    pub target: String,
    /// The version token, when there was a third field.
    pub version: Option<String>,
}

/// The path part of a request target, whichever form it takes.
///
/// `*` (as in `OPTIONS *`) and an authority-form target both reduce to `/`: neither
/// names a path, and a scope rule matches paths.
fn path_of_target(target: &str) -> String {
    if target == "*" {
        return "/".to_string();
    }
    match target.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(at) => rest[at..].to_string(),
            None => "/".to_string(),
        },
        None if target.starts_with('/') => target.to_string(),
        // Authority-form, as in a CONNECT. There is no path in it.
        None => "/".to_string(),
    }
}

/// How a request reaches the socket: as a model, or as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSource {
    /// Serialized from the message model.
    Structured(HttpRequest),
    /// Written exactly as supplied.
    Raw(RawRequest),
}

impl RequestSource {
    /// Which mode this is.
    pub fn mode(&self) -> RequestMode {
        match self {
            Self::Structured(_) => RequestMode::Structured,
            Self::Raw(_) => RequestMode::Raw,
        }
    }

    /// Where the request is addressed.
    pub fn service(&self) -> &HttpService {
        match self {
            Self::Structured(request) => &request.service,
            Self::Raw(raw) => &raw.service,
        }
    }

    /// The path the scope guard checks.
    pub fn scope_path(&self) -> String {
        match self {
            Self::Structured(request) => request.path.clone(),
            Self::Raw(raw) => raw.scope_path(),
        }
    }

    /// The URL, for logs and tables.
    pub fn url(&self) -> String {
        match self {
            Self::Structured(request) => request.url(),
            Self::Raw(raw) => raw.url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> HttpService {
        HttpService::new("api.example.com", 443, true)
    }

    fn raw(bytes: &[u8]) -> crate::Result<RawRequest> {
        RawRequest::new(service(), Bytes::copy_from_slice(bytes))
    }

    #[test]
    fn a_request_line_is_read_without_being_validated() {
        let request = raw(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let line = request.request_line().unwrap();
        assert_eq!(line.method, "GET");
        assert_eq!(line.target, "/a");
        assert_eq!(line.version.as_deref(), Some("HTTP/1.1"));
    }

    #[test]
    fn a_bare_lf_request_line_is_read_too() {
        // The whole point of raw mode. A request whose line endings are LF is one a
        // tester wrote deliberately, and refusing to understand it would rule out the
        // tests raw mode exists for.
        let request = raw(b"GET /a HTTP/1.1\nHost: x\n\nbody").unwrap();
        assert_eq!(request.request_line().unwrap().target, "/a");
        assert_eq!(request.body().as_ref(), b"body");
    }

    #[test]
    fn an_unusual_version_is_not_an_error() {
        let request = raw(b"FROBNICATE /a HTTP/9.9\r\n\r\n").unwrap();
        let line = request.request_line().unwrap();
        assert_eq!(line.method, "FROBNICATE");
        assert_eq!(line.version.as_deref(), Some("HTTP/9.9"));
    }

    #[test]
    fn a_request_with_no_readable_target_is_refused() {
        // Not because it is malformed — raw mode is for malformed requests — but
        // because scope is checked against the target, and a request nobody can
        // scope must not reach a socket.
        assert!(raw(b"nonsense\r\n\r\n").is_err());
        assert!(raw(b"").is_err());
    }

    #[test]
    fn an_absolute_form_target_is_scoped_by_its_path() {
        let request = raw(b"GET http://elsewhere.example/admin HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.scope_path(), "/admin");
        // And the destination is still what the caller set, not what the line says.
        // Otherwise a rewritten request line would be a way to choose the socket.
        assert_eq!(request.service.host, "api.example.com");
        assert_eq!(request.url(), "https://api.example.com/admin");
    }

    #[test]
    fn an_asterisk_target_scopes_as_root() {
        let request = raw(b"OPTIONS * HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.scope_path(), "/");
    }

    #[test]
    fn an_authority_form_target_scopes_as_root() {
        let request = raw(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.scope_path(), "/");
    }

    #[test]
    fn the_head_and_body_split_on_either_terminator() {
        let crlf = raw(b"GET / HTTP/1.1\r\nA: b\r\n\r\npayload").unwrap();
        assert_eq!(crlf.head().as_ref(), b"GET / HTTP/1.1\r\nA: b\r\n\r\n");
        assert_eq!(crlf.body().as_ref(), b"payload");

        let lf = raw(b"GET / HTTP/1.1\nA: b\n\npayload").unwrap();
        assert_eq!(lf.head().as_ref(), b"GET / HTTP/1.1\nA: b\n\n");
        assert_eq!(lf.body().as_ref(), b"payload");
    }

    #[test]
    fn an_unterminated_head_has_no_body_rather_than_a_guessed_one() {
        let request = raw(b"GET / HTTP/1.1\r\nA: b").unwrap();
        assert!(request.head_end().is_none());
        assert!(request.body().is_empty());
        assert_eq!(request.head(), request.bytes);
    }

    #[test]
    fn non_utf8_bytes_survive() {
        let request = raw(b"GET /a HTTP/1.1\r\nX: \xff\xfe\r\n\r\n\x00\x01").unwrap();
        assert_eq!(request.body().as_ref(), b"\x00\x01");
        assert!(request.bytes.contains(&0xff));
    }

    #[test]
    fn an_oversized_raw_request_is_refused() {
        let huge = vec![b'A'; MAX_RAW_REQUEST_BYTES + 1];
        assert!(RawRequest::new(service(), huge).is_err());
    }

    #[test]
    fn the_mode_round_trips_through_its_stored_word() {
        assert_eq!(RequestMode::parse("raw"), RequestMode::Raw);
        assert_eq!(RequestMode::parse("structured"), RequestMode::Structured);
        // A row written before raw mode existed has no value at all.
        assert_eq!(RequestMode::parse(""), RequestMode::Structured);
        assert_eq!(RequestMode::Raw.as_str(), "raw");
    }

    #[test]
    fn a_source_reports_where_it_is_addressed_whichever_form_it_takes() {
        let structured = RequestSource::Structured(HttpRequest::get(service(), "/a"));
        assert_eq!(structured.mode(), RequestMode::Structured);
        assert_eq!(structured.scope_path(), "/a");

        let raw = RequestSource::Raw(raw(b"GET /b HTTP/1.1\r\n\r\n").unwrap());
        assert_eq!(raw.mode(), RequestMode::Raw);
        assert_eq!(raw.scope_path(), "/b");
        assert_eq!(raw.service().host, "api.example.com");
    }
}
