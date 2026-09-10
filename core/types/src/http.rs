//! The normalized HTTP message model.
//!
//! Security testing has an unusual requirement: the tool must be able to send and
//! record messages that are *deliberately* invalid. Request smuggling, header
//! injection and parser-differential testing all depend on Hexora preserving
//! byte-for-byte what the user wrote, including duplicate headers, unusual casing,
//! obs-fold whitespace and non-UTF-8 bytes.
//!
//! So the model here is intentionally lower-level than a typical HTTP client's:
//!
//! * Headers are an **ordered list**, not a map. Order and duplicates are preserved.
//! * Header names keep their original casing.
//! * Bodies are raw [`Bytes`], never `String`.
//! * The parsed view is derived on demand and never replaces the raw bytes.

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{HexoraError, ProtocolError, Result};

/// The HTTP version a message was sent or received on.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    /// The wire representation used in an HTTP/1.x request line.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }

    /// Whether this version frames messages as text on the wire.
    ///
    /// HTTP/2 and HTTP/3 are binary, so a raw HTTP/1-style rendering of them is a
    /// reconstruction for display, not the actual bytes sent.
    pub fn is_text_framed(&self) -> bool {
        matches!(self, Self::Http10 | Self::Http11)
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One HTTP header field, preserving original name casing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The field name exactly as it appeared on the wire.
    pub name: String,
    /// The field value. Kept as bytes because hostile targets send non-UTF-8 values.
    #[serde(with = "crate::http::serde_bytes_lossy")]
    pub value: Bytes,
}

impl Header {
    /// Builds a header from string parts.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Bytes::from(value.into()),
        }
    }

    /// The value decoded as UTF-8, lossily. For display only — never for comparison
    /// where an attacker controls the bytes.
    pub fn value_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }

    /// Whether this header's name matches `name`, case-insensitively per RFC 9110.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// An ordered, duplicate-preserving header list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Headers(Vec<Header>);

impl Headers {
    /// An empty header list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a header, keeping any existing header of the same name.
    ///
    /// This is the default because duplicate headers are a testing primitive, not a
    /// mistake. Use [`Headers::set`] when you want replace semantics.
    pub fn append(&mut self, header: Header) {
        self.0.push(header);
    }

    /// Replaces every header with this name, or appends if none exist.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let header = Header::new(name.to_string(), value);
        match self.0.iter().position(|h| h.is(name)) {
            Some(first) => {
                self.0.retain(|h| !h.is(name));
                self.0.insert(first, header);
            }
            None => self.0.push(header),
        }
    }

    /// Removes every header with this name, returning how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.0.len();
        self.0.retain(|h| !h.is(name));
        before - self.0.len()
    }

    /// The first value for `name`, if any.
    pub fn get(&self, name: &str) -> Option<&Header> {
        self.0.iter().find(|h| h.is(name))
    }

    /// Every value for `name`, in wire order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.0.iter().filter(move |h| h.is(name))
    }

    /// How many headers with this name are present.
    ///
    /// A count above one for `Content-Length` or `Transfer-Encoding` is the signature
    /// of a request-smuggling test case, so callers check this rather than assuming
    /// uniqueness.
    pub fn count(&self, name: &str) -> usize {
        self.0.iter().filter(|h| h.is(name)).count()
    }

    /// Iterates all headers in wire order.
    pub fn iter(&self) -> std::slice::Iter<'_, Header> {
        self.0.iter()
    }

    /// The number of header fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no header fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The total serialized size of the header block, for limit enforcement.
    pub fn wire_size(&self) -> usize {
        // name + ": " + value + CRLF
        self.0
            .iter()
            .map(|h| h.name.len() + 2 + h.value.len() + 2)
            .sum()
    }
}

impl FromIterator<Header> for Headers {
    fn from_iter<T: IntoIterator<Item = Header>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Where a message is going: scheme, host and port.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpService {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl HttpService {
    /// Builds a service descriptor.
    pub fn new(host: impl Into<String>, port: u16, secure: bool) -> Self {
        Self {
            host: host.into(),
            port,
            secure,
        }
    }

    /// The URL scheme.
    pub fn scheme(&self) -> &'static str {
        if self.secure {
            "https"
        } else {
            "http"
        }
    }

    /// Whether the port is the default for the scheme.
    pub fn is_default_port(&self) -> bool {
        self.port == if self.secure { 443 } else { 80 }
    }

    /// The value an `Host` header would carry, omitting a default port.
    pub fn authority(&self) -> String {
        if self.is_default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The origin URL, without a path.
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme(), self.authority())
    }
}

impl fmt::Display for HttpService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin())
    }
}

/// An HTTP request as Hexora stores and sends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Where the request is sent.
    pub service: HttpService,
    /// The method, verbatim. Not an enum: testing needs arbitrary methods.
    pub method: String,
    /// The request target (origin-form path plus query), verbatim.
    pub path: String,
    /// The protocol version.
    pub version: HttpVersion,
    /// Header fields in wire order.
    pub headers: Headers,
    /// The raw body.
    #[serde(with = "crate::http::serde_bytes_lossy")]
    pub body: Bytes,
}

impl HttpRequest {
    /// Builds a minimal `GET` request for a service and path.
    pub fn get(service: HttpService, path: impl Into<String>) -> Self {
        let mut headers = Headers::new();
        headers.set("Host", service.authority());
        Self {
            service,
            method: "GET".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: Bytes::new(),
        }
    }

    /// The absolute URL of this request, for display and scope matching.
    pub fn url(&self) -> String {
        format!("{}{}", self.service.origin(), self.path)
    }

    /// Serializes the request head in HTTP/1.x wire form.
    ///
    /// For HTTP/2 and HTTP/3 this is a readable reconstruction, not the bytes that
    /// went out; see [`HttpVersion::is_text_framed`].
    pub fn to_wire_head(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.headers.wire_size() + 64);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.extend_from_slice(b"\r\n");
        for header in self.headers.iter() {
            out.extend_from_slice(header.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&header.value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Rejects requests whose framing headers are self-contradictory.
    ///
    /// Hexora does not *prevent* sending these — smuggling tests need them — but the
    /// engine calls this so it can warn, and so automated subsystems (scanner,
    /// fuzzer) never send an ambiguous message by accident.
    pub fn check_framing(&self) -> Result<()> {
        let cl = self.headers.count("Content-Length");
        let te = self.headers.count("Transfer-Encoding");
        if cl > 1 {
            return Err(HexoraError::Protocol(ProtocolError::AmbiguousFraming(
                format!("{cl} Content-Length headers"),
            )));
        }
        if cl == 1 && te >= 1 {
            return Err(HexoraError::Protocol(ProtocolError::AmbiguousFraming(
                "both Content-Length and Transfer-Encoding present".into(),
            )));
        }
        Ok(())
    }
}

/// An HTTP response as Hexora records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// The status code, verbatim. Not validated: targets do send invalid codes.
    pub status: u16,
    /// The reason phrase, if the version carries one.
    pub reason: Option<String>,
    /// The protocol version the response arrived on.
    pub version: HttpVersion,
    /// Header fields in wire order.
    pub headers: Headers,
    /// The body, after transfer-decoding but before content-decoding.
    #[serde(with = "crate::http::serde_bytes_lossy")]
    pub body: Bytes,
    /// Whether the body was truncated by a resource limit.
    ///
    /// Findings derived from a truncated body must say so, otherwise evidence is
    /// misleading.
    pub truncated: bool,
}

impl HttpResponse {
    /// The status class, e.g. `2` for `2xx`.
    pub fn status_class(&self) -> u16 {
        self.status / 100
    }

    /// Whether the status indicates success.
    pub fn is_success(&self) -> bool {
        self.status_class() == 2
    }

    /// Whether the status indicates a redirect with a `Location` header.
    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308) && self.headers.get("Location").is_some()
    }

    /// The `Content-Type` media type, lowercased and without parameters.
    pub fn media_type(&self) -> Option<String> {
        let raw = self.headers.get("Content-Type")?;
        let value = raw.value_lossy();
        Some(value.split(';').next()?.trim().to_ascii_lowercase())
    }
}

/// Serde support for [`Bytes`] that survives non-UTF-8 payloads.
///
/// Bodies are stored base64-encoded in JSON so that binary and deliberately
/// malformed content round-trips exactly. Inside SQLite they are stored as BLOBs.
mod serde_bytes_lossy {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        bytes.as_ref().to_vec().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        Vec::<u8>::deserialize(d).map(Bytes::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> HttpService {
        HttpService::new("example.com", 443, true)
    }

    #[test]
    fn default_ports_are_omitted_from_the_authority() {
        assert_eq!(svc().authority(), "example.com");
        assert_eq!(
            HttpService::new("example.com", 8443, true).authority(),
            "example.com:8443"
        );
        assert_eq!(
            HttpService::new("example.com", 80, false).authority(),
            "example.com"
        );
        assert_eq!(
            HttpService::new("example.com", 443, false).authority(),
            "example.com:443"
        );
    }

    #[test]
    fn duplicate_headers_are_preserved_by_append() {
        let mut h = Headers::new();
        h.append(Header::new("Content-Length", "5"));
        h.append(Header::new("Content-Length", "10"));
        assert_eq!(h.count("Content-Length"), 2);
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn set_replaces_all_duplicates_and_keeps_position() {
        let mut h = Headers::new();
        h.append(Header::new("A", "1"));
        h.append(Header::new("X", "first"));
        h.append(Header::new("B", "2"));
        h.append(Header::new("X", "second"));
        h.set("X", "only");
        assert_eq!(h.count("X"), 1);
        assert_eq!(h.get("X").unwrap().value_lossy(), "only");
        let names: Vec<&str> = h.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["A", "X", "B"]);
    }

    #[test]
    fn header_lookup_is_case_insensitive_but_casing_is_kept() {
        let mut h = Headers::new();
        h.append(Header::new("CoNtEnT-tYpE", "text/html"));
        assert_eq!(h.get("content-type").unwrap().value_lossy(), "text/html");
        assert_eq!(h.iter().next().unwrap().name, "CoNtEnT-tYpE");
    }

    #[test]
    fn remove_reports_how_many_it_removed() {
        let mut h = Headers::new();
        h.append(Header::new("X", "1"));
        h.append(Header::new("x", "2"));
        assert_eq!(h.remove("X"), 2);
        assert!(h.is_empty());
    }

    #[test]
    fn wire_head_round_trips_method_path_and_headers() {
        let req = HttpRequest::get(svc(), "/a?b=c");
        let wire = String::from_utf8(req.to_wire_head()).unwrap();
        assert!(wire.starts_with("GET /a?b=c HTTP/1.1\r\n"), "{wire:?}");
        assert!(wire.contains("Host: example.com\r\n"), "{wire:?}");
        assert!(wire.ends_with("\r\n\r\n"), "{wire:?}");
    }

    #[test]
    fn framing_check_flags_duplicate_content_length() {
        let mut req = HttpRequest::get(svc(), "/");
        req.headers.append(Header::new("Content-Length", "5"));
        req.headers.append(Header::new("Content-Length", "6"));
        assert!(req.check_framing().is_err());
    }

    #[test]
    fn framing_check_flags_cl_te_conflict() {
        let mut req = HttpRequest::get(svc(), "/");
        req.headers.append(Header::new("Content-Length", "5"));
        req.headers
            .append(Header::new("Transfer-Encoding", "chunked"));
        assert!(req.check_framing().is_err());
    }

    #[test]
    fn framing_check_accepts_a_normal_request() {
        let mut req = HttpRequest::get(svc(), "/");
        req.headers.set("Content-Length", "5");
        assert!(req.check_framing().is_ok());
    }

    #[test]
    fn media_type_strips_parameters_and_lowercases() {
        let mut headers = Headers::new();
        headers.set("Content-Type", "APPLICATION/JSON; charset=utf-8");
        let res = HttpResponse {
            status: 200,
            reason: Some("OK".into()),
            version: HttpVersion::Http11,
            headers,
            body: Bytes::new(),
            truncated: false,
        };
        assert_eq!(res.media_type().as_deref(), Some("application/json"));
        assert!(res.is_success());
        assert!(!res.is_redirect());
    }

    #[test]
    fn redirect_needs_a_location_header() {
        let res = HttpResponse {
            status: 302,
            reason: None,
            version: HttpVersion::Http11,
            headers: Headers::new(),
            body: Bytes::new(),
            truncated: false,
        };
        assert!(
            !res.is_redirect(),
            "302 without Location is not a usable redirect"
        );
    }

    #[test]
    fn non_utf8_header_values_survive_storage() {
        let h = Header {
            name: "X-Raw".into(),
            value: Bytes::from_static(&[0xff, 0xfe, 0x00]),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: Header = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, h.value);
    }

    #[test]
    fn binary_bodies_round_trip_through_json() {
        let req = HttpRequest {
            body: Bytes::from_static(&[0x00, 0x80, 0xff, 0x0a]),
            ..HttpRequest::get(svc(), "/")
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: HttpRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }
}
