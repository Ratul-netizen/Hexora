//! # hexora-scan
//!
//! Observations over traffic that has already been captured.
//!
//! ## It cannot send, and that is structural
//!
//! [`passive::scan`] takes a [`Project`](hexora_storage::Project) and nothing else.
//! There is no `HttpTransport` in its signature, no [`Lab`](hexora_verify::Lab), and
//! no way to obtain either from what it is given — so "the passive scanner makes no
//! network requests" is not a rule somebody has to keep, it is a fact about the
//! function's arguments. The same shape as the identifier analyzer, for the same
//! reason.
//!
//! That is what makes it safe to run at any point in an engagement, including on a
//! project belonging to a client who has gone home, and what makes it worth running
//! before anything active: it costs the target nothing.
//!
//! ## Three products, and only one of them is a finding
//!
//! ```text
//! Observation (informational)   "Server: nginx/1.24.0"          listed, never filed
//! Observation (reportable)      "no HSTS on an HTTPS response"  → a lead
//! Hypothesis                    "the origin may be reflected"   → waits for a verifier
//! ```
//!
//! A passive check states facts. A fact needs no experiment, so it goes through
//! [`Verification::Observed`](hexora_types::verify::Verification::Observed), whose
//! ceiling is [`Confidence::Reported`](hexora_types::Confidence::Reported) — a lead,
//! not a vulnerability. **A passive check cannot produce anything stronger, by
//! construction**: it does not choose its own verification, the scanner applies the
//! same one to every observation, and the ladder in `core/types` does the rest.
//!
//! When a check is suspicious rather than certain it raises a
//! [`Hypothesis`](hexora_types::finding::Hypothesis), and that is where the hypothesis
//! stops. Nothing here verifies one, because verifying one would mean sending
//! something. `Access-Control-Allow-Origin` echoing one request's `Origin` is
//! consistent with a reflecting server and equally consistent with a server that
//! allows exactly that one origin; the difference is a second request with a different
//! `Origin`, and that belongs to the active scheduler.
//!
//! ## What a check never sees
//!
//! Credentials — in **both** directions. Request headers that carry one arrive with
//! the value replaced, and `Set-Cookie` response headers arrive with the cookie's
//! value replaced and its attributes intact:
//!
//! ```text
//! sent:      Cookie: sessionid=abc123        seen: Cookie: [redacted]
//! received:  Set-Cookie: sessionid=abc123;   seen: Set-Cookie: sessionid=[redacted];
//!                        Path=/; HttpOnly                       Path=/; HttpOnly
//! ```
//!
//! The response direction matters as much as the request one and is easier to forget:
//! a `Set-Cookie` on authenticated traffic *is* the session the server just issued.
//! Redacting when an exchange is assembled rather than at each use is deliberate — a
//! check cannot leak what it was never given, and neither can anything that later
//! holds on to an exchange for its own reasons.
//!
//! ## What a check does not load
//!
//! Response bodies. None of the checks in this milestone needs one, and reading every
//! body of a large engagement to satisfy a shape nobody uses would be the exact
//! premature cost worth avoiding — a project can hold hundreds of gigabytes of them.
//! [`Exchange::response_bytes`] carries the size, which is what the checks that care
//! about "did this response have content" actually ask. It is also the safer default:
//! a body-reading check is the one most likely to quote somebody's data into a report.
//! A check that genuinely needs bodies arrives with a body accessor, and pays for it
//! then.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod checks;
pub mod passive;

use hexora_types::finding::Hypothesis;
use hexora_types::http::{Header, Headers};
use hexora_types::ids::{RequestId, TargetId};
use hexora_types::tls::TlsInfo;
use hexora_types::verify::{DetectorInfo, Observation, Writeup};

pub use passive::{scan, Grouped, Selection, Summary};

/// One captured exchange, as a passive check sees it.
///
/// Assembled once per exchange and shared by every check, so a project's traffic is
/// parsed once rather than once per detector.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The request's id — the handle a report uses to open the evidence.
    pub id: RequestId,
    /// The target it was sent to.
    pub target: TargetId,
    /// The host, for grouping observations that are really about one server.
    pub host: String,
    /// The port.
    pub port: u16,
    /// Whether the connection was TLS.
    pub secure: bool,
    /// The method, verbatim.
    pub method: String,
    /// The absolute URL.
    pub url: String,
    /// The request target as sent, including any query string.
    pub path: String,
    /// The response status, or 0 when no response was stored.
    pub status: u16,
    /// Request headers, with credential values replaced.
    ///
    /// See [`redacted_request_headers`].
    pub request_headers: Headers,
    /// Response headers, with `Set-Cookie` values replaced.
    ///
    /// See [`redacted_response_headers`].
    pub response_headers: Headers,
    /// How many bytes the decoded response body was.
    ///
    /// The body itself is not loaded; see the module documentation.
    pub response_bytes: u64,
    /// Whether the request carried something that authenticates it.
    ///
    /// Derived from the *presence* of a credential header before the value was
    /// stripped, which is the only moment it can be known — afterwards there is
    /// deliberately nothing left to look at.
    pub authenticated: bool,
    /// TLS details, when the exchange had any.
    pub tls: Option<TlsInfo>,
    /// When it was sent, RFC 3339.
    pub sent_at: String,
}

impl Exchange {
    /// Whether the request carried something that authenticates it.
    ///
    /// Asked by the checks that only make sense about authenticated traffic — a
    /// cacheable public page is not a finding.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Whether the response carried any content.
    pub fn has_body(&self) -> bool {
        self.response_bytes > 0
    }

    /// Whether this looks like a response a browser would render.
    ///
    /// Used to decide whether framing and content-type headers are applicable: a JSON
    /// API response is not framed and is not sniffed into a document.
    pub fn is_document(&self) -> bool {
        self.response_headers
            .get("content-type")
            .map(|header| {
                let value = text(header).to_ascii_lowercase();
                value.starts_with("text/html") || value.starts_with("application/xhtml")
            })
            .unwrap_or(false)
    }
}

/// Every request header whose value authenticates the request.
///
/// Replaced before any check sees one. Applied by replacement rather than by masking
/// at each use, so a check has nothing to accidentally print.
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
];

/// Strips credential values from a request's headers, keeping their names.
///
/// The names matter — "this request was authenticated" is exactly what several checks
/// need to know — and the values never do.
pub fn redacted_request_headers(headers: &Headers) -> Headers {
    let mut out = Headers::new();
    for header in headers.iter() {
        if CREDENTIAL_HEADERS
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            out.append(Header::new(header.name.clone(), "[redacted]"));
        } else {
            out.append(header.clone());
        }
    }
    out
}

/// Replaces the value in a `Set-Cookie`, keeping the name and every attribute.
///
/// `sessionid=abc123; Path=/; Secure` becomes `sessionid=[redacted]; Path=/; Secure`.
///
/// Everything the cookie check needs survives — the name says what the cookie is for,
/// the attributes are the entire subject — and the one part that is somebody's session
/// does not.
pub fn redact_set_cookie(value: &str) -> String {
    let mut parts = value.splitn(2, ';');
    let Some(pair) = parts.next() else {
        return value.to_string();
    };
    let rest = parts.next();

    let name = match pair.split_once('=') {
        Some((name, _)) => name.trim(),
        // No `=` at all: there is no value to remove, and the whole token is the
        // name of a cookie some server thought was a good idea.
        None => return value.to_string(),
    };

    match rest {
        Some(rest) => format!("{name}=[redacted];{rest}"),
        None => format!("{name}=[redacted]"),
    }
}

/// Strips cookie values from a response's headers.
///
/// Only `Set-Cookie`, and only its value: everything else a server sends is about the
/// server rather than about a session.
pub fn redacted_response_headers(headers: &Headers) -> Headers {
    let mut out = Headers::new();
    for header in headers.iter() {
        if header.is("set-cookie") {
            out.append(Header::new(
                header.name.clone(),
                redact_set_cookie(&header.value_lossy()),
            ));
        } else {
            out.append(header.clone());
        }
    }
    out
}

/// A header's value as text, for reading and for matching keywords in it.
///
/// Lossy, because a hostile application sends whatever bytes it likes and a check that
/// refused to look at a non-UTF-8 header would refuse to look at the interesting one.
/// Safe for what it is used for: finding `no-store` inside a `Cache-Control`, or
/// putting a `Server` banner in front of a reader.
///
/// **Not safe for deciding two values are equal**, which is why the one check that
/// compares a response header against a request header — CORS origin reflection —
/// uses [`bytes_equal`] instead. Two different byte strings can both decode to the
/// same replacement characters, and a check that concluded "the server echoed what I
/// sent" from that would be concluding it from a decoding artefact.
pub fn text(header: &Header) -> std::borrow::Cow<'_, str> {
    header.value_lossy()
}

/// Whether two header values are the same bytes.
///
/// The comparison to use when the answer matters and the bytes are somebody else's.
pub fn bytes_equal(a: &Header, b: &Header) -> bool {
    a.value == b.value
}

/// A check that reads captured traffic and says what it sees.
///
/// Two products, deliberately separate: [`observe`](PassiveCheck::observe) states
/// facts that need no experiment, and [`suspect`](PassiveCheck::suspect) raises
/// suspicions that do — and will not get one here.
pub trait PassiveCheck: Send + Sync {
    /// What this check is, for the registry and for a retest.
    fn about(&self) -> DetectorInfo;

    /// Facts about this exchange.
    ///
    /// Every observation names the exchange it came from: one with no evidence is not
    /// evidence of anything.
    fn observe(&self, _exchange: &Exchange) -> Vec<Observation> {
        Vec::new()
    }

    /// Suspicions about this exchange, which stop here.
    ///
    /// Nothing in this crate verifies one, because verifying one would mean sending
    /// something. They are counted, listed and handed to whoever asks; they become
    /// findings only when an active verifier establishes them.
    fn suspect(&self, _exchange: &Exchange) -> Vec<Hypothesis> {
        Vec::new()
    }

    /// The prose one of this check's observations becomes, when it is reportable.
    ///
    /// Only called for reportable observations, so an informational one never needs
    /// remediation advice nobody asked for.
    fn writeup(&self, observation: &Observation, exchange: &Exchange, target: TargetId) -> Writeup;
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn a_set_cookie_keeps_its_name_and_attributes_and_loses_its_value() {
        assert_eq!(
            redact_set_cookie("sessionid=abc123; Path=/; Secure; HttpOnly"),
            "sessionid=[redacted]; Path=/; Secure; HttpOnly"
        );
        assert_eq!(redact_set_cookie("a=b"), "a=[redacted]");
    }

    #[test]
    fn a_malformed_set_cookie_is_left_alone_rather_than_mangled() {
        // Nothing that looks like a value, so nothing to remove.
        assert_eq!(redact_set_cookie("noequals"), "noequals");
        assert_eq!(redact_set_cookie(""), "");
    }

    #[test]
    fn credentials_are_stripped_in_both_directions() {
        // The response direction is the one that is easy to forget, and the one that
        // carries the session the server has just issued.
        let mut request = Headers::new();
        request.append(Header::new("Authorization", "Bearer secret-token"));
        request.append(Header::new("Cookie", "sessionid=secret-value"));
        request.append(Header::new("Accept", "application/json"));

        let seen = redacted_request_headers(&request);
        let rendered = format!("{seen:?}");
        assert!(!rendered.contains("secret-token"), "{rendered}");
        assert!(!rendered.contains("secret-value"), "{rendered}");
        assert_eq!(
            seen.get("accept").unwrap().value_lossy(),
            "application/json"
        );

        let mut response = Headers::new();
        response.append(Header::new("Set-Cookie", "sessionid=secret-value; Secure"));
        response.append(Header::new("Server", "nginx"));

        let seen = redacted_response_headers(&response);
        let rendered = format!("{seen:?}");
        assert!(!rendered.contains("secret-value"), "{rendered}");
        assert!(
            rendered.contains("sessionid"),
            "the name is the reportable part"
        );
        assert!(
            rendered.contains("Secure"),
            "attributes are the whole subject"
        );
        assert_eq!(seen.get("server").unwrap().value_lossy(), "nginx");
    }

    #[test]
    fn a_non_utf8_header_value_survives_redaction_without_panicking() {
        let mut headers = Headers::new();
        headers.append(Header {
            name: "Set-Cookie".into(),
            value: bytes::Bytes::from_static(&[b'a', b'=', 0xff, 0xfe]),
        });
        let seen = redacted_response_headers(&headers);
        assert_eq!(
            seen.get("set-cookie").unwrap().value_lossy(),
            "a=[redacted]"
        );
    }
}
