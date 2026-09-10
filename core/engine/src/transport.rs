//! The HTTP transport boundary.
//!
//! Everything that sends a request — proxy, repeater, scanner, fuzzer, workflows,
//! extensions, AI tools — goes through [`HttpTransport`]. Keeping that surface to a
//! single trait is what makes it possible to enforce scope, limits and audit logging
//! in exactly one place ([`crate::guard`]) rather than in seven callers, one of which
//! will eventually forget.
//!
//! The real implementation lands in M1. At M0 this crate defines the shape and ships
//! [`RecordingTransport`], which records what it was asked to send without opening a
//! socket, so the guard layer above it can be tested today.

use std::time::Duration;

use async_trait::async_trait;
use hexora_types::error::Result;
use hexora_types::http::{HttpRequest, HttpResponse};
use hexora_types::limits::Limits;
use hexora_types::raw::RawRequest;

/// Which subsystem originated a request.
///
/// Recorded on every exchange, because "why did my tool send that?" is a question a
/// tester must always be able to answer — for their own debugging and for the client
/// whose production system received the traffic.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    Proxy,
    Repeater,
    Scanner,
    Fuzzer,
    Workflow,
    Extension,
    Authz,
    /// Requests the AI layer asked for. Always subject to the tool-permission gate.
    Ai,
}

impl Origin {
    /// Whether requests from this origin are generated without a human deciding on
    /// each one.
    ///
    /// Automated origins are the ones scope enforcement exists for: a human typing a
    /// URL into the repeater has made a decision, a fuzzer emitting 50 000 requests
    /// has not.
    pub fn is_automated(&self) -> bool {
        !matches!(self, Self::Proxy | Self::Repeater)
    }

    /// The value stored in the `requests.origin` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Repeater => "repeater",
            Self::Scanner => "scanner",
            Self::Fuzzer => "fuzzer",
            Self::Workflow => "workflow",
            Self::Extension => "extension",
            Self::Authz => "authz",
            Self::Ai => "extension",
        }
    }
}

/// One completed exchange.
///
/// The response body appears twice, on purpose. [`HttpResponse::body`] is the
/// application's bytes — what a reader wants — and [`Self::encoded_body`] is what was
/// actually on the wire inside the framing. For a `Content-Encoding: gzip` response
/// those differ, and a security tool that kept only the second one could not show the
/// tester what the server sent, while one that kept only the first could not show what
/// it meant.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The request as it was sent.
    pub request: HttpRequest,
    /// The response as it arrived, with transfer *and* content coding reversed.
    pub response: HttpResponse,
    /// The response body after transfer framing was removed but before
    /// `Content-Encoding` was reversed.
    ///
    /// `None` when no coding was reversed: the decoded body is then the wire form
    /// already, and a second copy of every ordinary response would be pure cost.
    pub encoded_body: Option<bytes::Bytes>,
    /// The coding that was reversed, when one was.
    ///
    /// What actually happened, not what the header announced. A body that hit a limit
    /// is never decoded, and recording the header there would describe a
    /// transformation nobody performed.
    pub content_encoding: Option<String>,
    /// The exact bytes written to the socket, when the request was sent raw.
    ///
    /// `None` for a structured send, where [`Self::request`] is the whole truth and
    /// serializing it again reproduces what went out. For a raw send it is the only
    /// faithful record: the point of raw mode is that the bytes are *not* what
    /// serializing the model would produce.
    pub raw_request: Option<bytes::Bytes>,
    /// Wall-clock time from first byte written to last byte read.
    pub duration: Duration,
    /// What the TLS handshake produced, for `https` exchanges.
    ///
    /// Part of the exchange record rather than a side channel: how the peer was
    /// authenticated is a property of what happened, and a finding derived from an
    /// unverified connection has to be able to disclose that.
    pub tls: Option<hexora_types::tls::TlsInfo>,
}

/// Per-request options.
#[derive(Debug, Clone)]
pub struct SendOptions {
    /// Which subsystem is sending.
    pub origin: Origin,
    /// Resource bounds for this exchange.
    pub limits: Limits,
    /// Whether to follow redirects automatically.
    ///
    /// Off by default: a security tester usually wants to see the 302 itself, and
    /// silently following it can take traffic to a host that was never in scope.
    pub follow_redirects: bool,
}

impl SendOptions {
    /// Options for an interactive, human-initiated request.
    pub fn interactive(origin: Origin) -> Self {
        Self {
            origin,
            limits: Limits::default(),
            follow_redirects: false,
        }
    }

    /// Options for an automated, high-volume subsystem.
    pub fn automated(origin: Origin) -> Self {
        Self {
            origin,
            limits: Limits::automated(),
            follow_redirects: false,
        }
    }
}

/// Sends HTTP requests.
///
/// Implementations must honour [`SendOptions::limits`] at the network boundary rather
/// than after the fact: a 40 GB response has to be refused while it is arriving.
///
/// # Two ways in, one boundary
///
/// [`Self::send`] serializes a message model. [`Self::send_raw`] writes bytes the
/// tester supplied, unchanged. Both are on this trait rather than one of them going
/// around it, because everything the guard layer enforces — scope above all — is
/// enforced by wrapping *this trait*. A raw send path that sat beside it would be a
/// second door into the network with nobody standing at it.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Sends one request and returns the exchange.
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange>;

    /// Writes a request exactly as supplied.
    ///
    /// Nothing is added, removed, reordered or re-cased — not a `Host` header, not a
    /// `Content-Length`, not a line ending. If the bytes are not a valid request, they
    /// are sent anyway and whatever the server does with them is the result.
    ///
    /// The default refuses. A transport that cannot write raw bytes says so, rather
    /// than falling back to serializing a model and returning an answer about a
    /// request the tester did not write.
    async fn send_raw(&self, request: RawRequest, options: SendOptions) -> Result<Exchange> {
        let _ = (request, options);
        Err(hexora_types::error::HexoraError::NotImplemented(
            "raw request sending on this transport",
        ))
    }
}

/// A transport that records requests instead of sending them.
///
/// Not a stand-in for the real engine and not wired into any production path — it
/// exists so that the layers built on top of the transport boundary (scope
/// enforcement, permission gating, workflow sequencing) are testable before M1 lands.
#[derive(Debug)]
pub struct RecordingTransport {
    sent: std::sync::Mutex<Vec<(HttpRequest, Origin)>>,
    raw_sent: std::sync::Mutex<Vec<(RawRequest, Origin)>>,
    status: u16,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingTransport {
    /// A transport that answers every request with `200 OK` and an empty body.
    pub fn new() -> Self {
        Self {
            sent: std::sync::Mutex::new(Vec::new()),
            raw_sent: std::sync::Mutex::new(Vec::new()),
            status: 200,
        }
    }

    /// A transport that answers with a fixed status.
    pub fn with_status(status: u16) -> Self {
        Self {
            sent: std::sync::Mutex::new(Vec::new()),
            raw_sent: std::sync::Mutex::new(Vec::new()),
            status,
        }
    }

    /// Every request that reached the transport, in order.
    pub fn sent(&self) -> Vec<(HttpRequest, Origin)> {
        self.sent.lock().expect("recording mutex poisoned").clone()
    }

    /// How many requests reached the transport.
    pub fn count(&self) -> usize {
        self.sent.lock().expect("recording mutex poisoned").len()
    }

    /// Every raw request that reached the transport, in order.
    ///
    /// Kept apart from [`Self::sent`] on purpose: a test that asserts "these bytes
    /// were written" must not be satisfied by a structured send that happened to
    /// serialize to something similar.
    pub fn raw_sent(&self) -> Vec<(RawRequest, Origin)> {
        self.raw_sent
            .lock()
            .expect("recording mutex poisoned")
            .clone()
    }

    /// How many raw requests reached the transport.
    pub fn raw_count(&self) -> usize {
        self.raw_sent
            .lock()
            .expect("recording mutex poisoned")
            .len()
    }

    /// The URLs that reached the transport.
    pub fn urls(&self) -> Vec<String> {
        self.sent()
            .iter()
            .map(|(request, _)| request.url())
            .collect()
    }
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn send_raw(&self, request: RawRequest, options: SendOptions) -> Result<Exchange> {
        self.raw_sent
            .lock()
            .expect("recording mutex poisoned")
            .push((request.clone(), options.origin));

        let bytes = request.bytes.clone();
        let mut structured = HttpRequest::get(request.service.clone(), request.scope_path());
        structured.method = request.method();
        structured.body = request.body();

        Ok(Exchange {
            request: structured,
            response: HttpResponse {
                status: self.status,
                reason: None,
                version: hexora_types::http::HttpVersion::Http11,
                headers: hexora_types::http::Headers::new(),
                body: Default::default(),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            raw_request: Some(bytes),
            duration: Duration::from_millis(0),
            tls: None,
        })
    }

    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange> {
        self.sent
            .lock()
            .expect("recording mutex poisoned")
            .push((request.clone(), options.origin));
        Ok(Exchange {
            request,
            response: HttpResponse {
                status: self.status,
                reason: None,
                version: hexora_types::http::HttpVersion::Http11,
                headers: hexora_types::http::Headers::new(),
                body: Default::default(),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            raw_request: None,
            duration: Duration::from_millis(0),
            tls: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::http::HttpService;

    use super::*;

    #[test]
    fn human_driven_origins_are_not_automated() {
        assert!(!Origin::Proxy.is_automated());
        assert!(!Origin::Repeater.is_automated());
    }

    #[test]
    fn machine_driven_origins_are_automated() {
        for origin in [
            Origin::Scanner,
            Origin::Fuzzer,
            Origin::Workflow,
            Origin::Ai,
            Origin::Authz,
        ] {
            assert!(
                origin.is_automated(),
                "{origin:?} generates traffic without a human decision"
            );
        }
    }

    #[test]
    fn redirects_are_not_followed_by_default() {
        assert!(!SendOptions::interactive(Origin::Repeater).follow_redirects);
        assert!(!SendOptions::automated(Origin::Scanner).follow_redirects);
    }

    #[tokio::test]
    async fn the_recording_transport_captures_what_it_was_asked_to_send() {
        let transport = RecordingTransport::new();
        let request = HttpRequest::get(HttpService::new("example.com", 443, true), "/a");
        transport
            .send(request, SendOptions::interactive(Origin::Repeater))
            .await
            .unwrap();
        assert_eq!(transport.count(), 1);
        assert_eq!(transport.urls(), ["https://example.com/a"]);
    }
}
