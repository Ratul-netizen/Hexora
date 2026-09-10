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
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The request as it was sent.
    pub request: HttpRequest,
    /// The response as it arrived.
    pub response: HttpResponse,
    /// Wall-clock time from first byte written to last byte read.
    pub duration: Duration,
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
        Self { origin, limits: Limits::default(), follow_redirects: false }
    }

    /// Options for an automated, high-volume subsystem.
    pub fn automated(origin: Origin) -> Self {
        Self { origin, limits: Limits::automated(), follow_redirects: false }
    }
}

/// Sends HTTP requests.
///
/// Implementations must honour [`SendOptions::limits`] at the network boundary rather
/// than after the fact: a 40 GB response has to be refused while it is arriving.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Sends one request and returns the exchange.
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange>;
}

/// A transport that records requests instead of sending them.
///
/// Not a stand-in for the real engine and not wired into any production path — it
/// exists so that the layers built on top of the transport boundary (scope
/// enforcement, permission gating, workflow sequencing) are testable before M1 lands.
#[derive(Debug)]
pub struct RecordingTransport {
    sent: std::sync::Mutex<Vec<(HttpRequest, Origin)>>,
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
        Self { sent: std::sync::Mutex::new(Vec::new()), status: 200 }
    }

    /// A transport that answers with a fixed status.
    pub fn with_status(status: u16) -> Self {
        Self { sent: std::sync::Mutex::new(Vec::new()), status }
    }

    /// Every request that reached the transport, in order.
    pub fn sent(&self) -> Vec<(HttpRequest, Origin)> {
        self.sent.lock().expect("recording mutex poisoned").clone()
    }

    /// How many requests reached the transport.
    pub fn count(&self) -> usize {
        self.sent.lock().expect("recording mutex poisoned").len()
    }

    /// The URLs that reached the transport.
    pub fn urls(&self) -> Vec<String> {
        self.sent().iter().map(|(request, _)| request.url()).collect()
    }
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange> {
        self.sent.lock().expect("recording mutex poisoned").push((request.clone(), options.origin));
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
            duration: Duration::from_millis(0),
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
        for origin in [Origin::Scanner, Origin::Fuzzer, Origin::Workflow, Origin::Ai, Origin::Authz]
        {
            assert!(origin.is_automated(), "{origin:?} generates traffic without a human decision");
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
        transport.send(request, SendOptions::interactive(Origin::Repeater)).await.unwrap();
        assert_eq!(transport.count(), 1);
        assert_eq!(transport.urls(), ["https://example.com/a"]);
    }
}
