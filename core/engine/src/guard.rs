//! Scope enforcement at the transport boundary.
//!
//! `docs/security-invariants.md` invariant 1 says automated components must never
//! send an out-of-scope request. A `Scope` type alone does not achieve that — it only
//! makes the check *possible*. What makes it hold is that every subsystem receives
//! its transport as a [`ScopeGuard`], and the guard checks before the socket is
//! touched.
//!
//! ```text
//! Scanner ─┐
//! Fuzzer  ─┤
//! Workflow─┼─→ ScopeGuard ─→ HttpTransport ─→ network
//! AI tool ─┤        │
//! Extension┘        └─ out of scope: refused, audited, never sent
//! ```
//!
//! Human-driven origins (proxy and repeater) are **not** blocked. A tester typing a
//! URL has made a decision; silently dropping their request would be worse than
//! useless, and the proxy must be able to observe traffic to a host before that host
//! is known well enough to be added to scope. Those requests are flagged rather than
//! refused, so the UI can offer "add to scope?" instead of failing mysteriously.

use std::sync::Arc;

use async_trait::async_trait;
use hexora_types::error::{HexoraError, Result};
use hexora_types::http::HttpRequest;
use hexora_types::raw::RawRequest;
use hexora_types::scope::Scope;

use crate::transport::{Exchange, HttpTransport, SendOptions};

/// What the guard decided about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    /// In scope; send it.
    Allowed,
    /// Out of scope but human-initiated; send it and flag it in the UI.
    AllowedOutOfScope,
    /// Out of scope and automated; refuse.
    Refused,
}

impl ScopeDecision {
    /// Whether the request may be sent.
    pub fn permits_sending(&self) -> bool {
        !matches!(self, Self::Refused)
    }
}

/// Wraps a transport so that no automated subsystem can send out-of-scope traffic.
pub struct ScopeGuard<T: HttpTransport> {
    inner: T,
    scope: Arc<Scope>,
}

impl<T: HttpTransport> ScopeGuard<T> {
    /// Wraps `inner` with the given scope.
    pub fn new(inner: T, scope: Arc<Scope>) -> Self {
        Self { inner, scope }
    }

    /// The scope being enforced.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Decides what should happen to a request, without sending it.
    ///
    /// Exposed so the UI can render the decision (and offer to widen scope) before
    /// the user commits to an action.
    pub fn decide(&self, request: &HttpRequest, options: &SendOptions) -> ScopeDecision {
        self.decide_for(&request.service, &request.path, options)
    }

    /// The same decision for a request the tester wrote as bytes.
    ///
    /// Raw mode changes what is written on the connection. It does not change which
    /// connection is opened, and it does not change who may open one: the destination
    /// is the service the raw request carries, and the path comes from reading its
    /// request line — an absolute-form target contributes its *path*, never its
    /// authority, so a rewritten request line cannot point the socket somewhere the
    /// scope does not cover.
    pub fn decide_raw(&self, request: &RawRequest, options: &SendOptions) -> ScopeDecision {
        self.decide_for(&request.service, &request.scope_path(), options)
    }

    fn decide_for(
        &self,
        service: &hexora_types::http::HttpService,
        path: &str,
        options: &SendOptions,
    ) -> ScopeDecision {
        if self.scope.contains(service, path) {
            return ScopeDecision::Allowed;
        }
        if options.origin.is_automated() {
            ScopeDecision::Refused
        } else {
            ScopeDecision::AllowedOutOfScope
        }
    }
}

#[async_trait]
impl<T: HttpTransport> HttpTransport for ScopeGuard<T> {
    async fn send(&self, request: HttpRequest, options: SendOptions) -> Result<Exchange> {
        match self.decide(&request, &options) {
            ScopeDecision::Refused => {
                let target = request.url();
                // Logged at warn because a refused automated request usually means a
                // misconfigured scope, and silence would look like the scan simply
                // finding nothing.
                tracing::warn!(
                    origin = options.origin.as_str(),
                    target = %target,
                    "refusing out-of-scope request from an automated subsystem"
                );
                Err(HexoraError::OutOfScope(target))
            }
            ScopeDecision::AllowedOutOfScope => {
                tracing::debug!(
                    origin = options.origin.as_str(),
                    target = %request.url(),
                    "sending out-of-scope request from a human-driven subsystem"
                );
                self.inner.send(request, options).await
            }
            ScopeDecision::Allowed => self.inner.send(request, options).await,
        }
    }

    async fn send_raw(&self, request: RawRequest, options: SendOptions) -> Result<Exchange> {
        match self.decide_raw(&request, &options) {
            ScopeDecision::Refused => {
                let target = request.url();
                tracing::warn!(
                    origin = options.origin.as_str(),
                    target = %target,
                    "refusing an out-of-scope raw request from an automated subsystem"
                );
                Err(HexoraError::OutOfScope(target))
            }
            ScopeDecision::AllowedOutOfScope => {
                tracing::debug!(
                    origin = options.origin.as_str(),
                    target = %request.url(),
                    "sending an out-of-scope raw request from a human-driven subsystem"
                );
                self.inner.send_raw(request, options).await
            }
            ScopeDecision::Allowed => self.inner.send_raw(request, options).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::http::HttpService;
    use hexora_types::scope::ScopeRule;

    use super::*;
    use crate::transport::{Origin, RecordingTransport};

    fn request(host: &str, path: &str) -> HttpRequest {
        HttpRequest::get(HttpService::new(host, 443, true), path)
    }

    fn guard(scope: Scope) -> ScopeGuard<RecordingTransport> {
        ScopeGuard::new(RecordingTransport::new(), Arc::new(scope))
    }

    fn in_scope() -> Scope {
        Scope::new().include(ScopeRule::host("example.com"))
    }

    #[tokio::test]
    async fn in_scope_automated_requests_are_sent() {
        let guard = guard(in_scope());
        guard
            .send(
                request("example.com", "/api"),
                SendOptions::automated(Origin::Scanner),
            )
            .await
            .unwrap();
        assert_eq!(guard.inner.count(), 1);
    }

    #[tokio::test]
    async fn out_of_scope_automated_requests_never_reach_the_transport() {
        let guard = guard(in_scope());
        for origin in [
            Origin::Scanner,
            Origin::Fuzzer,
            Origin::Workflow,
            Origin::Ai,
            Origin::Authz,
        ] {
            let err = guard
                .send(
                    request("not-in-scope.example.net", "/"),
                    SendOptions::automated(origin),
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), "out_of_scope", "{origin:?}");
        }
        assert_eq!(
            guard.inner.count(),
            0,
            "not one byte may reach an out-of-scope host"
        );
    }

    #[tokio::test]
    async fn extensions_are_subject_to_scope_like_any_other_automated_caller() {
        let guard = guard(in_scope());
        let err = guard
            .send(
                request("evil.example.net", "/"),
                SendOptions::automated(Origin::Extension),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "out_of_scope");
        assert_eq!(guard.inner.count(), 0);
    }

    #[tokio::test]
    async fn human_driven_requests_are_flagged_rather_than_blocked() {
        let guard = guard(in_scope());
        for origin in [Origin::Proxy, Origin::Repeater] {
            let options = SendOptions::interactive(origin);
            let request = request("unknown.example.net", "/");
            assert_eq!(
                guard.decide(&request, &options),
                ScopeDecision::AllowedOutOfScope
            );
            guard.send(request, options).await.unwrap();
        }
        assert_eq!(
            guard.inner.count(),
            2,
            "a tester's own request is never silently dropped"
        );
    }

    #[tokio::test]
    async fn an_empty_scope_stops_all_automated_traffic() {
        let guard = guard(Scope::new());
        let err = guard
            .send(
                request("example.com", "/"),
                SendOptions::automated(Origin::Scanner),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "out_of_scope");
        assert_eq!(guard.inner.count(), 0);
    }

    #[tokio::test]
    async fn excluded_paths_are_refused_even_on_an_included_host() {
        let scope = in_scope().exclude(ScopeRule::host("example.com").with_prefix("/logout"));
        let guard = guard(scope);
        let err = guard
            .send(
                request("example.com", "/logout"),
                SendOptions::automated(Origin::Fuzzer),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "out_of_scope");
        assert_eq!(guard.inner.count(), 0);
    }

    #[tokio::test]
    async fn an_excluded_path_cannot_be_reached_by_encoding_it() {
        // A fuzzer mutating a path must not be able to walk into a carve-out.
        let scope = in_scope().exclude(ScopeRule::host("example.com").with_prefix("/admin"));
        let guard = guard(scope);
        for path in ["/admin", "/%61dmin", "/x/../admin", "//admin", "/%2fadmin"] {
            let err = guard
                .send(
                    request("example.com", path),
                    SendOptions::automated(Origin::Fuzzer),
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.code(),
                "out_of_scope",
                "path {path} slipped past the carve-out"
            );
        }
        assert_eq!(guard.inner.count(), 0);
    }

    #[test]
    fn a_refusal_does_not_permit_sending() {
        assert!(!ScopeDecision::Refused.permits_sending());
        assert!(ScopeDecision::Allowed.permits_sending());
        assert!(ScopeDecision::AllowedOutOfScope.permits_sending());
    }
}
