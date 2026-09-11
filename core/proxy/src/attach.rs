//! Putting a programme's required headers on traffic the tester's browser generates.
//!
//! # Why the proxy needs this at all
//!
//! M14.2 puts a project's attached headers on every request *Hexora* sends — the
//! repeater, the scanner's probes, the intruder, every replay. It does nothing for the
//! requests a **browser** makes, and during a bug bounty engagement those are the
//! overwhelming majority. A programme that says
//!
//! ```text
//! Add the following headers to requests: X-HackerOne-Research: [H1 username]
//! ```
//!
//! is not talking about your scanner. It is talking about your traffic. A day of
//! manual hunting through a proxy that did not do this would breach the terms on every
//! request while the tester believed they were covered.
//!
//! # Rewriting a browser's traffic is not a small thing
//!
//! So it is bounded three ways, and each bound is the point rather than a nicety.
//!
//! **In scope only.** A tester's browser goes everywhere: their own mail, their bank,
//! an unrelated search. Attaching `X-HackerOne-Research: <username>` to all of it would
//! broadcast a real person's researcher identity to every site they visit, from a tool
//! they turned on for one engagement. So the header goes only to hosts the project has
//! declared, and **an empty scope means nowhere** — the same reading `Scope` gives
//! everywhere else, and the safe one.
//!
//! **Opt in, per project.** A proxy that quietly edits traffic is a proxy whose
//! captures cannot be trusted, so this is off unless somebody turned it on, and the
//! proxy says what it will do before the first request.
//!
//! **Recorded as sent.** The capture observer sees the request after this runs, so what
//! the project stores is what actually went out. A history that showed the original
//! would be a record of a request nobody made.
//!
//! # What it does not touch
//!
//! Responses, bodies, and any header the request already carries under a *different*
//! name. It sets the named headers and nothing else, which keeps the difference between
//! what the browser sent and what the server saw to exactly the list a tester can print.

use std::sync::Arc;

use async_trait::async_trait;
use hexora_types::http::{Header, HttpRequest, HttpResponse};
use hexora_types::scope::Scope;

use crate::hook::{Interceptor, RequestVerdict, ResponseVerdict};

/// Adds a project's required headers to in-scope proxied requests.
///
/// Wraps another interceptor rather than replacing it, so interception and attachment
/// compose: the inner interceptor is consulted on the request as it will actually be
/// sent, header included, because a tester pausing a request to read it should be
/// reading what goes out.
pub struct Attaching {
    headers: Vec<Header>,
    scope: Arc<Scope>,
    inner: Arc<dyn Interceptor>,
}

impl Attaching {
    /// Attaches `headers` to requests inside `scope`, then defers to `inner`.
    pub fn new(headers: Vec<Header>, scope: Arc<Scope>, inner: Arc<dyn Interceptor>) -> Self {
        Self {
            headers,
            scope,
            inner,
        }
    }

    /// The headers this will add.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Whether this request is one the project declared.
    ///
    /// The whole guard. A host nobody declared is somebody else's, and a researcher's
    /// name does not belong in its logs.
    fn applies_to(&self, request: &HttpRequest) -> bool {
        !self.headers.is_empty() && self.scope.contains(&request.service, &request.path)
    }

    /// A copy of the request carrying the headers.
    fn attached(&self, request: &HttpRequest) -> HttpRequest {
        let mut copy = request.clone();
        for header in &self.headers {
            copy.headers
                .set(&header.name, header.value_lossy().into_owned());
        }
        copy
    }
}

#[async_trait]
impl Interceptor for Attaching {
    async fn on_request(&self, request: &HttpRequest) -> RequestVerdict {
        if !self.applies_to(request) {
            return self.inner.on_request(request).await;
        }

        let attached = self.attached(request);
        match self.inner.on_request(&attached).await {
            // The inner interceptor was happy with the request it saw, which is the
            // attached one — so that is what must be sent.
            RequestVerdict::Forward => RequestVerdict::Replace(Box::new(attached)),
            // A tester edited it. Re-apply, because an edit is not a decision to drop
            // the programme's header, and forgetting it here is the failure this whole
            // module exists to prevent.
            RequestVerdict::Replace(edited) => {
                RequestVerdict::Replace(Box::new(self.attached(&edited)))
            }
            other => other,
        }
    }

    async fn on_response(&self, request: &HttpRequest, response: &HttpResponse) -> ResponseVerdict {
        self.inner.on_response(request, response).await
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::http::HttpService;
    use hexora_types::scope::ScopeRule;

    use super::*;
    use crate::hook::PassThrough;

    fn attaching(scope: Scope) -> Attaching {
        Attaching::new(
            vec![Header::new("X-HackerOne-Research", "wahid_ratul")],
            Arc::new(scope),
            Arc::new(PassThrough),
        )
    }

    fn request(host: &str, path: &str) -> HttpRequest {
        HttpRequest::get(HttpService::new(host, 443, true), path)
    }

    fn sent(verdict: RequestVerdict) -> HttpRequest {
        match verdict {
            RequestVerdict::Replace(request) => *request,
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_in_scope_request_carries_the_header() {
        let attaching = attaching(Scope::new().include(ScopeRule::host("wolt.com")));
        let out = sent(attaching.on_request(&request("wolt.com", "/en")).await);

        assert_eq!(
            out.headers
                .get("x-hackerone-research")
                .map(|h| h.value_lossy().into_owned()),
            Some("wahid_ratul".to_string())
        );
    }

    #[tokio::test]
    async fn a_host_nobody_declared_is_left_alone() {
        // The guard that matters. A tester's browser goes to their own mail and their
        // own bank, and a researcher's name does not belong in either's logs.
        let attaching = attaching(Scope::new().include(ScopeRule::host("wolt.com")));

        let verdict = attaching.on_request(&request("mail.google.com", "/")).await;
        assert!(
            matches!(verdict, RequestVerdict::Forward),
            "an out-of-scope request must not even be rewritten: {verdict:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_scope_attaches_to_nothing() {
        // Same reading `Scope` gives everywhere else: no rules matches nothing, not
        // everything. A freshly created project must not broadcast anybody's identity.
        let attaching = attaching(Scope::new());
        let verdict = attaching.on_request(&request("wolt.com", "/en")).await;
        assert!(matches!(verdict, RequestVerdict::Forward), "{verdict:?}");
    }

    #[tokio::test]
    async fn a_subdomain_covered_by_the_scope_is_covered_here_too() {
        let attaching = attaching(Scope::new().include(ScopeRule::host("*.wolt.com")));
        let out = sent(
            attaching
                .on_request(&request("restaurant-api.wolt.com", "/v1"))
                .await,
        );
        assert!(out.headers.get("x-hackerone-research").is_some());
    }

    #[tokio::test]
    async fn an_edit_by_the_inner_interceptor_still_ends_up_with_the_header() {
        // An interceptor that rewrites a request has not decided to stop identifying
        // the traffic, and losing the header on the edited path would be invisible.
        struct Rewrites;

        #[async_trait]
        impl Interceptor for Rewrites {
            async fn on_request(&self, request: &HttpRequest) -> RequestVerdict {
                let mut edited = request.clone();
                edited.path = "/edited".into();
                edited.headers.remove("x-hackerone-research");
                RequestVerdict::Replace(Box::new(edited))
            }

            async fn on_response(&self, _: &HttpRequest, _: &HttpResponse) -> ResponseVerdict {
                ResponseVerdict::Forward
            }
        }

        let attaching = Attaching::new(
            vec![Header::new("X-HackerOne-Research", "wahid_ratul")],
            Arc::new(Scope::new().include(ScopeRule::host("wolt.com"))),
            Arc::new(Rewrites),
        );

        let out = sent(attaching.on_request(&request("wolt.com", "/en")).await);
        assert_eq!(out.path, "/edited", "the edit survives");
        assert!(
            out.headers.get("x-hackerone-research").is_some(),
            "and so does the header"
        );
    }

    #[tokio::test]
    async fn a_drop_is_still_a_drop() {
        struct Drops;

        #[async_trait]
        impl Interceptor for Drops {
            async fn on_request(&self, _: &HttpRequest) -> RequestVerdict {
                RequestVerdict::Drop
            }

            async fn on_response(&self, _: &HttpRequest, _: &HttpResponse) -> ResponseVerdict {
                ResponseVerdict::Forward
            }
        }

        let attaching = Attaching::new(
            vec![Header::new("X-HackerOne-Research", "r")],
            Arc::new(Scope::new().include(ScopeRule::host("wolt.com"))),
            Arc::new(Drops),
        );

        let verdict = attaching.on_request(&request("wolt.com", "/")).await;
        assert!(matches!(verdict, RequestVerdict::Drop), "{verdict:?}");
    }

    #[tokio::test]
    async fn a_header_the_browser_already_sent_is_replaced_rather_than_duplicated() {
        // Two `X-HackerOne-Research` headers is not twice as identifiable, it is a
        // malformed request somebody has to explain.
        let attaching = attaching(Scope::new().include(ScopeRule::host("wolt.com")));
        let mut incoming = request("wolt.com", "/");
        incoming
            .headers
            .append(Header::new("X-HackerOne-Research", "somebody-else"));

        let out = sent(attaching.on_request(&incoming).await);
        assert_eq!(out.headers.count("x-hackerone-research"), 1);
        assert_eq!(
            out.headers
                .get("x-hackerone-research")
                .map(|h| h.value_lossy().into_owned()),
            Some("wahid_ratul".to_string())
        );
    }
}
