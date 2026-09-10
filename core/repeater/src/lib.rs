//! # hexora-repeater
//!
//! Take a request out of history, change it, send it again, and see what moved.
//!
//! ```text
//! history ──→ Draft ──→ edit the raw bytes ──→ send ──→ Sent
//!               ▲                                        │
//!               └──────────── branch ────────────────────┘
//! ```
//!
//! ## Branching, not tabs
//!
//! Every other tool in this category models the repeater as a set of tabs: a tab holds
//! the current text of a request, and editing it overwrites what was there. That loses
//! the thing a tester actually needs at report time — *which* edit produced the change.
//!
//! Here a send is immutable and keeps a link to the request it derived from
//! ([`Sent::parent`]). A tab is then just a walk over that tree, and weeks later
//! "what did I change to get the 403?" is a query rather than a memory. The schema has
//! carried `requests.parent_id` since M0 for exactly this.
//!
//! ## Nothing is corrected
//!
//! The repeater sends what was written — wrong `Content-Length` included. See [`raw`]
//! for why, and for the one place where the bytes are not byte-exact.
//!
//! ## Scope
//!
//! The repeater is human-driven, so [`hexora_engine::guard::ScopeGuard`] flags
//! out-of-scope requests rather than refusing them: a tester who types a URL has made
//! a decision. Automated subsystems get the opposite treatment.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod diff;
pub mod raw;

use std::sync::Arc;

use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_engine::transport::{HttpTransport, Origin, SendOptions};
use hexora_storage::{CapturedExchange, TrafficStore};
use hexora_types::error::Result;
use hexora_types::http::HttpRequest;
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;

pub use crate::diff::{HeaderChange, ResponseDiff};
pub use crate::raw::{inspect, parse, render, ParsedRequest, Warning};

/// A request being edited, and where it came from.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The request as it currently stands.
    pub request: HttpRequest,
    /// The stored request this was derived from, if any.
    pub parent: Option<RequestId>,
    /// What the parser noticed when the draft was last parsed from text.
    pub quirks: Vec<hexora_http::Quirk>,
}

impl Draft {
    /// Starts a draft from a request built in code.
    pub fn new(request: HttpRequest) -> Self {
        Self {
            request,
            parent: None,
            quirks: Vec::new(),
        }
    }

    /// The draft as editable bytes.
    pub fn to_raw(&self) -> Vec<u8> {
        render(&self.request)
    }

    /// Replaces the draft's content with edited bytes.
    ///
    /// The connection target is carried over rather than re-derived from `Host`, so
    /// editing `Host` tests virtual-host routing instead of silently sending the
    /// request somewhere else. An absolute-form request line still wins; see [`raw`].
    pub fn apply_raw(&mut self, bytes: &[u8], limits: &Limits) -> Result<()> {
        let parsed = parse(bytes, self.request.service.clone(), limits)?;
        self.request = parsed.request;
        self.quirks = parsed.quirks;
        Ok(())
    }

    /// Everything questionable about the draft, without changing any of it.
    pub fn warnings(&self) -> Vec<Warning> {
        inspect(&self.request, &self.quirks)
    }
}

/// A completed repeater send.
#[derive(Debug, Clone)]
pub struct Sent {
    /// The id the send was stored under.
    pub id: RequestId,
    /// The request this one derived from.
    pub parent: Option<RequestId>,
    /// What came back.
    pub exchange: hexora_engine::transport::Exchange,
    /// What the scope guard decided. Out-of-scope is flagged, never refused.
    pub decision: ScopeDecision,
}

/// Sends drafts and records them.
///
/// Holds the transport and the store together because a repeater send that is not
/// recorded is not evidence: an engagement's report is written from the project, and a
/// result that exists only in a UI panel cannot be cited.
pub struct Repeater<T: HttpTransport> {
    transport: ScopeGuard<T>,
    store: Arc<TrafficStore>,
    limits: Limits,
}

impl<T: HttpTransport> std::fmt::Debug for Repeater<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Repeater").finish_non_exhaustive()
    }
}

impl<T: HttpTransport> Repeater<T> {
    /// Builds a repeater over a scope-guarded transport and a project's traffic store.
    pub fn new(transport: ScopeGuard<T>, store: Arc<TrafficStore>) -> Self {
        Self {
            transport,
            store,
            limits: Limits::default(),
        }
    }

    /// Uses different resource limits for sends.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The limits sends are made under.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Loads a stored request as a draft, ready to edit and resend.
    ///
    /// The draft's parent is the request it was loaded from, so a resend records what
    /// it descended from even when nothing was edited.
    pub fn draft_from(&self, id: RequestId) -> Result<Draft> {
        let stored = self.store.request(id)?;

        // Re-parsed from the stored header block rather than reconstructed field by
        // field: the round trip through bytes is what proves nothing was lost on the
        // way in, and it is the same path an edited draft takes.
        let mut raw = Vec::with_capacity(stored.headers_raw.len() + stored.body.len() + 64);
        raw.extend_from_slice(stored.method.as_bytes());
        raw.push(b' ');
        raw.extend_from_slice(stored.path.as_bytes());
        raw.push(b' ');
        raw.extend_from_slice(stored.http_version.as_bytes());
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&stored.headers_raw);
        if !stored.headers_raw.ends_with(b"\r\n") {
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&stored.body);

        let parsed = parse(&raw, stored.service, &self.limits)?;
        Ok(Draft {
            request: parsed.request,
            parent: Some(id),
            quirks: parsed.quirks,
        })
    }

    /// Decides what scope would do with a draft, without sending it.
    ///
    /// Exposed so a UI can offer "this is out of scope — add it?" before the request
    /// leaves, rather than after.
    pub fn decide(&self, draft: &Draft) -> ScopeDecision {
        self.transport
            .decide(&draft.request, &SendOptions::interactive(Origin::Repeater))
    }

    /// Sends a draft and records the exchange against the project.
    pub async fn send(&self, draft: &Draft) -> Result<Sent> {
        let mut options = SendOptions::interactive(Origin::Repeater);
        options.limits = self.limits.clone();

        let decision = self.transport.decide(&draft.request, &options);
        let exchange = self.transport.send(draft.request.clone(), options).await?;

        let content_encoding = exchange
            .response
            .headers
            .get("Content-Encoding")
            .map(|h| h.value_lossy().into_owned());

        let captured = CapturedExchange {
            request: exchange.request.clone(),
            response: exchange.response.clone(),
            encoded_body: None,
            content_encoding,
            origin: "repeater",
            parent: draft.parent,
            quirks: draft.quirks.iter().map(|q| format!("{q:?}")).collect(),
            tls: exchange.tls.clone(),
            duration_ms: exchange.duration.as_millis().min(u128::from(u32::MAX)) as u32,
        };

        // Recorded before returning, and a failure propagates. Unlike the proxy — where
        // a storage failure must not break a browsing session — a repeater send the
        // tester is watching should say plainly that it was not saved.
        let id = self.store.record(&captured)?;

        Ok(Sent {
            id,
            parent: draft.parent,
            exchange,
            decision,
        })
    }

    /// Compares a send against the request it derived from.
    ///
    /// Returns `None` when the send has no parent, or the parent has no stored
    /// response to compare against.
    pub fn diff_against_parent(&self, sent: &Sent) -> Result<Option<ResponseDiff>> {
        let Some(parent) = sent.parent else {
            return Ok(None);
        };
        Ok(Some(self.diff(parent, sent.id)?))
    }

    /// Compares two stored exchanges.
    pub fn diff(&self, before: RequestId, after: RequestId) -> Result<ResponseDiff> {
        let a = self.stored_response(before)?;
        let b = self.stored_response(after)?;
        Ok(ResponseDiff::compare(&a.0, &b.0, (a.1, b.1)))
    }

    /// Rebuilds a stored response, with its round-trip time.
    fn stored_response(&self, id: RequestId) -> Result<(hexora_types::http::HttpResponse, u128)> {
        let (status, reason, version, headers_raw) = self.store.response_head(id)?;
        let body = self.store.response_body(id, false)?;

        // Re-parsed through the response parser so the comparison sees exactly the
        // header list that was stored, duplicates and casing included.
        let mut raw = Vec::with_capacity(headers_raw.len() + 64);
        raw.extend_from_slice(version.as_bytes());
        raw.push(b' ');
        raw.extend_from_slice(status.to_string().as_bytes());
        if let Some(reason) = &reason {
            raw.push(b' ');
            raw.extend_from_slice(reason.as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&headers_raw);
        if !headers_raw.ends_with(b"\r\n") {
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");

        // The method matters to the parser only for HEAD/204 framing, and the body
        // is supplied separately here, so GET is the honest placeholder.
        let head = hexora_http::parse::parse_response_head(&raw, "GET", &self.limits)?;
        let duration = self
            .store
            .history(None, hexora_storage::repository::Limit::new(1000))?
            .items
            .iter()
            .find(|item| item.id == id)
            .and_then(|item| item.duration_ms)
            .unwrap_or(0) as u128;

        Ok((
            hexora_types::http::HttpResponse {
                status: head.status,
                reason: head.reason,
                version: head.version,
                headers: head.headers,
                body: bytes::Bytes::from(body),
                truncated: false,
            },
            duration,
        ))
    }

    /// Every send derived from a request, oldest first.
    pub fn branches(&self, parent: RequestId) -> Result<Vec<RequestId>> {
        Ok(self.store.children(parent)?)
    }
}

#[cfg(test)]
mod tests {
    use hexora_engine::transport::{Exchange, RecordingTransport};
    use hexora_storage::{MemoryBlobStore, Project};
    use hexora_types::http::{Header, Headers, HttpResponse, HttpService, HttpVersion};
    use hexora_types::scope::{Scope, ScopeRule};

    use super::*;

    fn service() -> HttpService {
        HttpService::new("example.com", 443, true)
    }

    /// A repeater over a transport that answers without a socket.
    fn repeater(scope: Scope) -> (Repeater<RecordingTransport>, Arc<TrafficStore>, Project) {
        let project = Project::in_memory().unwrap();
        let store = Arc::new(TrafficStore::new(
            project.metadata().clone(),
            Arc::new(MemoryBlobStore::new()),
        ));
        let transport = ScopeGuard::new(RecordingTransport::default(), Arc::new(scope));
        (Repeater::new(transport, store.clone()), store, project)
    }

    fn in_scope() -> Scope {
        Scope::new().include(ScopeRule::host("example.com"))
    }

    fn capture(path: &str, status: u16, body: &[u8]) -> CapturedExchange {
        let mut request = HttpRequest::get(service(), path);
        request.headers.append(Header::new("x-Original", "kept"));
        CapturedExchange {
            request,
            response: HttpResponse {
                status,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: bytes::Bytes::copy_from_slice(body),
                truncated: false,
            },
            encoded_body: None,
            content_encoding: None,
            origin: "proxy",
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 30,
        }
    }

    #[tokio::test]
    async fn a_captured_request_can_be_loaded_edited_and_resent() {
        let (repeater, store, _project) = repeater(in_scope());
        let original = store.record(&capture("/item/1", 200, b"ok")).unwrap();

        let mut draft = repeater.draft_from(original).unwrap();
        let raw = String::from_utf8(draft.to_raw()).unwrap();
        assert!(raw.starts_with("GET /item/1 HTTP/1.1\r\n"), "{raw:?}");
        // The original header survived storage and reload with its casing.
        assert!(raw.contains("x-Original: kept"), "{raw:?}");

        draft
            .apply_raw(
                raw.replace("/item/1", "/item/2").as_bytes(),
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(draft.request.path, "/item/2");

        let sent = repeater.send(&draft).await.unwrap();
        assert_eq!(sent.parent, Some(original));
        assert_eq!(store.count().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_resend_records_what_it_derived_from() {
        // Branching is the point: weeks later, "which edit caused this?" is a query.
        let (repeater, store, _project) = repeater(in_scope());
        let original = store.record(&capture("/", 200, b"a")).unwrap();

        let draft = repeater.draft_from(original).unwrap();
        let first = repeater.send(&draft).await.unwrap();
        let second = repeater.send(&draft).await.unwrap();

        assert_eq!(
            repeater.branches(original).unwrap(),
            vec![first.id, second.id]
        );
    }

    #[tokio::test]
    async fn a_send_is_recorded_as_coming_from_the_repeater() {
        let (repeater, store, _project) = repeater(in_scope());
        let original = store.record(&capture("/", 200, b"a")).unwrap();
        let sent = repeater
            .send(&repeater.draft_from(original).unwrap())
            .await
            .unwrap();

        assert_eq!(store.request(sent.id).unwrap().origin, "repeater");
    }

    #[tokio::test]
    async fn an_out_of_scope_resend_is_flagged_but_still_sent() {
        // A tester who chose to send it has made a decision. Refusing would be worse
        // than useless; silently sending it without a flag would be dishonest.
        let (repeater, store, _project) = repeater(Scope::new());
        let original = store.record(&capture("/", 200, b"a")).unwrap();

        let draft = repeater.draft_from(original).unwrap();
        assert_eq!(repeater.decide(&draft), ScopeDecision::AllowedOutOfScope);

        let sent = repeater.send(&draft).await.unwrap();
        assert_eq!(sent.decision, ScopeDecision::AllowedOutOfScope);
        assert_eq!(store.count().unwrap(), 2, "and it was still recorded");
    }

    #[tokio::test]
    async fn an_edited_request_is_scope_checked_after_the_edit_not_before() {
        // Editing an absolute-form target moves the request to another host. The
        // decision has to follow the edit, or scope means nothing.
        let (repeater, store, _project) = repeater(in_scope());
        let original = store.record(&capture("/", 200, b"a")).unwrap();

        let mut draft = repeater.draft_from(original).unwrap();
        assert_eq!(repeater.decide(&draft), ScopeDecision::Allowed);

        draft
            .apply_raw(
                b"GET http://elsewhere.test/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(repeater.decide(&draft), ScopeDecision::AllowedOutOfScope);
    }

    #[tokio::test]
    async fn a_wrong_content_length_survives_being_loaded_and_resent() {
        // The end-to-end version of the promise raw.rs makes.
        let (repeater, store, _project) = repeater(in_scope());
        let mut captured = capture("/", 200, b"a");
        captured.request.method = "POST".into();
        captured.request.body = bytes::Bytes::from_static(b"short");
        captured.request.headers.set("Content-Length", "999");
        let original = store.record(&captured).unwrap();

        let draft = repeater.draft_from(original).unwrap();
        let raw = String::from_utf8(draft.to_raw()).unwrap();
        assert!(raw.contains("Content-Length: 999"), "{raw:?}");
        assert!(
            draft.warnings().contains(&Warning::ContentLengthMismatch {
                declared: 999,
                actual: 5,
            }),
            "{:?}",
            draft.warnings()
        );
    }

    #[tokio::test]
    async fn a_draft_from_an_unknown_request_is_an_error() {
        let (repeater, _store, _project) = repeater(in_scope());
        assert!(repeater.draft_from(RequestId::new()).is_err());
    }

    #[tokio::test]
    async fn a_send_with_no_parent_has_nothing_to_diff_against() {
        let (repeater, _store, _project) = repeater(in_scope());
        let draft = Draft::new(HttpRequest::get(service(), "/"));
        let sent = repeater.send(&draft).await.unwrap();
        assert_eq!(sent.parent, None);
        assert!(repeater.diff_against_parent(&sent).unwrap().is_none());
    }

    #[tokio::test]
    async fn two_stored_exchanges_can_be_compared() {
        let (repeater, store, _project) = repeater(in_scope());
        let before = store.record(&capture("/", 200, b"allowed")).unwrap();
        let after = store.record(&capture("/", 403, b"denied")).unwrap();

        let diff = repeater.diff(before, after).unwrap();
        assert_eq!(diff.status, Some((200, 403)));
        assert!(diff.is_interesting());
    }

    #[tokio::test]
    async fn a_resend_that_changed_nothing_diffs_to_identical() {
        let (repeater, store, _project) = repeater(in_scope());
        let original = store.record(&capture("/", 200, b"same")).unwrap();

        let draft = repeater.draft_from(original).unwrap();
        let sent = repeater.send(&draft).await.unwrap();
        let diff = repeater.diff_against_parent(&sent).unwrap().unwrap();

        // The recording transport answers identically, so the only difference is
        // timing — which is exactly what a stable resend should show.
        assert!(diff.status.is_none(), "{diff:?}");
    }

    #[tokio::test]
    async fn the_transport_receives_exactly_what_was_drafted() {
        let (repeater, store, _project) = repeater(in_scope());
        let mut captured = capture("/", 200, b"a");
        captured.request.headers.append(Header::new("z-last", "1"));
        captured.request.headers.append(Header::new("A-First", "2"));
        let original = store.record(&captured).unwrap();

        let draft = repeater.draft_from(original).unwrap();
        let sent = repeater.send(&draft).await.unwrap();

        let wire = String::from_utf8(render(&sent.exchange.request)).unwrap();
        assert!(
            wire.find("z-last").unwrap() < wire.find("A-First").unwrap(),
            "order must survive the whole path: {wire:?}"
        );
    }

    #[test]
    fn a_draft_built_in_code_has_no_parent() {
        let draft = Draft::new(HttpRequest::get(service(), "/"));
        assert!(draft.parent.is_none());
        assert!(draft.warnings().is_empty());
    }

    #[allow(dead_code)]
    fn assert_exchange_is_used(_: Exchange) {}
}
