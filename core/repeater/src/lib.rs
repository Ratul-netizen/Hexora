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

use bytes::Bytes;
use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_engine::transport::{HttpTransport, Origin, SendOptions};
use hexora_storage::{CapturedExchange, TrafficStore};
use hexora_types::error::Result;
use hexora_types::http::{HttpRequest, HttpService};
use hexora_types::identity::Identity;
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;
use hexora_types::raw::{RawRequest, RequestMode, RequestSource};

pub use crate::diff::{HeaderChange, ResponseDiff};
pub use crate::raw::{inspect, parse, render, ParsedRequest, Warning};

/// A request being edited, and where it came from.
///
/// # Two modes, and no silent switching
///
/// A **structured** draft is a message model. Editing it and sending it serializes
/// that model, which means CRLF line endings and framing headers added where they
/// were missing — the right answer for almost every request, because almost every
/// request is meant to be well formed.
///
/// A **raw** draft is bytes. They are sent exactly as they stand: a bare LF stays a
/// bare LF, a `Content-Length` that disagrees with the body stays wrong, two headers
/// with the same name stay in the order they were written. Nothing parses them on the
/// way out.
///
/// A draft never changes mode on its own. [`Draft::into_raw`] converts a structured
/// draft to bytes and says so by producing them; loading raw bytes keeps them raw.
/// The reason is that the two modes disagree about what "send this" means, and a tool
/// that guessed which one a tester wanted would eventually guess wrong about a request
/// whose whole point was the byte the guess changed.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The request as it currently stands.
    ///
    /// In raw mode this is a *view* of the bytes — good enough for a URL, a method
    /// and a scope decision, and never what is written to the socket.
    pub request: HttpRequest,
    /// The stored request this was derived from, if any.
    pub parent: Option<RequestId>,
    /// What the parser noticed when the draft was last parsed from text.
    pub quirks: Vec<hexora_http::Quirk>,
    /// The bytes to send, when this draft is in raw mode.
    raw: Option<Bytes>,
}

impl Draft {
    /// Starts a structured draft from a request built in code.
    pub fn new(request: HttpRequest) -> Self {
        Self {
            request,
            parent: None,
            quirks: Vec::new(),
            raw: None,
        }
    }

    /// Starts a structured draft that records what it was derived from.
    ///
    /// Used by subsystems that build a variant of a captured request — the
    /// authorization matrix does — so the provenance survives without them needing to
    /// know how a draft is put together.
    pub fn derived_from(request: HttpRequest, parent: Option<RequestId>) -> Self {
        Self {
            request,
            parent,
            quirks: Vec::new(),
            raw: None,
        }
    }

    /// Starts a raw draft from bytes.
    ///
    /// The service is the connection target and is not re-derived from the bytes:
    /// where a request goes and what it says are separate decisions, and letting the
    /// second choose the first is how a rewritten request line would become a way to
    /// reach a host nobody scoped.
    pub fn raw(service: HttpService, bytes: impl Into<Bytes>) -> Result<Self> {
        let request = RawRequest::new(service, bytes)?;
        Ok(Self {
            // A best-effort view, for display and for the history columns. It is
            // regenerated from the bytes on every edit, and never sent.
            request: view_of(&request),
            parent: None,
            quirks: Vec::new(),
            raw: Some(request.bytes),
        })
    }

    /// Which mode this draft is in.
    pub fn mode(&self) -> RequestMode {
        match self.raw {
            Some(_) => RequestMode::Raw,
            None => RequestMode::Structured,
        }
    }

    /// The bytes this draft would send, when it is in raw mode.
    pub fn raw_bytes(&self) -> Option<&Bytes> {
        self.raw.as_ref()
    }

    /// Converts a structured draft to raw bytes, keeping what it currently says.
    ///
    /// An explicit operation with a visible result: the serialized form appears, and
    /// from then on those bytes are what gets sent. Converting a raw draft does
    /// nothing, because it is already the thing being converted to.
    pub fn into_raw(mut self) -> Self {
        if self.raw.is_none() {
            self.raw = Some(Bytes::from(render(&self.request)));
        }
        self
    }

    /// Reverts a raw draft to structured editing by parsing its bytes.
    ///
    /// Also explicit, and lossy by definition — that is the point of naming it. What
    /// comes back is a *model* of the bytes, and sending it will produce whatever
    /// serializing that model produces, not what the bytes said.
    pub fn into_structured(mut self, limits: &Limits) -> Result<Self> {
        if let Some(bytes) = self.raw.take() {
            let parsed = parse(&bytes, self.request.service.clone(), limits)?;
            self.request = parsed.request;
            self.quirks = parsed.quirks;
        }
        Ok(self)
    }

    /// The draft as editable bytes.
    ///
    /// In raw mode this is exactly what will be sent. In structured mode it is the
    /// serialization of the model, which is what would be sent.
    pub fn to_raw(&self) -> Vec<u8> {
        match &self.raw {
            Some(bytes) => bytes.to_vec(),
            None => render(&self.request),
        }
    }

    /// Replaces the draft's content with edited bytes.
    ///
    /// In **structured** mode the bytes are parsed and the model replaced: the
    /// connection target is carried over rather than re-derived from `Host`, so
    /// editing `Host` tests virtual-host routing instead of silently sending the
    /// request somewhere else. An absolute-form request line still wins; see [`raw`].
    ///
    /// In **raw** mode the bytes are kept as they are. They are still *read* — a
    /// method, a target and a set of headers are needed for the scope decision and
    /// the history table — but reading is not rewriting, and what goes on the wire is
    /// what was typed. A raw edit whose first line cannot be read at all is refused,
    /// because a request nobody can scope must not be sent.
    pub fn apply_raw(&mut self, bytes: &[u8], limits: &Limits) -> Result<()> {
        if self.raw.is_some() {
            let request = RawRequest::new(self.request.service.clone(), bytes.to_vec())?;
            self.request = view_of(&request);
            // The quirk list belongs to the parser, and nothing was parsed. Leaving a
            // stale one would attribute the previous draft's oddities to these bytes.
            self.quirks.clear();
            self.raw = Some(request.bytes);
            return Ok(());
        }

        let parsed = parse(bytes, self.request.service.clone(), limits)?;
        self.request = parsed.request;
        self.quirks = parsed.quirks;
        Ok(())
    }

    /// Everything questionable about the draft, without changing any of it.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut warnings = inspect(&self.request, &self.quirks);
        if self.raw.is_some() {
            warnings.push(Warning::RawMode);
        }
        warnings
    }

    /// What the transport will be handed.
    pub fn source(&self) -> Result<RequestSource> {
        match &self.raw {
            Some(bytes) => Ok(RequestSource::Raw(RawRequest::new(
                self.request.service.clone(),
                bytes.clone(),
            )?)),
            None => Ok(RequestSource::Structured(self.request.clone())),
        }
    }
}

/// A message-model view of raw bytes, for display, scope and the history columns.
///
/// Never sent. The bytes are.
fn view_of(raw: &RawRequest) -> HttpRequest {
    let line = raw.request_line();
    let mut request = HttpRequest::get(
        raw.service.clone(),
        line.as_ref()
            .map(|l| l.target.clone())
            .unwrap_or_else(|| "/".to_string()),
    );
    request.method = line.map(|l| l.method).unwrap_or_default();
    request.body = raw.body();
    // `HttpRequest::get` adds a Host from the service. These bytes may not have
    // carried one — a missing Host is a routing test — and a view that invented it
    // would show the tester a header they did not send.
    request.headers = hexora_types::http::Headers::new();

    let head = raw.head();
    let text = String::from_utf8_lossy(&head);
    for field in text.split(LF).skip(1) {
        let field = field.trim_end_matches(CR);
        if field.is_empty() {
            break;
        }
        if let Some((name, value)) = field.split_once(':') {
            request
                .headers
                .append(hexora_types::http::Header::new(name.trim(), value.trim()));
        }
    }
    request
}

const LF: char = '\n';
const CR: char = '\r';

/// A completed repeater send.
#[derive(Debug, Clone)]
pub struct Sent {
    /// The id the send was stored under.
    pub id: RequestId,
    /// The request this one derived from.
    pub parent: Option<RequestId>,
    /// The principal it was sent as, when one was chosen.
    pub identity: Option<hexora_types::ids::IdentityId>,
    /// What came back.
    pub exchange: hexora_engine::transport::Exchange,
    /// What the scope guard decided. Out-of-scope is flagged, never refused.
    pub decision: ScopeDecision,
}

/// Who a send is made as, and which subsystem is making it.
///
/// A separate type rather than two arguments because the pair must stay consistent:
/// an authorization replay that recorded itself as ordinary repeater traffic would be
/// indistinguishable, in the project, from a tester resending something by hand.
#[derive(Debug, Clone, Copy)]
pub struct SendAs<'a> {
    /// The subsystem the request is attributed to.
    pub origin: Origin,
    /// The principal whose credential is applied before sending.
    pub identity: Option<&'a Identity>,
}

impl SendAs<'_> {
    /// A hand-driven repeater send, with whatever credential the draft already
    /// carries.
    pub fn repeater() -> Self {
        Self {
            origin: Origin::Repeater,
            identity: None,
        }
    }
}

impl<'a> SendAs<'a> {
    /// An authorization-matrix send, replayed as `identity`.
    pub fn authz(identity: &'a Identity) -> Self {
        Self {
            origin: Origin::Authz,
            identity: Some(identity),
        }
    }
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

        // A request that was sent raw comes back raw. Rebuilding it from the columns
        // would produce a structured request that *looks* the same and is not: the
        // bare LF the tester wrote would come back as CRLF, which is precisely the
        // difference they were testing.
        if let (hexora_types::raw::RequestMode::Raw, Some(bytes)) = (stored.mode, &stored.raw) {
            let mut draft = Draft::raw(stored.service.clone(), bytes.clone())?;
            draft.parent = Some(id);
            return Ok(draft);
        }

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
            raw: None,
        })
    }

    /// Decides what scope would do with a draft, without sending it.
    ///
    /// Exposed so a UI can offer "this is out of scope — add it?" before the request
    /// leaves, rather than after.
    pub fn decide(&self, draft: &Draft) -> ScopeDecision {
        self.decide_as(draft, SendAs::repeater())
    }

    /// Decides what scope would do with a draft sent by a particular subsystem.
    ///
    /// The answer depends on who is asking: a hand-driven send to an out-of-scope
    /// host is allowed and flagged, while the same request from an automated
    /// subsystem is refused outright. A caller that is about to send several requests
    /// in a row — an authorization matrix, say — should ask first, so a misconfigured
    /// scope is one clear message rather than one failure per identity.
    pub fn decide_as(&self, draft: &Draft, sender: SendAs<'_>) -> ScopeDecision {
        let options = if sender.origin.is_automated() {
            SendOptions::automated(sender.origin)
        } else {
            SendOptions::interactive(sender.origin)
        };
        self.transport.decide(&draft.request, &options)
    }

    /// Sends a draft and records the exchange against the project.
    pub async fn send(&self, draft: &Draft) -> Result<Sent> {
        self.send_as(draft, SendAs::repeater()).await
    }

    /// Sends a draft as a chosen principal, on behalf of a chosen subsystem.
    ///
    /// The identity's credential is applied to a *copy* of the draft, so a matrix that
    /// replays one request as six identities leaves the tester's draft untouched and
    /// each send carries exactly one credential.
    ///
    /// The identity is recorded against the stored request. Without that column an
    /// authorization result is only an assertion: "this response reached User B" needs
    /// the project to be able to say which principal sent it, months later, to someone
    /// who was not in the room.
    pub async fn send_as(&self, draft: &Draft, sender: SendAs<'_>) -> Result<Sent> {
        let mut options = if sender.origin.is_automated() {
            SendOptions::automated(sender.origin)
        } else {
            SendOptions::interactive(sender.origin)
        };
        options.limits = self.limits.clone();

        // Raw mode is byte-exact, so a credential cannot be applied to it: doing so
        // would mean rewriting a header block the tester wrote deliberately. A raw
        // draft carries whatever authorization its bytes contain, and a caller that
        // wants an identity applied converts to structured first.
        let (decision, exchange) = match draft.source()? {
            RequestSource::Raw(raw) => {
                if sender.identity.is_some() {
                    return Err(hexora_types::HexoraError::invalid_input(
                        "raw",
                        "a raw request is sent byte for byte, so an identity's \
                         credential cannot be applied to it. Put the credential in the \
                         bytes, or convert the draft to structured first",
                    ));
                }
                let decision = self.transport.decide_raw(&raw, &options);
                (decision, self.transport.send_raw(raw, options).await?)
            }
            RequestSource::Structured(mut request) => {
                if let Some(identity) = sender.identity {
                    identity.authenticate(&mut request.headers);
                }
                let decision = self.transport.decide(&request, &options);
                (decision, self.transport.send(request, options).await?)
            }
        };

        let captured = CapturedExchange {
            request: exchange.request.clone(),
            raw_request: exchange.raw_request.clone(),
            response: exchange.response.clone(),
            encoded_body: exchange.encoded_body.clone(),
            content_encoding: exchange.content_encoding.clone(),
            origin: sender.origin.as_str(),
            identity: sender.identity.map(|i| i.id),
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
            identity: sender.identity.map(|i| i.id),
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
            raw_request: None,
            content_encoding: None,
            origin: "proxy",
            identity: None,
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
    // ------------------------------------------------------------------- raw mode

    const ODD: &[u8] = b"get /raw HTTP/1.1\nhOsT: example.com\nX-Dup: a\nX-Dup: b\n\nbody";

    fn raw_draft() -> Draft {
        Draft::raw(service(), ODD.to_vec()).unwrap()
    }

    #[test]
    fn a_draft_never_changes_mode_on_its_own() {
        let structured = Draft::new(HttpRequest::get(service(), "/a"));
        assert_eq!(structured.mode(), RequestMode::Structured);
        assert!(structured.raw_bytes().is_none());

        // Editing a structured draft leaves it structured, even when the bytes typed
        // in were bare-LF: that is what the LineEndingsNormalized warning is for.
        let mut edited = structured.clone();
        edited
            .apply_raw(
                b"GET /b HTTP/1.1\nHost: example.com\n\n",
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(edited.mode(), RequestMode::Structured);

        // And converting is an explicit act with a visible result.
        let raw = edited.into_raw();
        assert_eq!(raw.mode(), RequestMode::Raw);
        assert!(raw.raw_bytes().is_some());
    }

    #[test]
    fn editing_a_raw_draft_keeps_every_byte() {
        let mut draft = raw_draft();
        assert_eq!(draft.to_raw(), ODD);

        draft
            .apply_raw(b"POST /x HTTP/1.1\nA: 1\n\n\xff", &Limits::default())
            .unwrap();
        assert_eq!(draft.to_raw(), b"POST /x HTTP/1.1\nA: 1\n\n\xff");
        assert_eq!(draft.mode(), RequestMode::Raw);

        // The view follows the bytes, so history and scope stay right...
        assert_eq!(draft.request.method, "POST");
        assert_eq!(draft.request.path, "/x");
        // ...and the bytes are still what would be sent.
        assert_eq!(
            draft.raw_bytes().unwrap().as_ref(),
            b"POST /x HTTP/1.1\nA: 1\n\n\xff"
        );
    }

    #[test]
    fn a_raw_draft_says_that_nothing_will_be_corrected() {
        let warnings = raw_draft().warnings();
        assert!(
            warnings.iter().any(|w| matches!(w, Warning::RawMode)),
            "{warnings:?}"
        );
        assert!(warnings
            .iter()
            .any(|w| w.to_string().contains("exactly as written")));
    }

    #[test]
    fn a_raw_edit_with_no_readable_request_line_is_refused() {
        // Not because it is malformed. Because scope is checked against the target,
        // and a request nobody can scope must never reach a socket.
        let mut draft = raw_draft();
        let error = draft
            .apply_raw(b"garbage\n\n", &Limits::default())
            .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
        assert_eq!(draft.to_raw(), ODD, "and the draft is left as it was");
    }

    #[tokio::test]
    async fn a_raw_send_writes_the_bytes_and_records_them() {
        let (repeater, store, _project) = repeater(in_scope());
        let sent = repeater.send(&raw_draft()).await.unwrap();

        assert_eq!(sent.exchange.raw_request.as_deref(), Some(ODD));

        // And the project can hand them back, byte for byte, months later.
        let stored = store.request(sent.id).unwrap();
        assert_eq!(stored.mode, RequestMode::Raw);
        assert_eq!(stored.raw.as_deref(), Some(ODD));
    }

    #[tokio::test]
    async fn a_stored_raw_request_reloads_as_raw() {
        // The regression this milestone exists to prevent: rebuilding a raw request
        // from its columns would turn the tester's bare LF into CRLF and send a
        // different request under the same name.
        let (repeater, _store, _project) = repeater(in_scope());
        let sent = repeater.send(&raw_draft()).await.unwrap();

        let reloaded = repeater.draft_from(sent.id).unwrap();
        assert_eq!(reloaded.mode(), RequestMode::Raw);
        assert_eq!(reloaded.to_raw(), ODD);
        assert_eq!(reloaded.parent, Some(sent.id));
    }

    #[tokio::test]
    async fn a_structured_request_still_reloads_as_structured() {
        let (repeater, _store, _project) = repeater(in_scope());
        let sent = repeater
            .send(&Draft::new(HttpRequest::get(service(), "/plain")))
            .await
            .unwrap();

        let reloaded = repeater.draft_from(sent.id).unwrap();
        assert_eq!(reloaded.mode(), RequestMode::Structured);
        assert_eq!(reloaded.request.path, "/plain");
    }

    #[tokio::test]
    async fn an_out_of_scope_raw_request_from_an_automated_origin_is_refused() {
        // Raw mode is powerful on purpose, and it is not a way around invariant 1.
        let (repeater, _store, _project) =
            repeater(Scope::new().include(ScopeRule::host("elsewhere.example")));
        let identity = Identity::bearer("Scanner", "t");

        let error = repeater
            .send_as(
                &raw_draft(),
                SendAs {
                    origin: Origin::Scanner,
                    identity: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "out_of_scope", "{error}");
        let _ = identity;
    }

    #[tokio::test]
    async fn an_out_of_scope_raw_request_from_a_human_is_flagged_rather_than_refused() {
        let (repeater, _store, _project) =
            repeater(Scope::new().include(ScopeRule::host("elsewhere.example")));
        let sent = repeater.send(&raw_draft()).await.unwrap();
        assert_eq!(sent.decision, ScopeDecision::AllowedOutOfScope);
    }

    #[tokio::test]
    async fn a_raw_request_whose_line_points_elsewhere_is_scoped_by_its_path() {
        // The authority in an absolute-form target does not choose the connection, so
        // it must not choose the scope decision either — otherwise a rewritten request
        // line would be a way to make an out-of-scope host look in scope, or the
        // reverse.
        let (repeater, _store, _project) = repeater(in_scope());
        let draft = Draft::raw(
            service(),
            b"GET http://elsewhere.example/admin HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n"
                .to_vec(),
        )
        .unwrap();

        let sent = repeater
            .send_as(
                &draft,
                SendAs {
                    origin: Origin::Scanner,
                    identity: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            sent.decision,
            ScopeDecision::Allowed,
            "example.com/admin is in scope; the request line said nothing about that"
        );
    }

    #[tokio::test]
    async fn an_identity_cannot_be_applied_to_a_raw_request() {
        // Applying one would mean rewriting a header block the tester wrote
        // deliberately, which is the one thing raw mode promises not to do.
        let (repeater, _store, _project) = repeater(in_scope());
        let identity = Identity::bearer("User B", "TOKEN_B");

        let error = repeater
            .send_as(&raw_draft(), SendAs::authz(&identity))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "invalid_input");
        assert!(error.to_string().contains("byte for byte"), "{error}");
    }

    #[tokio::test]
    async fn a_raw_send_keeps_its_provenance() {
        let (repeater, store, _project) = repeater(in_scope());
        let original = repeater
            .send(&Draft::new(HttpRequest::get(service(), "/original")))
            .await
            .unwrap();

        let mut draft = repeater.draft_from(original.id).unwrap().into_raw();
        draft
            .apply_raw(
                b"GET /edited HTTP/1.1\nHost: example.com\n\n",
                &Limits::default(),
            )
            .unwrap();

        let resent = repeater.send(&draft).await.unwrap();
        assert_eq!(resent.parent, Some(original.id));

        let stored = store.request(resent.id).unwrap();
        assert_eq!(stored.parent, Some(original.id));
        assert_eq!(stored.mode, RequestMode::Raw);
        assert_eq!(store.children(original.id).unwrap(), vec![resent.id]);
    }

    #[test]
    fn converting_back_to_structured_is_explicit_and_says_what_it_costs() {
        // Round-tripping through the model is lossy by definition: that is why it has
        // a name rather than happening on the next edit.
        let draft = raw_draft().into_structured(&Limits::default()).unwrap();
        assert_eq!(draft.mode(), RequestMode::Structured);
        assert!(
            draft.to_raw().windows(2).any(|w| w == b"\r\n"),
            "serializing the model produces CRLF, which is exactly the loss"
        );
    }
}
