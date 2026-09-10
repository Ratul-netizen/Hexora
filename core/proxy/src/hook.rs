//! Interception hooks: forward, drop, modify, or answer.
//!
//! Up to now the proxy has been a recorder. This is what makes it a tool — the point
//! where a request stops, waits for a decision, and can be changed before it goes on.
//!
//! # The failure mode this design exists to prevent
//!
//! An intercepting proxy holds the browser hostage by definition: interception means
//! "stop and wait for a human". That is correct and expected *while someone is
//! watching*. It is a disaster when nobody is.
//!
//! Leave interception enabled, close the UI, and every subsequent request hangs. The
//! browser spins, the tester assumes the proxy has crashed, and the real cause —
//! a queue nobody is reading — is invisible.
//!
//! So [`ManualInterceptor`] tracks whether a consumer is actually attached. With none,
//! it forwards immediately rather than queueing. Interception being *enabled* and
//! interception being *watched* are different things, and only the second can block a
//! request. A queue with no reader is a bug, not a policy.
//!
//! There is still a timeout for the case where a consumer attaches and then stops
//! responding — a UI that froze, say — because a decision that never comes must not
//! wedge the connection indefinitely.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hexora_types::http::{HttpRequest, HttpResponse};
use tokio::sync::{mpsc, oneshot};

/// How long to wait for a verdict before falling back.
///
/// Generous: a human reading a request is slow, and interrupting them would be worse
/// than waiting. This exists only to bound a consumer that has stopped answering.
const DEFAULT_VERDICT_TIMEOUT: Duration = Duration::from_secs(300);

/// Identifies one paused request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterceptId(u64);

impl std::fmt::Display for InterceptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// What to do with a paused request.
#[derive(Debug, Clone)]
pub enum RequestVerdict {
    /// Send it as-is.
    Forward,
    /// Send this instead.
    ///
    /// The replacement goes through scope enforcement like any other request — a user
    /// editing the `Host` header must not be able to steer an automated subsystem
    /// somewhere it was never authorised.
    Replace(Box<HttpRequest>),
    /// Do not send it; close the client connection.
    Drop,
    /// Do not send it; answer the client with this.
    ///
    /// Useful for testing how a client handles a response the server never gave.
    Respond(Box<HttpResponse>),
}

/// What to do with a response on its way back.
#[derive(Debug, Clone)]
pub enum ResponseVerdict {
    /// Return it unchanged.
    Forward,
    /// Return this instead.
    Replace(Box<HttpResponse>),
    /// Close the connection without answering.
    Drop,
}

/// A request paused for a decision.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Identifies this pause, for [`InterceptHandle::resolve_request`].
    pub id: InterceptId,
    /// The request as it would be sent.
    pub request: HttpRequest,
}

/// A response paused for a decision.
#[derive(Debug, Clone)]
pub struct PendingResponse {
    /// Identifies this pause.
    pub id: InterceptId,
    /// The request that produced it, for context.
    pub request: HttpRequest,
    /// The response as it would be returned.
    pub response: HttpResponse,
}

/// Decides what happens to intercepted traffic.
#[async_trait]
pub trait Interceptor: Send + Sync + 'static {
    /// Called before a request is sent upstream.
    async fn on_request(&self, request: &HttpRequest) -> RequestVerdict;

    /// Called before a response is returned to the client.
    async fn on_response(&self, request: &HttpRequest, response: &HttpResponse) -> ResponseVerdict;
}

/// Forwards everything without pausing.
///
/// The default, and what the proxy uses until a tester turns interception on.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassThrough;

#[async_trait]
impl Interceptor for PassThrough {
    async fn on_request(&self, _request: &HttpRequest) -> RequestVerdict {
        RequestVerdict::Forward
    }

    async fn on_response(
        &self,
        _request: &HttpRequest,
        _response: &HttpResponse,
    ) -> ResponseVerdict {
        ResponseVerdict::Forward
    }
}

/// Which direction a manual interceptor pauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterceptDirections {
    /// Pause requests on their way out.
    pub requests: bool,
    /// Pause responses on their way back.
    pub responses: bool,
}

impl InterceptDirections {
    /// Pause requests only — the common case, and what Burp users expect by default.
    pub fn requests_only() -> Self {
        Self {
            requests: true,
            responses: false,
        }
    }

    /// Pause both directions.
    pub fn both() -> Self {
        Self {
            requests: true,
            responses: true,
        }
    }
}

type RequestWaiters = Arc<Mutex<HashMap<InterceptId, oneshot::Sender<RequestVerdict>>>>;
type ResponseWaiters = Arc<Mutex<HashMap<InterceptId, oneshot::Sender<ResponseVerdict>>>>;

/// An interceptor driven by a consumer — the UI, or the CLI.
pub struct ManualInterceptor {
    enabled: AtomicBool,
    directions: Mutex<InterceptDirections>,
    /// How many consumers are attached. Zero means nothing is watching, so nothing
    /// pauses; see the module documentation.
    consumers: Arc<AtomicUsize>,
    next_id: AtomicUsize,
    request_tx: mpsc::UnboundedSender<PendingRequest>,
    response_tx: mpsc::UnboundedSender<PendingResponse>,
    request_waiters: RequestWaiters,
    response_waiters: ResponseWaiters,
    timeout: Duration,
}

impl std::fmt::Debug for ManualInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualInterceptor")
            .field("enabled", &self.is_enabled())
            .field("consumers", &self.consumers.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// The consumer side: takes paused traffic and returns verdicts.
pub struct InterceptHandle {
    requests: mpsc::UnboundedReceiver<PendingRequest>,
    responses: mpsc::UnboundedReceiver<PendingResponse>,
    request_waiters: RequestWaiters,
    response_waiters: ResponseWaiters,
    consumers: Arc<AtomicUsize>,
}

impl Drop for InterceptHandle {
    fn drop(&mut self) {
        // The moment the last consumer goes away, paused traffic must stop pausing.
        // Otherwise closing the UI silently wedges the browser.
        self.consumers.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ManualInterceptor {
    /// Creates an interceptor and the handle a consumer drives it with.
    pub fn new(directions: InterceptDirections) -> (Arc<Self>, InterceptHandle) {
        let (request_tx, requests) = mpsc::unbounded_channel();
        let (response_tx, responses) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(Mutex::new(HashMap::new()));
        let response_waiters: ResponseWaiters = Arc::new(Mutex::new(HashMap::new()));
        let consumers = Arc::new(AtomicUsize::new(1));

        let interceptor = Arc::new(Self {
            enabled: AtomicBool::new(true),
            directions: Mutex::new(directions),
            consumers: consumers.clone(),
            next_id: AtomicUsize::new(1),
            request_tx,
            response_tx,
            request_waiters: request_waiters.clone(),
            response_waiters: response_waiters.clone(),
            timeout: DEFAULT_VERDICT_TIMEOUT,
        });

        let handle = InterceptHandle {
            requests,
            responses,
            request_waiters,
            response_waiters,
            consumers,
        };
        (interceptor, handle)
    }

    /// Turns interception on or off without disconnecting the consumer.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    /// Whether interception is on.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Changes which directions pause.
    pub fn set_directions(&self, directions: InterceptDirections) {
        *self.directions.lock().expect("directions mutex poisoned") = directions;
    }

    /// Whether anything would actually pause right now.
    ///
    /// Enabled *and* watched. Either alone is not enough.
    pub fn is_active(&self) -> bool {
        self.is_enabled() && self.consumers.load(Ordering::SeqCst) > 0
    }

    fn next_id(&self) -> InterceptId {
        InterceptId(self.next_id.fetch_add(1, Ordering::SeqCst) as u64)
    }
}

#[async_trait]
impl Interceptor for ManualInterceptor {
    async fn on_request(&self, request: &HttpRequest) -> RequestVerdict {
        let paused = self
            .directions
            .lock()
            .expect("directions mutex poisoned")
            .requests;
        if !paused || !self.is_active() {
            return RequestVerdict::Forward;
        }

        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.request_waiters
            .lock()
            .expect("waiters mutex poisoned")
            .insert(id, tx);

        if self
            .request_tx
            .send(PendingRequest {
                id,
                request: request.clone(),
            })
            .is_err()
        {
            // The consumer vanished between the check and the send.
            self.request_waiters
                .lock()
                .expect("waiters mutex poisoned")
                .remove(&id);
            return RequestVerdict::Forward;
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(verdict)) => verdict,
            // Either the consumer dropped the sender or it stopped answering. Neither
            // is a reason to leave the browser hanging forever.
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    %id,
                    url = %request.url(),
                    "no interception verdict arrived; forwarding the request unchanged"
                );
                self.request_waiters
                    .lock()
                    .expect("waiters mutex poisoned")
                    .remove(&id);
                RequestVerdict::Forward
            }
        }
    }

    async fn on_response(&self, request: &HttpRequest, response: &HttpResponse) -> ResponseVerdict {
        let paused = self
            .directions
            .lock()
            .expect("directions mutex poisoned")
            .responses;
        if !paused || !self.is_active() {
            return ResponseVerdict::Forward;
        }

        let id = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.response_waiters
            .lock()
            .expect("waiters mutex poisoned")
            .insert(id, tx);

        if self
            .response_tx
            .send(PendingResponse {
                id,
                request: request.clone(),
                response: response.clone(),
            })
            .is_err()
        {
            self.response_waiters
                .lock()
                .expect("waiters mutex poisoned")
                .remove(&id);
            return ResponseVerdict::Forward;
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(%id, "no interception verdict arrived; returning the response");
                self.response_waiters
                    .lock()
                    .expect("waiters mutex poisoned")
                    .remove(&id);
                ResponseVerdict::Forward
            }
        }
    }
}

impl InterceptHandle {
    /// Waits for the next paused request.
    pub async fn next_request(&mut self) -> Option<PendingRequest> {
        self.requests.recv().await
    }

    /// Waits for the next paused response.
    pub async fn next_response(&mut self) -> Option<PendingResponse> {
        self.responses.recv().await
    }

    /// Delivers a verdict for a paused request.
    ///
    /// Returns whether the pause was still waiting; a stale id — one that already
    /// timed out — is reported rather than silently ignored.
    pub fn resolve_request(&self, id: InterceptId, verdict: RequestVerdict) -> bool {
        let waiter = self
            .request_waiters
            .lock()
            .expect("waiters mutex poisoned")
            .remove(&id);
        match waiter {
            Some(tx) => tx.send(verdict).is_ok(),
            None => false,
        }
    }

    /// Delivers a verdict for a paused response.
    pub fn resolve_response(&self, id: InterceptId, verdict: ResponseVerdict) -> bool {
        let waiter = self
            .response_waiters
            .lock()
            .expect("waiters mutex poisoned")
            .remove(&id);
        match waiter {
            Some(tx) => tx.send(verdict).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::http::HttpService;

    use super::*;

    fn request(path: &str) -> HttpRequest {
        HttpRequest::get(HttpService::new("example.com", 80, false), path)
    }

    fn response(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            reason: None,
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::new(),
            truncated: false,
        }
    }

    #[tokio::test]
    async fn pass_through_forwards_everything() {
        let verdict = PassThrough.on_request(&request("/")).await;
        assert!(matches!(verdict, RequestVerdict::Forward));
    }

    #[tokio::test]
    async fn a_watched_request_pauses_until_a_verdict_arrives() {
        let (interceptor, mut handle) =
            ManualInterceptor::new(InterceptDirections::requests_only());

        let waiting = tokio::spawn({
            let interceptor = interceptor.clone();
            async move { interceptor.on_request(&request("/a")).await }
        });

        let pending = handle.next_request().await.expect("a request should pause");
        assert_eq!(pending.request.path, "/a");
        assert!(handle.resolve_request(pending.id, RequestVerdict::Forward));

        assert!(matches!(waiting.await.unwrap(), RequestVerdict::Forward));
    }

    #[tokio::test]
    async fn a_request_can_be_replaced() {
        let (interceptor, mut handle) =
            ManualInterceptor::new(InterceptDirections::requests_only());

        let waiting = tokio::spawn({
            let interceptor = interceptor.clone();
            async move { interceptor.on_request(&request("/original")).await }
        });

        let pending = handle.next_request().await.unwrap();
        let mut edited = pending.request.clone();
        edited.path = "/edited".to_string();
        handle.resolve_request(pending.id, RequestVerdict::Replace(Box::new(edited)));

        match waiting.await.unwrap() {
            RequestVerdict::Replace(edited) => assert_eq!(edited.path, "/edited"),
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_request_can_be_dropped_or_answered_directly() {
        for verdict in [
            RequestVerdict::Drop,
            RequestVerdict::Respond(Box::new(response(418))),
        ] {
            let (interceptor, mut handle) =
                ManualInterceptor::new(InterceptDirections::requests_only());
            let waiting = tokio::spawn({
                let interceptor = interceptor.clone();
                async move { interceptor.on_request(&request("/")).await }
            });
            let pending = handle.next_request().await.unwrap();
            handle.resolve_request(pending.id, verdict.clone());

            match (waiting.await.unwrap(), &verdict) {
                (RequestVerdict::Drop, RequestVerdict::Drop) => {}
                (RequestVerdict::Respond(got), RequestVerdict::Respond(want)) => {
                    assert_eq!(got.status, want.status);
                }
                (got, want) => panic!("expected {want:?}, got {got:?}"),
            }
        }
    }

    // ------------------------------------------------- the queue-with-no-reader case

    #[tokio::test]
    async fn nothing_pauses_when_no_consumer_is_attached() {
        // The failure this whole design exists to prevent: interception left on, UI
        // closed, and every request hangs forever.
        let (interceptor, handle) = ManualInterceptor::new(InterceptDirections::both());
        assert!(interceptor.is_active());

        drop(handle);
        assert!(
            !interceptor.is_active(),
            "with nobody watching, interception must stop pausing"
        );

        // Would block forever if the consumer check were missing.
        let verdict = tokio::time::timeout(
            Duration::from_millis(200),
            interceptor.on_request(&request("/")),
        )
        .await
        .expect("must not hang when nobody is watching");
        assert!(matches!(verdict, RequestVerdict::Forward));
    }

    #[tokio::test]
    async fn disabling_interception_forwards_without_pausing() {
        let (interceptor, _handle) = ManualInterceptor::new(InterceptDirections::both());
        interceptor.set_enabled(false);
        assert!(!interceptor.is_active());

        let verdict = tokio::time::timeout(
            Duration::from_millis(200),
            interceptor.on_request(&request("/")),
        )
        .await
        .expect("disabled interception must not pause");
        assert!(matches!(verdict, RequestVerdict::Forward));
    }

    #[tokio::test]
    async fn enabled_and_watched_are_different_things() {
        let (interceptor, handle) = ManualInterceptor::new(InterceptDirections::both());
        assert!(interceptor.is_enabled() && interceptor.is_active());

        drop(handle);
        assert!(
            interceptor.is_enabled() && !interceptor.is_active(),
            "still enabled, but no longer able to block anything"
        );
    }

    #[tokio::test]
    async fn a_consumer_that_stops_answering_does_not_wedge_the_connection() {
        let (interceptor, mut handle) =
            ManualInterceptor::new(InterceptDirections::requests_only());
        // A frozen UI: it takes the request off the queue and never replies.
        let interceptor = Arc::new(ManualInterceptor {
            timeout: Duration::from_millis(150),
            ..Arc::try_unwrap(interceptor).map_err(|_| ()).unwrap()
        });

        let waiting = tokio::spawn({
            let interceptor = interceptor.clone();
            async move { interceptor.on_request(&request("/")).await }
        });
        let _pending = handle.next_request().await.unwrap();

        let verdict = tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("the timeout must fire")
            .unwrap();
        assert!(matches!(verdict, RequestVerdict::Forward));
    }

    #[tokio::test]
    async fn resolving_an_unknown_id_reports_failure_rather_than_pretending() {
        let (_interceptor, handle) = ManualInterceptor::new(InterceptDirections::requests_only());
        assert!(!handle.resolve_request(InterceptId(999), RequestVerdict::Forward));
    }

    // ---------------------------------------------------------------- directions

    #[tokio::test]
    async fn requests_only_leaves_responses_alone() {
        let (interceptor, _handle) = ManualInterceptor::new(InterceptDirections::requests_only());
        let verdict = tokio::time::timeout(
            Duration::from_millis(200),
            interceptor.on_response(&request("/"), &response(200)),
        )
        .await
        .expect("responses must not pause in requests-only mode");
        assert!(matches!(verdict, ResponseVerdict::Forward));
    }

    #[tokio::test]
    async fn responses_pause_when_asked_to() {
        let (interceptor, mut handle) = ManualInterceptor::new(InterceptDirections::both());

        let waiting = tokio::spawn({
            let interceptor = interceptor.clone();
            async move { interceptor.on_response(&request("/"), &response(200)).await }
        });

        let pending = handle
            .next_response()
            .await
            .expect("a response should pause");
        assert_eq!(pending.response.status, 200);
        handle.resolve_response(
            pending.id,
            ResponseVerdict::Replace(Box::new(response(404))),
        );

        match waiting.await.unwrap() {
            ResponseVerdict::Replace(replaced) => assert_eq!(replaced.status, 404),
            other => panic!("expected a replacement, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn directions_can_change_at_runtime() {
        let (interceptor, _handle) = ManualInterceptor::new(InterceptDirections::default());
        // Neither direction set: nothing pauses.
        let verdict = tokio::time::timeout(
            Duration::from_millis(200),
            interceptor.on_request(&request("/")),
        )
        .await
        .expect("must not pause");
        assert!(matches!(verdict, RequestVerdict::Forward));

        interceptor.set_directions(InterceptDirections::requests_only());
        assert!(interceptor.is_active());
    }
}
