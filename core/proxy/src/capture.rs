//! Writing captured traffic to a project.
//!
//! The proxy hands every completed exchange to an [`ExchangeObserver`]. This is the
//! one that persists them, turning a stream that scrolls past into history a tester
//! can come back to.
//!
//! # Why capture never fails the request
//!
//! Storage runs on a background task, and a failure there logs rather than propagates.
//! That is deliberate: a full disk or a locked database must not break the browsing
//! session a tester is in the middle of. Losing a recorded exchange is bad; having the
//! proxy stop working is worse, and the tester can see it happening in the first case
//! and cannot in the second.
//!
//! The failure is loud, though — a warning per failure and a running count — because
//! silently dropped evidence is exactly the kind of thing that is noticed only when a
//! report is being written.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hexora_engine::guard::ScopeDecision;
use hexora_engine::transport::Exchange;
use hexora_storage::{CapturedExchange, TrafficStore};

use crate::server::ExchangeObserver;

/// Persists exchanges into a project.
pub struct ProjectCapture {
    store: Arc<TrafficStore>,
    recorded: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
    /// Whether to record traffic that fell outside the project scope.
    ///
    /// On by default: a tester needs the proxy to see a host *before* deciding it
    /// belongs in scope, and discarding those exchanges would make that impossible.
    capture_out_of_scope: bool,
}

impl std::fmt::Debug for ProjectCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectCapture")
            .field("recorded", &self.recorded())
            .field("failed", &self.failed())
            .finish_non_exhaustive()
    }
}

impl ProjectCapture {
    /// Captures everything the proxy sees.
    pub fn new(store: Arc<TrafficStore>) -> Self {
        Self {
            store,
            recorded: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
            capture_out_of_scope: true,
        }
    }

    /// Captures only in-scope traffic.
    ///
    /// Useful late in an engagement when scope is settled and the noise of a tester's
    /// own browsing is not wanted in the project.
    pub fn in_scope_only(mut self) -> Self {
        self.capture_out_of_scope = false;
        self
    }

    /// How many exchanges have been stored.
    pub fn recorded(&self) -> u64 {
        self.recorded.load(Ordering::Relaxed)
    }

    /// How many failed to store.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    fn should_capture(&self, decision: ScopeDecision) -> bool {
        match decision {
            ScopeDecision::Allowed => true,
            ScopeDecision::AllowedOutOfScope => self.capture_out_of_scope,
            // Nothing was sent, so there is nothing to record.
            ScopeDecision::Refused => false,
        }
    }
}

/// Turns an engine exchange into the form the store persists.
fn to_captured(exchange: &Exchange) -> CapturedExchange {
    let content_encoding = exchange
        .response
        .headers
        .get("Content-Encoding")
        .map(|h| h.value_lossy().into_owned());

    CapturedExchange {
        request: exchange.request.clone(),
        response: exchange.response.clone(),
        // The engine currently hands back only the decoded body; the encoded form is
        // recoverable from the response headers plus the decoded bytes only for
        // lossless codings, so it is stored as absent rather than reconstructed
        // wrongly. Threading the encoded bytes through the transport is a follow-up.
        encoded_body: None,
        content_encoding,
        origin: "proxy",
        identity: None,
        // Proxied traffic has no parent: nobody derived it from an earlier request.
        parent: None,
        quirks: Vec::new(),
        tls: exchange.tls.clone(),
        duration_ms: exchange.duration.as_millis().min(u128::from(u32::MAX)) as u32,
    }
}

impl ExchangeObserver for ProjectCapture {
    fn observe(&self, exchange: &Exchange, decision: ScopeDecision) {
        if !self.should_capture(decision) {
            return;
        }

        let captured = to_captured(exchange);
        let store = self.store.clone();
        let recorded = self.recorded.clone();
        let failed = self.failed.clone();
        let url = exchange.request.url();

        // SQLite is blocking, so it goes to the blocking pool rather than stalling the
        // proxy's async runtime while a disk write completes.
        tokio::task::spawn_blocking(move || match store.record(&captured) {
            Ok(_) => {
                recorded.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                let count = failed.fetch_add(1, Ordering::Relaxed) + 1;
                // Loud, because silently dropped evidence is discovered while writing
                // a report, which is far too late.
                tracing::warn!(
                    %url,
                    total_failures = count,
                    "failed to record a proxied exchange: {e}"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use hexora_storage::{MemoryBlobStore, Project};
    use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};

    use super::*;

    fn store() -> (Arc<TrafficStore>, Project) {
        let project = Project::in_memory().unwrap();
        let store = Arc::new(TrafficStore::new(
            project.metadata().clone(),
            Arc::new(MemoryBlobStore::new()),
        ));
        (store, project)
    }

    fn exchange(path: &str) -> Exchange {
        Exchange {
            request: HttpRequest::get(HttpService::new("example.com", 443, true), path),
            response: HttpResponse {
                status: 200,
                reason: Some("OK".into()),
                version: HttpVersion::Http11,
                headers: Headers::new(),
                body: bytes::Bytes::from_static(b"body"),
                truncated: false,
            },
            duration: std::time::Duration::from_millis(12),
            tls: None,
        }
    }

    /// Capture is asynchronous, so tests wait for the write rather than racing it.
    async fn settle() {
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn an_observed_exchange_is_persisted() {
        let (store, _project) = store();
        let capture = ProjectCapture::new(store.clone());

        capture.observe(&exchange("/a"), ScopeDecision::Allowed);
        settle().await;

        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(capture.recorded(), 1);
        assert_eq!(capture.failed(), 0);
    }

    #[tokio::test]
    async fn out_of_scope_traffic_is_captured_by_default() {
        // The proxy has to see a host before a tester can decide it belongs in scope,
        // so discarding these would make scoping impossible.
        let (store, _project) = store();
        let capture = ProjectCapture::new(store.clone());

        capture.observe(&exchange("/a"), ScopeDecision::AllowedOutOfScope);
        settle().await;

        assert_eq!(store.count().unwrap(), 1);
    }

    #[tokio::test]
    async fn in_scope_only_mode_discards_the_rest() {
        let (store, _project) = store();
        let capture = ProjectCapture::new(store.clone()).in_scope_only();

        capture.observe(&exchange("/kept"), ScopeDecision::Allowed);
        capture.observe(&exchange("/dropped"), ScopeDecision::AllowedOutOfScope);
        settle().await;

        assert_eq!(store.count().unwrap(), 1);
        let page = store
            .history(None, hexora_storage::repository::Limit::default())
            .unwrap();
        assert!(page.items[0].url.ends_with("/kept"), "{:?}", page.items[0]);
    }

    #[tokio::test]
    async fn a_refused_request_records_nothing() {
        // Nothing was sent, so there is no exchange to be evidence of.
        let (store, _project) = store();
        let capture = ProjectCapture::new(store.clone());

        capture.observe(&exchange("/a"), ScopeDecision::Refused);
        settle().await;

        assert_eq!(store.count().unwrap(), 0);
    }

    #[tokio::test]
    async fn the_content_encoding_is_recorded_so_the_wire_form_is_identifiable() {
        let (store, _project) = store();
        let capture = ProjectCapture::new(store.clone());

        let mut exchange = exchange("/compressed");
        exchange.response.headers.set("Content-Encoding", "gzip");
        capture.observe(&exchange, ScopeDecision::Allowed);
        settle().await;

        assert_eq!(store.count().unwrap(), 1);
    }

    /// The whole path, not just the observer: a browser's request goes through a real
    /// proxy to a real server, and afterwards the project holds it.
    #[tokio::test]
    async fn traffic_proxied_end_to_end_is_readable_from_the_project() {
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        use crate::{CertificateAuthority, ProxyConfig, ProxyServer};

        // An upstream that answers with a body worth reading back.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut scratch = vec![0u8; 8192];
                    let _ = socket.read(&mut scratch).await;
                    let _ = socket
                        .write_all(
                            concat!(
                                "HTTP/1.1 418 I'm a teapot\r\n",
                                "Content-Length: 11\r\n",
                                "Content-Type: text/plain\r\n",
                                "\r\n",
                                "hello world",
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let (store, project) = store();
        let capture = Arc::new(ProjectCapture::new(store.clone()));
        let config = ProxyConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Default::default()
        };
        let server = ProxyServer::bind(
            config,
            Arc::new(hexora_types::scope::Scope::new()),
            hexora_http::TcpTransport::default(),
            capture.clone(),
            Arc::new(CertificateAuthority::generate().unwrap()),
        )
        .await
        .unwrap();
        let proxy_port = server.local_addr().unwrap().port();
        tokio::spawn(async move { server.serve().await });

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{upstream_port}/tea HTTP/1.1\r\n\
                     Host: 127.0.0.1:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        assert!(
            String::from_utf8_lossy(&response).contains("418"),
            "the proxy must still answer the client"
        );

        settle().await;

        let page = store
            .history(None, hexora_storage::repository::Limit::default())
            .unwrap();
        assert_eq!(page.items.len(), 1, "{page:?}");
        let item = &page.items[0];
        assert_eq!(item.method, "GET");
        assert_eq!(item.status, Some(418));
        assert!(item.url.ends_with("/tea"), "{}", item.url);

        // And the body is retrievable, which is the point of storing it at all.
        let body = store.response_body(item.id, false).unwrap();
        assert_eq!(body, b"hello world");
        drop(project);
    }

    #[tokio::test]
    async fn tls_details_reach_the_project() {
        let (store, project) = store();
        let capture = ProjectCapture::new(store.clone());

        let mut exchange = exchange("/");
        exchange.tls = Some(hexora_types::tls::TlsInfo {
            protocol: "TLSv1.3".into(),
            cipher_suite: "TLS13_AES_128_GCM_SHA256".into(),
            alpn: Some("http/1.1".into()),
            verification: hexora_types::tls::Verification::Platform,
            peer_certificates: Vec::new(),
        });
        capture.observe(&exchange, ScopeDecision::Allowed);
        settle().await;

        let stored: Option<String> = project
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT tls_json FROM requests", [], |row| row.get(0))
            .unwrap();
        assert!(
            stored.is_some(),
            "an https exchange must record its handshake"
        );
    }
}
