//! The proxy listener.
//!
//! # Scope (M2.2)
//!
//! Plain HTTP, absolute-form requests — what a browser configured to use an HTTP
//! proxy sends for `http://` URLs. `CONNECT` tunnelling and TLS interception are M2.3;
//! a `CONNECT` here is answered with a clear `501` rather than a hang, so a
//! misconfigured browser gets an explanation instead of a stall.
//!
//! # Binding
//!
//! The listener binds to **loopback by default**. A proxy reachable from the network
//! is an open relay carrying a tester's credentials, and defaults are what people
//! actually run. Binding wider is possible and deliberate, never accidental.
//!
//! # Scope enforcement
//!
//! Proxied traffic is human-driven: the tester's browser asked for it. So requests are
//! forwarded even when out of scope, and *flagged* rather than blocked — the proxy
//! must be able to observe traffic to a host before that host is known well enough to
//! be added to scope. Automated subsystems get no such latitude; see
//! `docs/security-invariants.md`, invariant 1.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_engine::transport::{Exchange, HttpTransport, Origin, SendOptions};
use hexora_http::parse::find_head_end;
use hexora_http::request::{parse_request_head, RequestHead};
use hexora_http::{BodyStream, TcpTransport};
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{HttpRequest, HttpResponse, HttpService};
use hexora_types::limits::Limits;
use hexora_types::scope::Scope;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::ca::CertificateAuthority;
use crate::hook::{Interceptor, PassThrough, RequestVerdict, ResponseVerdict};
use crate::intercept::{self, InterceptionPolicy, TunnelOutcome};

/// Bytes read from a client per call.
const READ_CHUNK: usize = 16 * 1024;

/// Hop-by-hop headers, which RFC 9110 §7.6.1 says a proxy must not forward.
///
/// Forwarding `Connection` in particular would let a client dictate the framing of the
/// upstream connection, which is a smuggling primitive handed over for free.
/// `Proxy-Connection` is not in the RFC — it is a de-facto header from the HTTP/1.0
/// era that clients still send when they are configured to use a proxy. It is listed
/// because it is addressed to *this* proxy: forwarding it means the origin sees a
/// header the client never intended it to see, and Hexora's whole claim is that the
/// target receives what the tester meant to send. Every other proxy strips it too.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What the proxy does with each exchange it observes.
///
/// The proxy captures traffic; what happens to it — storage, the UI, interception
/// decisions — is not its concern. This keeps the listener testable without a project
/// database and lets M2.4 add interception without touching the listener.
pub trait ExchangeObserver: Send + Sync + 'static {
    /// Called once per completed exchange.
    fn observe(&self, exchange: &Exchange, decision: ScopeDecision);
}

/// An observer that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoObserver;

impl ExchangeObserver for NoObserver {
    fn observe(&self, _exchange: &Exchange, _decision: ScopeDecision) {}
}

/// Proxy settings.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on. Defaults to loopback.
    pub bind: SocketAddr,
    /// Limits applied to proxied requests and responses.
    pub limits: Limits,
    /// Which hosts are decrypted, and which are tunnelled untouched.
    pub interception: InterceptionPolicy,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            // Loopback, and port 8080 because that is what every proxy tutorial and
            // browser extension already assumes.
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            limits: Limits::default(),
            interception: InterceptionPolicy::intercept_all(),
        }
    }
}

/// A running proxy.
pub struct ProxyServer {
    listener: TcpListener,
    transport: Arc<ScopeGuard<TcpTransport>>,
    observer: Arc<dyn ExchangeObserver>,
    limits: Limits,
    interception: InterceptionPolicy,
    ca: Arc<CertificateAuthority>,
    interceptor: Arc<dyn Interceptor>,
}

impl std::fmt::Debug for ProxyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyServer")
            .field("bind", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl ProxyServer {
    /// Binds the proxy without starting to serve.
    pub async fn bind(
        config: ProxyConfig,
        scope: Arc<Scope>,
        transport: TcpTransport,
        observer: Arc<dyn ExchangeObserver>,
        ca: Arc<CertificateAuthority>,
    ) -> Result<Self> {
        if !config.bind.ip().is_loopback() {
            // Not refused — a tester may genuinely need to proxy a phone or a VM — but
            // never silent. An exposed proxy is an open relay carrying credentials.
            tracing::warn!(
                bind = %config.bind,
                "proxy is binding to a non-loopback address and will be reachable from \
                 the network; anything that can reach it can use it as an open relay"
            );
        }

        let listener = TcpListener::bind(config.bind).await.map_err(|e| {
            HexoraError::Internal(format!("cannot bind the proxy to {}: {e}", config.bind))
        })?;

        Ok(Self {
            listener,
            transport: Arc::new(ScopeGuard::new(transport, scope)),
            observer,
            limits: config.limits,
            interception: config.interception,
            ca,
            // Forwarding everything until a tester turns interception on.
            interceptor: Arc::new(PassThrough),
        })
    }

    /// Installs an interceptor, replacing the pass-through default.
    pub fn with_interceptor(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.interceptor = interceptor;
        self
    }

    /// The address actually bound, useful when port 0 was requested.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| HexoraError::Internal(format!("proxy has no local address: {e}")))
    }

    /// Serves connections until the task is dropped or cancelled.
    pub async fn serve(self) -> Result<()> {
        loop {
            let (socket, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    // One bad accept must not take the proxy down; a tester loses their
                    // whole session if it does.
                    tracing::warn!("proxy accept failed: {e}");
                    continue;
                }
            };

            let context = ConnectionContext {
                transport: self.transport.clone(),
                observer: self.observer.clone(),
                limits: self.limits.clone(),
                interception: self.interception.clone(),
                ca: self.ca.clone(),
                interceptor: self.interceptor.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, context).await {
                    tracing::debug!(%peer, "proxy connection ended: {e}");
                }
            });
        }
    }
}

/// Everything one connection needs, so the handler signature stays readable.
#[derive(Clone)]
struct ConnectionContext {
    transport: Arc<ScopeGuard<TcpTransport>>,
    observer: Arc<dyn ExchangeObserver>,
    limits: Limits,
    interception: InterceptionPolicy,
    ca: Arc<CertificateAuthority>,
    interceptor: Arc<dyn Interceptor>,
}

/// Serves one client connection.
async fn handle_connection(mut client: TcpStream, context: ConnectionContext) -> Result<()> {
    let (head, body_prefix) = read_request_head(&mut client, &context.limits).await?;

    report_request_signals(&head);

    if head.is_connect() {
        return handle_connect(client, &head, context).await.map(|_| ());
    }

    let request = build_upstream_request(&head, &mut client, body_prefix, &context.limits).await?;
    forward(&mut client, request, &context).await
}

/// Forwards one request upstream and writes the response back to the client.
///
/// The interceptor is consulted twice: once before the request leaves, once before the
/// response is returned.
async fn forward<S: AsyncWrite + Unpin>(
    client: &mut S,
    request: HttpRequest,
    context: &ConnectionContext,
) -> Result<()> {
    let request = match context.interceptor.on_request(&request).await {
        RequestVerdict::Forward => request,

        // An edited request is re-checked against scope on the way out, because the
        // user may have changed the host. That check lives in the ScopeGuard below,
        // so a replacement gets exactly the same treatment as any other request.
        RequestVerdict::Replace(edited) => {
            tracing::debug!(url = %edited.url(), "request replaced by the interceptor");
            *edited
        }

        RequestVerdict::Drop => {
            tracing::debug!(url = %request.url(), "request dropped by the interceptor");
            return Ok(());
        }

        // Answered without going upstream, which is how a tester sees what a client
        // does with a response the server never sent.
        RequestVerdict::Respond(response) => {
            tracing::debug!(url = %request.url(), "request answered by the interceptor");
            return write_response(client, &response).await;
        }
    };

    let options = SendOptions::interactive(Origin::Proxy);
    let decision = context.transport.decide(&request, &options);

    match context.transport.send(request, options).await {
        Ok(exchange) => {
            let verdict = context
                .interceptor
                .on_response(&exchange.request, &exchange.response)
                .await;

            // The exchange is recorded exactly as the server answered it, whatever the
            // client is subsequently shown. A tester's substitution is their own
            // action, not the server's behaviour, and recording it as the latter would
            // put a fabricated response into the evidence behind a finding.
            let to_client = match verdict {
                ResponseVerdict::Forward => Some(exchange.response.clone()),
                ResponseVerdict::Replace(replacement) => {
                    tracing::debug!("response replaced by the interceptor");
                    Some(*replacement)
                }
                ResponseVerdict::Drop => {
                    tracing::debug!("response dropped by the interceptor");
                    None
                }
            };

            context.observer.observe(&exchange, decision);

            if let Some(response) = to_client {
                write_response(client, &response).await?;
            }
            Ok(())
        }
        Err(e) => {
            // The browser is waiting. Telling it what went wrong is far more useful
            // than dropping the connection and leaving a spinner.
            let message = format!("Hexora could not reach the target: {e}");
            write_simple(client, 502, "Bad Gateway", message.as_bytes()).await?;
            Err(e)
        }
    }
}

/// Handles a `CONNECT`: either decrypt the tunnel or copy it blind.
async fn handle_connect(
    mut client: TcpStream,
    head: &RequestHead,
    context: ConnectionContext,
) -> Result<TunnelOutcome> {
    let service = head
        .target
        .service()
        .ok_or_else(|| HexoraError::invalid_input("connect", "CONNECT without an authority"))?;

    // The 200 goes out first either way: it is what tells the client to begin its
    // handshake, and until it arrives there is nothing to intercept.
    intercept::accept_tunnel(&mut client).await?;

    if !context.interception.intercepts(&service.host) {
        intercept::tunnel_blind(&mut client, &service).await?;
        return Ok(TunnelOutcome::Tunnelled);
    }

    let config = intercept::server_config_for(&context.ca, &service.host, &[b"http/1.1".to_vec()])?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let mut tls = acceptor.accept(client).await.map_err(|e| {
        // Usually the CA not being trusted yet, or certificate pinning. Both are
        // situations a tester needs named rather than left to guess at.
        HexoraError::Network(hexora_types::error::NetworkError::Tls {
            peer: service.host.clone(),
            reason: format!(
                "the client rejected Hexora's certificate ({e}); the CA may not be \
                 installed, or the client may pin certificates"
            ),
        })
    })?;

    // Inside the tunnel the client speaks ordinary HTTP with origin-form targets, so
    // the authority comes from the CONNECT line rather than from the request.
    let (inner_head, body_prefix) = read_request_head(&mut tls, &context.limits).await?;
    report_request_signals(&inner_head);

    let mut request =
        build_upstream_request(&inner_head, &mut tls, body_prefix, &context.limits).await?;
    // An origin-form target carries no scheme. Without this the request would be
    // replayed upstream over plaintext, silently downgrading a connection the user
    // believes is encrypted.
    request.service = HttpService::new(&service.host, service.port, true);

    forward(&mut tls, request, &context).await?;
    let _ = tls.shutdown().await;
    Ok(TunnelOutcome::Intercepted)
}

/// Warns when a proxied request's framing shows a smuggling primitive.
fn report_request_signals(head: &RequestHead) {
    if !head.has_smuggling_signal() {
        return;
    }
    let signals: Vec<&str> = head
        .quirks
        .iter()
        .filter(|q| q.is_smuggling_signal())
        .map(hexora_http::Quirk::explanation)
        .collect();
    tracing::warn!(
        method = %head.method,
        signals = ?signals,
        "proxied request framing shows a smuggling signal"
    );
}

/// Reads the request head, returning it with any body bytes that arrived alongside.
async fn read_request_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    limits: &Limits,
) -> Result<(RequestHead, BytesMut)> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let deadline = tokio::time::Instant::now() + limits.read_head_timeout;

    loop {
        if let Some(end) = find_head_end(&buf) {
            let head = parse_request_head(&buf[..end], limits)?;
            let rest = buf.split_off(end);
            return Ok((head, rest));
        }

        // Checked while reading: a client that never sends a blank line must not be
        // able to grow this buffer without bound.
        limits.check_header_size(buf.len())?;

        let before = buf.len();
        buf.resize(before + READ_CHUNK, 0);
        let read = tokio::time::timeout_at(deadline, stream.read(&mut buf[before..]))
            .await
            .map_err(|_| {
                HexoraError::Network(hexora_types::error::NetworkError::Timeout {
                    phase: hexora_types::error::TimeoutPhase::ReadResponseHead,
                    elapsed: limits.read_head_timeout,
                })
            })?
            .map_err(|e| {
                HexoraError::Network(hexora_types::error::NetworkError::Io(e.to_string()))
            })?;
        buf.truncate(before + read);

        if read == 0 {
            return Err(HexoraError::Protocol(ProtocolError::Malformed {
                protocol: "HTTP/1.1",
                reason: "client closed the connection before completing a request".to_string(),
            }));
        }
    }
}

/// Turns a proxied request into the request Hexora will send upstream.
async fn build_upstream_request<S: AsyncRead + Send + Unpin>(
    head: &RequestHead,
    client: &mut S,
    body_prefix: BytesMut,
    limits: &Limits,
) -> Result<HttpRequest> {
    let service = head.destination(false)?;

    let mut headers = hexora_types::http::Headers::new();
    for header in head.headers.iter() {
        if HOP_BY_HOP.iter().any(|h| header.is(h)) {
            continue;
        }
        headers.append(header.clone());
    }
    // A proxy rewrites the target to origin form; the authority moves to Host, which
    // the client already sent. Nothing else about the request is touched.
    if headers.count("Host") == 0 {
        headers.set("Host", service.authority());
    }

    let body = read_request_body(head, client, body_prefix, limits).await?;

    Ok(HttpRequest {
        service,
        method: head.method.clone(),
        path: if head.target.path().is_empty() {
            "/".to_string()
        } else {
            head.target.path().to_string()
        },
        version: head.version,
        headers,
        body,
    })
}

/// Reads the request body according to its framing.
async fn read_request_body<S: AsyncRead + Send + Unpin>(
    head: &RequestHead,
    client: &mut S,
    prefix: BytesMut,
    limits: &Limits,
) -> Result<bytes::Bytes> {
    use hexora_http::BodyFraming;

    if matches!(head.framing, BodyFraming::None) {
        return Ok(bytes::Bytes::new());
    }

    // The body stream needs to own its reader, so the client half is borrowed for the
    // duration through a thin adapter rather than moved.
    struct Borrowed<'a, S>(&'a mut S);
    impl<S: AsyncRead + Unpin> AsyncRead for Borrowed<'_, S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
        }
    }

    // A request body cannot be delimited by connection close — the client is waiting
    // for a response on the same connection — so `UntilClose` is treated as no body.
    let framing = match head.framing {
        BodyFraming::UntilClose => BodyFraming::None,
        other => other,
    };

    let stream = BodyStream::new(Box::new(Borrowed(client)), prefix, framing, limits.clone());
    // Content coding is left alone: the proxy forwards what the client sent.
    Ok(stream.collect("").await?.bytes)
}

/// Writes a response back to the client.
async fn write_response<S: AsyncWrite + Unpin>(
    client: &mut S,
    response: &HttpResponse,
) -> Result<()> {
    let mut out = Vec::with_capacity(response.body.len() + 256);
    out.extend_from_slice(response.version.as_str().as_bytes());
    out.extend_from_slice(format!(" {}", response.status).as_bytes());
    if let Some(reason) = &response.reason {
        out.extend_from_slice(format!(" {reason}").as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    for header in response.headers.iter() {
        // The body handed back has already been transfer- and content-decoded, so the
        // original framing headers would now be lies. They are replaced below.
        if HOP_BY_HOP.iter().any(|h| header.is(h))
            || header.is("Content-Length")
            || header.is("Content-Encoding")
        {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    // Each proxied request currently gets its own upstream connection, so the client
    // is told not to expect reuse. Keep-alive arrives with M1.4.
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&response.body);

    client
        .write_all(&out)
        .await
        .map_err(|e| HexoraError::Network(hexora_types::error::NetworkError::Io(e.to_string())))?;
    client.flush().await.ok();
    Ok(())
}

/// Writes a minimal status response, for errors the proxy itself generates.
async fn write_simple<S: AsyncWrite + Unpin>(
    client: &mut S,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client
        .write_all(head.as_bytes())
        .await
        .map_err(|e| HexoraError::Network(hexora_types::error::NetworkError::Io(e.to_string())))?;
    client
        .write_all(body)
        .await
        .map_err(|e| HexoraError::Network(hexora_types::error::NetworkError::Io(e.to_string())))?;
    client.flush().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hexora_types::scope::ScopeRule;

    use super::*;

    /// Records what the proxy observed, so tests can assert on capture.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(String, u16, ScopeDecision)>>,
    }

    impl ExchangeObserver for Arc<Recorder> {
        fn observe(&self, exchange: &Exchange, decision: ScopeDecision) {
            self.seen.lock().unwrap().push((
                exchange.request.url(),
                exchange.response.status,
                decision,
            ));
        }
    }

    /// An upstream server that answers every request with `response`.
    async fn upstream(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut scratch = vec![0u8; 8192];
                    let _ = socket.read(&mut scratch).await;
                    let _ = socket.write_all(response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        port
    }

    /// Starts a proxy on an ephemeral port, returning it and the recorder.
    async fn proxy(scope: Scope) -> (u16, Arc<Recorder>) {
        let (port, recorder, _ca) =
            proxy_with(scope, InterceptionPolicy::intercept_all(), None).await;
        (port, recorder)
    }

    /// Starts a proxy with an explicit interception policy and transport.
    ///
    /// Returns the CA too, so a test can trust it the way a browser would.
    async fn proxy_with(
        scope: Scope,
        interception: InterceptionPolicy,
        transport: Option<TcpTransport>,
    ) -> (u16, Arc<Recorder>, Arc<CertificateAuthority>) {
        proxy_full(scope, interception, transport, None).await
    }

    /// The full form, including an optional interceptor.
    async fn proxy_full(
        scope: Scope,
        interception: InterceptionPolicy,
        transport: Option<TcpTransport>,
        interceptor: Option<Arc<dyn Interceptor>>,
    ) -> (u16, Arc<Recorder>, Arc<CertificateAuthority>) {
        let recorder = Arc::new(Recorder::default());
        let ca = Arc::new(CertificateAuthority::generate().unwrap());
        let config = ProxyConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            interception,
            ..Default::default()
        };
        let server = ProxyServer::bind(
            config,
            Arc::new(scope),
            transport.unwrap_or_default(),
            Arc::new(recorder.clone()),
            ca.clone(),
        )
        .await
        .unwrap();
        let server = match interceptor {
            Some(interceptor) => server.with_interceptor(interceptor),
            None => server,
        };
        let port = server.local_addr().unwrap().port();
        tokio::spawn(server.serve());
        (port, recorder, ca)
    }

    /// An HTTPS upstream with a throwaway certificate.
    async fn https_upstream(response: &'static [u8]) -> u16 {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(issued.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.key_pair.serialize_der().into());

        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(socket).await {
                        let mut scratch = vec![0u8; 8192];
                        let _ = tls.read(&mut scratch).await;
                        let _ = tls.write_all(response).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        port
    }

    /// Speaks CONNECT to the proxy, then TLS, trusting only Hexora's CA — which is
    /// exactly what a browser with the CA installed does.
    async fn through_tunnel(
        proxy_port: u16,
        ca: &CertificateAuthority,
        target_host: &str,
        target_port: u16,
        request: &str,
    ) -> Result<String> {
        let mut socket = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let connect = format!(
            "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        );
        socket.write_all(connect.as_bytes()).await.unwrap();

        let mut established = [0u8; 128];
        let n = socket.read(&mut established).await.unwrap();
        let established = String::from_utf8_lossy(&established[..n]).into_owned();
        assert!(established.starts_with("HTTP/1.1 200"), "{established}");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.certificate_der().clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(target_host.to_string()).unwrap();
        let mut tls = connector
            .connect(name, socket)
            .await
            .map_err(|e| HexoraError::Internal(format!("client handshake failed: {e}")))?;

        tls.write_all(request.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Sends a raw request to the proxy and returns the raw response.
    async fn through_proxy(port: u16, request: &str) -> String {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        let mut out = Vec::new();
        socket.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn proxies_an_absolute_form_request() {
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        let (port, recorder) = proxy(Scope::new()).await;

        let response = through_proxy(
            port,
            &format!(
                "GET http://127.0.0.1:{target}/a HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"
            ),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("hello"), "{response}");

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the exchange must be captured");
        assert!(seen[0].0.contains("/a"), "{:?}", seen[0]);
        assert_eq!(seen[0].1, 200);
    }

    #[tokio::test]
    async fn a_post_body_is_forwarded() {
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let (port, _recorder) = proxy(Scope::new()).await;

        let response = through_proxy(
            port,
            &format!(
                "POST http://127.0.0.1:{target}/submit HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\
                 Content-Length: 9\r\n\r\nkey=value"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    #[tokio::test]
    async fn out_of_scope_traffic_is_forwarded_but_flagged() {
        // A tester's own browsing must not be blocked — the proxy has to see a host
        // before that host can be added to scope.
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await;
        let (port, recorder) = proxy(Scope::new().include(ScopeRule::host("elsewhere.test"))).await;

        let response = through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert_eq!(
            recorder.seen.lock().unwrap()[0].2,
            ScopeDecision::AllowedOutOfScope
        );
    }

    #[tokio::test]
    async fn in_scope_traffic_is_recorded_as_such() {
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await;
        let (port, recorder) = proxy(Scope::new().include(ScopeRule::host("127.0.0.1"))).await;

        through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        assert_eq!(recorder.seen.lock().unwrap()[0].2, ScopeDecision::Allowed);
    }

    #[tokio::test]
    async fn hop_by_hop_headers_are_not_forwarded() {
        // Forwarding Connection would let a client dictate the upstream framing, which
        // hands over a smuggling primitive for free.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(String::new()));
        let sink = received.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 8192];
            let n = socket.read(&mut scratch).await.unwrap_or(0);
            *sink.lock().unwrap() = String::from_utf8_lossy(&scratch[..n]).into_owned();
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = socket.shutdown().await;
        });

        let (port, _recorder) = proxy(Scope::new()).await;
        through_proxy(
            port,
            &format!(
                "GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\
                 Connection: keep-alive\r\nX-Kept: yes\r\n\r\n"
            ),
        )
        .await;

        let upstream_saw = received.lock().unwrap().clone();
        // Covers Proxy-Connection too: it is addressed to this proxy, and an origin
        // that sees it is seeing a header the client never meant it to have. Found by
        // reading what a real target received during an M4 smoke test.
        assert!(
            !upstream_saw.to_lowercase().contains("connection:"),
            "hop-by-hop header leaked upstream: {upstream_saw}"
        );
        assert!(upstream_saw.contains("X-Kept: yes"), "{upstream_saw}");
    }

    #[tokio::test]
    async fn an_https_tunnel_is_intercepted_and_captured() {
        // The whole point of the proxy: see inside TLS, with the client none the
        // wiser because it trusts Hexora's CA.
        let target = https_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret").await;

        // The upstream uses a throwaway certificate, so verification is relaxed for
        // it exactly as a tester would for a staging box.
        let transport = TcpTransport::with_tls(hexora_http::TlsConfig::accept_any());
        let (port, recorder, ca) = proxy_with(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            Some(transport),
        )
        .await;

        let response = through_tunnel(
            port,
            &ca,
            "localhost",
            target,
            "GET /private HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .unwrap();

        assert!(response.contains("200 OK"), "{response}");
        assert!(response.ends_with("secret"), "{response}");

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the decrypted exchange must be captured");
        assert!(
            seen[0].0.starts_with("https://"),
            "an intercepted request must be recorded as https, never downgraded: {:?}",
            seen[0]
        );
        assert!(seen[0].0.contains("/private"), "{:?}", seen[0]);
    }

    #[tokio::test]
    async fn an_exempt_host_is_tunnelled_without_being_decrypted() {
        // Certificate-pinned apps break when intercepted, and some traffic — a
        // tester's own password manager, say — should never be decrypted at all.
        let target = https_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await;
        let (port, recorder, _ca) = proxy_with(
            Scope::new(),
            InterceptionPolicy::exempting(["localhost".to_string()]),
            None,
        )
        .await;

        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let connect =
            format!("CONNECT localhost:{target} HTTP/1.1\r\nHost: localhost:{target}\r\n\r\n");
        socket.write_all(connect.as_bytes()).await.unwrap();
        let mut established = [0u8; 128];
        let n = socket.read(&mut established).await.unwrap();
        assert!(
            String::from_utf8_lossy(&established[..n]).starts_with("HTTP/1.1 200"),
            "a tunnel is still established; it is simply not decrypted"
        );

        assert!(
            recorder.seen.lock().unwrap().is_empty(),
            "an exempt host must produce no decrypted exchange"
        );
    }

    #[tokio::test]
    async fn only_mode_leaves_other_hosts_alone() {
        let policy = InterceptionPolicy::only(["target.test".to_string()]);
        assert!(policy.intercepts("target.test"));
        assert!(!policy.intercepts("localhost"));
    }

    #[tokio::test]
    async fn an_unreachable_target_produces_a_gateway_error_not_a_dropped_connection() {
        // Bind then drop, so nothing is listening on that port.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let (port, _recorder) = proxy(Scope::new()).await;
        let response = through_proxy(
            port,
            &format!("GET http://127.0.0.1:{dead_port}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(
            response.to_lowercase().contains("could not reach"),
            "the browser deserves an explanation, not a spinner: {response}"
        );
    }

    #[tokio::test]
    async fn a_malformed_request_does_not_take_the_proxy_down() {
        let (port, _recorder) = proxy(Scope::new()).await;
        let _ = through_proxy(port, "GARBAGE\r\n\r\n").await;

        // The proxy must still serve the next client.
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let response = through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    }

    // ------------------------------------------------------- interception hooks

    /// An interceptor that applies a fixed verdict, so a test can assert the effect
    /// end to end rather than only on the hook in isolation.
    struct Fixed {
        request: Mutex<Option<RequestVerdict>>,
        response: Mutex<Option<ResponseVerdict>>,
    }

    impl Fixed {
        fn request(verdict: RequestVerdict) -> Arc<Self> {
            Arc::new(Self {
                request: Mutex::new(Some(verdict)),
                response: Mutex::new(None),
            })
        }

        fn response(verdict: ResponseVerdict) -> Arc<Self> {
            Arc::new(Self {
                request: Mutex::new(None),
                response: Mutex::new(Some(verdict)),
            })
        }
    }

    #[async_trait::async_trait]
    impl Interceptor for Arc<Fixed> {
        async fn on_request(&self, _request: &HttpRequest) -> RequestVerdict {
            self.request
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(RequestVerdict::Forward)
        }

        async fn on_response(
            &self,
            _request: &HttpRequest,
            _response: &HttpResponse,
        ) -> ResponseVerdict {
            self.response
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(ResponseVerdict::Forward)
        }
    }

    #[tokio::test]
    async fn an_intercepted_request_can_be_rewritten_before_it_leaves() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(String::new()));
        let sink = received.clone();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = vec![0u8; 8192];
            let n = socket.read(&mut scratch).await.unwrap_or(0);
            *sink.lock().unwrap() = String::from_utf8_lossy(&scratch[..n]).into_owned();
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
            let _ = socket.shutdown().await;
        });

        let mut edited =
            HttpRequest::get(HttpService::new("127.0.0.1", target, false), "/rewritten");
        edited.headers.set("X-Added-By-Hexora", "yes");
        let interceptor = Fixed::request(RequestVerdict::Replace(Box::new(edited)));

        let (port, _recorder, _ca) = proxy_full(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(interceptor)),
        )
        .await;

        through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/original HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        let upstream_saw = received.lock().unwrap().clone();
        assert!(
            upstream_saw.starts_with("GET /rewritten "),
            "the edit must reach the server: {upstream_saw}"
        );
        assert!(
            upstream_saw.contains("X-Added-By-Hexora: yes"),
            "{upstream_saw}"
        );
    }

    #[tokio::test]
    async fn a_dropped_request_never_reaches_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let reached = Arc::new(Mutex::new(false));
        let flag = reached.clone();
        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                *flag.lock().unwrap() = true;
            }
        });

        let (port, recorder, _ca) = proxy_full(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(Fixed::request(RequestVerdict::Drop))),
        )
        .await;

        through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !*reached.lock().unwrap(),
            "a dropped request must not be sent"
        );
        assert!(
            recorder.seen.lock().unwrap().is_empty(),
            "and there is no exchange to record"
        );
    }

    #[tokio::test]
    async fn a_request_can_be_answered_without_contacting_the_server() {
        // How a tester sees what a client does with a response the server never gave.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let reached = Arc::new(Mutex::new(false));
        let flag = reached.clone();
        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                *flag.lock().unwrap() = true;
            }
        });

        let mut canned = HttpResponse {
            status: 418,
            reason: Some("I am a teapot".to_string()),
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::from_static(b"brewed locally"),
            truncated: false,
        };
        canned.headers.set("X-Source", "hexora");

        let (port, _recorder, _ca) = proxy_full(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(Fixed::request(RequestVerdict::Respond(Box::new(
                canned,
            ))))),
        )
        .await;

        let response = through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 418"), "{response}");
        assert!(response.ends_with("brewed locally"), "{response}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !*reached.lock().unwrap(),
            "the server must not be contacted"
        );
    }

    #[tokio::test]
    async fn a_response_can_be_replaced_on_the_way_back() {
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\noriginal").await;

        let replacement = HttpResponse {
            status: 500,
            reason: Some("Replaced".to_string()),
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::from_static(b"substituted"),
            truncated: false,
        };

        let (port, recorder, _ca) = proxy_full(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(Fixed::response(ResponseVerdict::Replace(
                Box::new(replacement),
            )))),
        )
        .await;

        let response = through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 500"), "{response}");
        assert!(response.ends_with("substituted"), "{response}");
        assert_eq!(
            recorder.seen.lock().unwrap()[0].1,
            200,
            "what the server actually said is still what gets recorded"
        );
    }

    #[tokio::test]
    async fn a_dropped_response_is_still_recorded() {
        // The client is denied the answer; the evidence is not.
        let target = upstream(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;

        let (port, recorder, _ca) = proxy_full(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(Fixed::response(ResponseVerdict::Drop))),
        )
        .await;

        through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the exchange happened and must be evidence");
        assert_eq!(seen[0].1, 403);
    }

    #[tokio::test]
    async fn a_rewritten_request_is_still_scope_checked() {
        // A user editing the Host must not be able to steer traffic past the guard.
        // The check lives below the interceptor, so a replacement gets the same
        // treatment as anything else.
        let target = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let edited = HttpRequest::get(HttpService::new("127.0.0.1", target, false), "/edited");

        let (port, recorder, _ca) = proxy_full(
            Scope::new().include(ScopeRule::host("elsewhere.test")),
            InterceptionPolicy::intercept_all(),
            None,
            Some(Arc::new(Fixed::request(RequestVerdict::Replace(Box::new(
                edited,
            ))))),
        )
        .await;

        through_proxy(
            port,
            &format!("GET http://127.0.0.1:{target}/ HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n"),
        )
        .await;

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(
            seen[0].2,
            ScopeDecision::AllowedOutOfScope,
            "the edited destination must be judged, not the original"
        );
    }
    #[tokio::test]
    async fn the_default_bind_is_loopback() {
        // Defaults are what people actually run, and a proxy reachable from the
        // network is an open relay carrying a tester's credentials.
        assert!(ProxyConfig::default().bind.ip().is_loopback());
    }
}
