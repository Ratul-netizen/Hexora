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
use hexora_http::ws::{encode, Frame, FrameParser};
use hexora_http::{BodyStream, TcpTransport, TlsConfig};
use hexora_types::error::{HexoraError, NetworkError, ProtocolError, Result};
use hexora_types::http::{Header, Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;
use hexora_types::scope::Scope;
use hexora_types::ws::WsDirection;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::ca::CertificateAuthority;
use crate::hook::{Interceptor, PassThrough, RequestVerdict, ResponseVerdict, WsVerdict};
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

    /// Records the Upgrade exchange that opened a WebSocket, returning the stored request id
    /// its frames will reference. `None` means the session is not being captured — the relay
    /// still runs, it just records nothing. Default: not captured.
    ///
    /// Returned synchronously, unlike [`Self::observe`], because a frame cannot be recorded
    /// against a request that does not exist yet: the Upgrade must be stored, and its id
    /// known, before the first frame it carries.
    fn observe_websocket_open(
        &self,
        exchange: &Exchange,
        decision: ScopeDecision,
    ) -> Option<RequestId> {
        let _ = (exchange, decision);
        None
    }

    /// Records one captured WebSocket frame against an open session.
    fn observe_websocket_message(
        &self,
        request_id: RequestId,
        direction: WsDirection,
        opcode: u8,
        payload: &[u8],
    ) {
        let _ = (request_id, direction, opcode, payload);
    }
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
    /// The TLS settings for an upstream connection the WebSocket relay opens itself.
    upstream_tls: TlsConfig,
}

/// A byte stream the relay can own, whatever its concrete type (plain or TLS).
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

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

        let upstream_tls = transport.tls_config().clone();
        Ok(Self {
            listener,
            transport: Arc::new(ScopeGuard::new(transport, scope)),
            observer,
            limits: config.limits,
            interception: config.interception,
            ca,
            // Forwarding everything until a tester turns interception on.
            interceptor: Arc::new(PassThrough),
            upstream_tls,
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
                upstream_tls: self.upstream_tls.clone(),
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
    upstream_tls: TlsConfig,
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

/// Forwards one request upstream and writes the response back to an HTTP/1.x client.
async fn forward<S: AsyncWrite + Unpin>(
    client: &mut S,
    request: HttpRequest,
    context: &ConnectionContext,
) -> Result<()> {
    match produce(request, context).await {
        Ok(Served::Respond(response)) => write_response(client, &response).await,
        Ok(Served::Nothing) => Ok(()),
        Err(e) => {
            // The browser is waiting. Telling it what went wrong is far more useful
            // than dropping the connection and leaving a spinner.
            let message = format!("Hexora could not reach the target: {e}");
            write_simple(client, 502, "Bad Gateway", message.as_bytes()).await?;
            Err(e)
        }
    }
}

/// What the proxy should return to the client for one request.
enum Served {
    /// Send this response.
    Respond(HttpResponse),
    /// Send nothing — the request or response was dropped by the interceptor.
    Nothing,
}

/// Processes one request: interceptor hooks, scope check, upstream send, and observation.
///
/// This is the whole of what the proxy *does* with a request, kept apart from how the
/// answer is written so the HTTP/1.x and HTTP/2 client paths share one implementation and
/// cannot drift. The interceptor is consulted twice — once before the request leaves, once
/// before the response is returned — exactly as it always has been.
async fn produce(request: HttpRequest, context: &ConnectionContext) -> Result<Served> {
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
            return Ok(Served::Nothing);
        }

        // Answered without going upstream, which is how a tester sees what a client
        // does with a response the server never sent.
        RequestVerdict::Respond(response) => {
            tracing::debug!(url = %request.url(), "request answered by the interceptor");
            return Ok(Served::Respond(*response));
        }
    };

    let options = SendOptions::interactive(Origin::Proxy);
    let decision = context.transport.decide(&request, &options);

    let exchange = context.transport.send(request, options).await?;
    let verdict = context
        .interceptor
        .on_response(&exchange.request, &exchange.response)
        .await;

    // The exchange is recorded exactly as the server answered it, whatever the client is
    // subsequently shown. A tester's substitution is their own action, not the server's
    // behaviour, and recording it as the latter would put a fabricated response into the
    // evidence behind a finding.
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

    note_protocol_translation(&exchange);

    context.observer.observe(&exchange, decision);

    Ok(match to_client {
        Some(response) => Served::Respond(response),
        None => Served::Nothing,
    })
}

/// Whether a request head is a WebSocket upgrade.
fn is_websocket_upgrade(head: &RequestHead) -> bool {
    head.headers
        .get("Upgrade")
        .map(|h| h.value_lossy().eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Relays an established WebSocket both ways, recording every frame that passes.
///
/// The bytes are forwarded **verbatim** — masked exactly as they arrived, nothing
/// re-serialised — so the wire is preserved; a copy is fed to a per-direction frame parser
/// only to observe it. Each direction runs concurrently; when either side closes, the
/// session ends. `request_id` anchors captured frames to the Upgrade exchange, or is `None`
/// when the session is not being recorded.
#[allow(clippy::too_many_arguments)]
async fn relay_websocket<C, U>(
    client: C,
    upstream: U,
    request_id: Option<RequestId>,
    observer: Arc<dyn ExchangeObserver>,
    interceptor: Arc<dyn Interceptor>,
    limits: Limits,
    // Bytes already read from each side that belong to the WebSocket stream — frames that
    // arrived in the same segment as the handshake. Forwarded and captured before the relay
    // reads any more, so nothing is missed.
    client_seed: Vec<u8>,
    upstream_seed: Vec<u8>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let cap = limits.max_body_bytes.min(usize::MAX as u64) as usize;

    let to_server = pump(
        &mut client_read,
        &mut upstream_write,
        WsDirection::ClientToServer,
        request_id,
        observer.clone(),
        interceptor.clone(),
        cap,
        client_seed,
    );
    let to_client = pump(
        &mut upstream_read,
        &mut client_write,
        WsDirection::ServerToClient,
        request_id,
        observer.clone(),
        interceptor.clone(),
        cap,
        upstream_seed,
    );

    // Either side closing ends the session — a WebSocket is symmetric, and once one half is
    // gone there is nothing left to relay.
    tokio::select! {
        result = to_server => result,
        result = to_client => result,
    }
}

/// Copies one direction of a WebSocket, recording every frame — and, when the interceptor
/// wants them, letting it forward, replace or drop each one.
///
/// Two modes. With no WebSocket interception the bytes are forwarded exactly as they arrived
/// and only observed, so the wire is preserved. With interception on, each frame is parsed,
/// put to the interceptor, and re-encoded from its verdict — a client frame re-masked, a
/// server frame not — which is the cost of being able to change or drop one.
#[allow(clippy::too_many_arguments)]
async fn pump<R, W>(
    read: &mut R,
    write: &mut W,
    direction: WsDirection,
    request_id: Option<RequestId>,
    observer: Arc<dyn ExchangeObserver>,
    interceptor: Arc<dyn Interceptor>,
    cap: usize,
    seed: Vec<u8>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let intercepting = interceptor.intercepts_websocket();
    let mut parser = FrameParser::new(cap);
    let mut buf = vec![0u8; 16 * 1024];
    let mut chunk = seed;

    loop {
        if intercepting {
            // Interception owns the forwarding: parse whole frames, decide, re-encode.
            parser.push(&chunk);
            while let Ok(Some(frame)) = parser.next_frame() {
                let payload = match interceptor
                    .on_websocket_message(direction, frame.opcode.as_u8(), &frame.payload)
                    .await
                {
                    WsVerdict::Forward => frame.payload.clone(),
                    WsVerdict::Replace(new) => new,
                    WsVerdict::Drop => continue, // the peer never sees it, and it is not recorded
                };
                let mask = matches!(direction, WsDirection::ClientToServer).then(random_mask);
                let out = encode(
                    &Frame {
                        fin: frame.fin,
                        rsv1: frame.rsv1,
                        opcode: frame.opcode,
                        masked: mask.is_some(),
                        payload: payload.clone(),
                    },
                    mask,
                );
                write
                    .write_all(&out)
                    .await
                    .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
                write.flush().await.ok();
                if let Some(id) = request_id {
                    observer.observe_websocket_message(
                        id,
                        direction,
                        frame.opcode.as_u8(),
                        &payload,
                    );
                }
            }
        } else {
            // Pass-through: forward verbatim, then observe. Re-framing would make the relay
            // the thing under test.
            write
                .write_all(&chunk)
                .await
                .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
            write.flush().await.ok();
            parser.push(&chunk);
            while let Ok(Some(frame)) = parser.next_frame() {
                if let Some(id) = request_id {
                    observer.observe_websocket_message(
                        id,
                        direction,
                        frame.opcode.as_u8(),
                        &frame.payload,
                    );
                }
            }
        }

        let n = read
            .read(&mut buf)
            .await
            .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
        if n == 0 {
            return Ok(()); // the peer closed this half
        }
        chunk = buf[..n].to_vec();
    }
}

/// A per-frame masking key for a re-encoded client frame.
///
/// A relay that re-masks does not need cryptographic unpredictability — the server unmasks
/// with whatever key the frame carries — so this is a cheap time-derived key, used only when
/// interception rewrites a client frame.
fn random_mask() -> [u8; 4] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ nanos.rotate_left(13)).to_ne_bytes()
}

/// Carries an intercepted WebSocket upgrade through to the origin and relays the session.
///
/// The handshake is forwarded with `permessage-deflate` removed, so every frame is
/// uncompressed and legible (real deflate support is WS.e); when the origin answers `101`,
/// the Upgrade exchange is recorded — synchronously, so its id exists before any frame — and
/// the connection becomes a captured bidirectional relay. A server that declines the upgrade
/// gets its response passed straight back to the client.
async fn relay_ws_tunnel<C>(
    mut client: C,
    head: &RequestHead,
    client_prefix: BytesMut,
    service: &HttpService,
    context: &ConnectionContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = serialize_ws_handshake(head);

    let tcp = TcpStream::connect((service.host.as_str(), service.port))
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    let mut upstream: Box<dyn Duplex> = if service.secure {
        let (stream, _tls) =
            hexora_http::tls::handshake(tcp, &service.host, &context.upstream_tls, &context.limits)
                .await?;
        Box::new(stream)
    } else {
        Box::new(tcp)
    };

    upstream
        .write_all(&handshake)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    upstream.flush().await.ok();

    let (response_head, upstream_prefix) =
        read_response_head(&mut upstream, &context.limits).await?;
    let status = parse_status_code(&response_head);

    // The server's answer goes back to the client either way — it is what the client's
    // handshake is waiting for.
    client
        .write_all(&response_head)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    client.flush().await.ok();

    if status != Some(101) {
        // The origin refused the upgrade; hand back anything already buffered and stop.
        if !upstream_prefix.is_empty() {
            let _ = client.write_all(&upstream_prefix).await;
        }
        return Ok(());
    }

    // Record the Upgrade exchange, and anchor the session's frames to it. Built directly
    // from the head so the WebSocket headers survive into the evidence rather than being
    // stripped as hop-by-hop.
    let mut headers = Headers::new();
    for header in head.headers.iter() {
        headers.append(header.clone());
    }
    let request = HttpRequest {
        service: service.clone(),
        method: head.method.clone(),
        path: if head.target.path().is_empty() {
            "/".to_string()
        } else {
            head.target.path().to_string()
        },
        version: head.version,
        headers,
        body: bytes::Bytes::new(),
    };
    let response = build_ws_response(&response_head);
    let options = SendOptions::interactive(Origin::Proxy);
    let decision = context.transport.decide(&request, &options);
    let exchange = Exchange {
        request,
        response,
        encoded_body: None,
        content_encoding: None,
        raw_request: None,
        duration: std::time::Duration::ZERO,
        tls: None,
    };
    let request_id = context.observer.observe_websocket_open(&exchange, decision);

    relay_websocket(
        client,
        upstream,
        request_id,
        context.observer.clone(),
        context.interceptor.clone(),
        context.limits.clone(),
        client_prefix.to_vec(),
        upstream_prefix.to_vec(),
    )
    .await
}

/// Serialises a WebSocket handshake request to forward upstream, stripping
/// `permessage-deflate` so the session stays uncompressed and legible (WS.a).
///
/// Unlike an ordinary proxied request, the connection-specific headers are *kept* — a
/// WebSocket handshake is `Connection: Upgrade` plus `Upgrade: websocket`, and dropping them
/// as hop-by-hop would turn the upgrade into an ordinary request. Only the compression
/// extension offer is removed.
fn serialize_ws_handshake(head: &RequestHead) -> Vec<u8> {
    let path = if head.target.path().is_empty() {
        "/"
    } else {
        head.target.path()
    };
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, path).into_bytes();
    for header in head.headers.iter() {
        if header.is("Sec-WebSocket-Extensions") || header.is("Proxy-Connection") {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&header.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Reads an HTTP response head (through the blank line) from a stream, returning the head
/// bytes and any bytes read past it — early WebSocket frames that arrived in the same read.
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    limits: &Limits,
) -> Result<(Vec<u8>, BytesMut)> {
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let deadline = tokio::time::Instant::now() + limits.read_head_timeout;
    loop {
        if let Some(end) = find_head_end(&buf) {
            let rest = buf.split_off(end);
            return Ok((buf.to_vec(), rest));
        }
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
            .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
        buf.truncate(before + read);
        if read == 0 {
            return Err(HexoraError::Protocol(ProtocolError::Malformed {
                protocol: "HTTP/1.1",
                reason: "the origin closed the connection during the WebSocket handshake"
                    .to_string(),
            }));
        }
    }
}

/// Reads the status code from a response head's first line.
fn parse_status_code(head: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(head).ok()?;
    let first = text.lines().next()?;
    first.split_whitespace().nth(1)?.parse().ok()
}

/// Builds the response model for a recorded WebSocket upgrade from the `101` head.
fn build_ws_response(head: &[u8]) -> HttpResponse {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(101);
    let reason = status_line.splitn(3, ' ').nth(2).map(|r| r.to_string());

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(": ") {
            headers.append(Header::new(name, value));
        }
    }

    HttpResponse {
        status,
        reason,
        version: HttpVersion::Http11,
        headers,
        body: bytes::Bytes::new(),
        truncated: false,
    }
}

/// Records, explicitly, when the client and the origin spoke different HTTP versions.
///
/// The proxy forwards a request over whatever the origin negotiates, so a browser's HTTP/2
/// request can reach an HTTP/1.x origin — a **downgrade**. That is not a mere plumbing
/// detail: h2→h1 downgrade is a request-smuggling class, because constructs HTTP/2's binary
/// framing carries safely (a header value with an embedded CR/LF, a `Content-Length` that
/// disagrees with the framed body) become a second request, or a desync, once serialised
/// onto an HTTP/1.x wire. The exchange already preserves both versions and the exact
/// request bytes, so the evidence is there; this makes the translation loud and names the
/// primitives a downgrade would carry, so it reads as a lead rather than a log line nobody
/// looks at.
fn note_protocol_translation(exchange: &Exchange) {
    let from = exchange.request.version;
    let to = exchange.response.version;
    if from == to {
        return;
    }

    tracing::info!(
        url = %exchange.request.url(),
        %from,
        %to,
        "the client and the origin spoke different HTTP versions"
    );

    if from == HttpVersion::Http2 && to == HttpVersion::Http11 {
        let signals = downgrade_smuggling_signals(&exchange.request);
        if !signals.is_empty() {
            // At warn, because this is a finding waiting to be raised: an h2 request that
            // an h1 back-end may frame differently is the whole of an h2->h1 desync.
            tracing::warn!(
                url = %exchange.request.url(),
                ?signals,
                "an HTTP/2 request downgraded to HTTP/1.1 carries a request-smuggling primitive"
            );
        }
    }
}

/// The request-smuggling primitives that survive an h2→h1 downgrade.
///
/// A conforming HTTP/2 client cannot usually produce these — the `h2` crate and `http`
/// types reject a header value with a CR/LF — so today this fires mainly for a request the
/// tester crafted at the frame level (M5.1e). It is written now so the surface exists and
/// is tested: the moment a downgrade can carry one of these, the proxy already names it.
fn downgrade_smuggling_signals(request: &HttpRequest) -> Vec<String> {
    let mut signals = Vec::new();

    for header in request.headers.iter() {
        let name_bad = header
            .name
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0);
        let value_bad = header
            .value
            .iter()
            .any(|&b| b == b'\r' || b == b'\n' || b == 0);
        if name_bad || value_bad {
            signals.push(format!(
                "header `{}` carries a CR, LF or NUL that becomes a request boundary once \
                 serialised to HTTP/1.1",
                header.name
            ));
        }
    }

    // A Content-Length that disagrees with the framed body is the h2.CL desync: HTTP/2
    // frames the body itself, so the header is advisory, but an h1 back-end believes it.
    if let Some(header) = request.headers.get("Content-Length") {
        if let Ok(declared) = header.value_lossy().trim().parse::<usize>() {
            if declared != request.body.len() {
                signals.push(format!(
                    "Content-Length {declared} disagrees with the {}-byte body; an HTTP/1.1 \
                     back-end may frame the request differently (h2.CL desync)",
                    request.body.len()
                ));
            }
        }
    }

    signals
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

    // Offer h2 as well as HTTP/1.1: the proxy can now be an HTTP/2 server to the browser
    // (M5.1c). Which one runs is decided by what the client negotiates.
    let config = intercept::server_config_for(
        &context.ca,
        &service.host,
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
    )?;
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

    let negotiated_h2 = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p == b"h2")
        .unwrap_or(false);

    if negotiated_h2 {
        serve_h2_tunnel(tls, service, context).await?;
        return Ok(TunnelOutcome::Intercepted);
    }

    // Inside the tunnel the client speaks ordinary HTTP with origin-form targets, so
    // the authority comes from the CONNECT line rather than from the request.
    let (inner_head, body_prefix) = read_request_head(&mut tls, &context.limits).await?;
    report_request_signals(&inner_head);

    if is_websocket_upgrade(&inner_head) {
        relay_ws_tunnel(tls, &inner_head, body_prefix, &service, &context).await?;
        return Ok(TunnelOutcome::Intercepted);
    }

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

/// Serves an intercepted HTTP/2 tunnel: the proxy is the h2 server to the browser.
///
/// The browser multiplexes many requests as concurrent streams over this one connection,
/// so each accepted stream is handled on its own task — that is the whole difference from
/// the HTTP/1.x path, which sees one request per tunnel. The shared [`ConnectionContext`]
/// is behind an `Arc` so every stream sees the same scope, interceptor and capture. The
/// exchanges those streams produce are recorded through the observer, whose write path is
/// already concurrency-safe.
async fn serve_h2_tunnel<S>(tls: S, service: HttpService, context: ConnectionContext) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = ::h2::server::handshake(tls)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(format!("http/2 handshake: {e}"))))?;

    let context = Arc::new(context);
    let service = Arc::new(service);

    while let Some(accepted) = connection.accept().await {
        let (request, responder) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                // A connection-level error ends the tunnel; a client that goes away is
                // ordinary and not worth more than a debug line.
                tracing::debug!(error = %e, "http/2 tunnel ended");
                break;
            }
        };

        let context = context.clone();
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_h2_stream(request, responder, &service, &context).await {
                tracing::debug!(error = %e, "http/2 stream failed");
            }
        });
    }

    Ok(())
}

/// Handles one HTTP/2 stream from the browser: build the request, process it exactly as
/// the HTTP/1.x path does, and send the answer back on the stream.
async fn serve_h2_stream(
    request: http::Request<::h2::RecvStream>,
    mut responder: ::h2::server::SendResponse<bytes::Bytes>,
    service: &HttpService,
    context: &ConnectionContext,
) -> Result<()> {
    let request = build_h2_upstream_request(request, service, &context.limits).await?;

    match produce(request, context).await {
        Ok(Served::Respond(response)) => send_h2_response(&mut responder, &response),
        // A dropped request or response resets the stream — the browser sees nothing was
        // returned, which is what "drop" means.
        Ok(Served::Nothing) => {
            responder.send_reset(::h2::Reason::CANCEL);
            Ok(())
        }
        Err(e) => {
            let message = format!("Hexora could not reach the target: {e}");
            let response = HttpResponse {
                status: 502,
                reason: None,
                version: HttpVersion::Http2,
                headers: {
                    let mut headers = hexora_types::http::Headers::new();
                    headers.set("Content-Type", "text/plain; charset=utf-8");
                    headers
                },
                body: bytes::Bytes::from(message.into_bytes()),
                truncated: false,
            };
            send_h2_response(&mut responder, &response)
        }
    }
}

/// Builds the upstream request from an HTTP/2 stream's head and body.
///
/// The connection target comes from the `CONNECT` authority, not the request, for the same
/// reason as the HTTP/1.x path: an origin-form target carries no scheme and trusting the
/// request to say where the socket goes is how an interceptor gets talked into sending
/// somewhere it should not. The version is recorded as HTTP/2 — that is how it arrived.
async fn build_h2_upstream_request(
    request: http::Request<::h2::RecvStream>,
    service: &HttpService,
    limits: &Limits,
) -> Result<HttpRequest> {
    let (parts, mut body) = request.into_parts();

    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_string());

    let mut headers = hexora_types::http::Headers::new();
    for (name, value) in parts.headers.iter() {
        if HOP_BY_HOP
            .iter()
            .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        headers.append(hexora_types::http::Header {
            name: name.as_str().to_string(),
            value: bytes::Bytes::copy_from_slice(value.as_bytes()),
        });
    }
    // HTTP/2 carries the authority as a pseudo-header, not a `Host`. The upstream request
    // may go out over HTTP/1.1, which needs one, so it is reconstructed here.
    if headers.count("Host") == 0 {
        headers.set("Host", service.authority());
    }

    // Read the request body, bounded the same way every other body is.
    let mut buf = BytesMut::new();
    let mut truncated = false;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| {
            HexoraError::Network(NetworkError::Io(format!("http/2 request body: {e}")))
        })?;
        let _ = body.flow_control().release_capacity(chunk.len());
        let remaining = limits.max_body_bytes.saturating_sub(buf.len() as u64);
        if (chunk.len() as u64) > remaining {
            buf.extend_from_slice(&chunk[..remaining as usize]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    if truncated {
        tracing::warn!("an HTTP/2 request body exceeded the size limit and was truncated");
    }

    Ok(HttpRequest {
        service: HttpService::new(&service.host, service.port, true),
        method: parts.method.as_str().to_string(),
        path,
        version: HttpVersion::Http2,
        headers,
        body: buf.freeze(),
    })
}

/// Sends a response back to the browser on an HTTP/2 stream.
///
/// The body handed back has already been transfer- and content-decoded, so the original
/// framing headers would now be lies — `Content-Length`, `Content-Encoding` and the
/// hop-by-hop set are dropped, exactly as the HTTP/1.x writer drops them, and h2 frames the
/// body itself.
fn send_h2_response(
    responder: &mut ::h2::server::SendResponse<bytes::Bytes>,
    response: &HttpResponse,
) -> Result<()> {
    let mut builder = http::Response::builder().status(response.status);
    for header in response.headers.iter() {
        let name = &header.name;
        if HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
            || name.eq_ignore_ascii_case("Content-Length")
            || name.eq_ignore_ascii_case("Content-Encoding")
        {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(lower.as_bytes()),
            http::header::HeaderValue::from_bytes(&header.value),
        ) {
            builder = builder.header(n, v);
        }
    }

    let http_response = builder.body(()).map_err(|e| {
        HexoraError::Network(NetworkError::Io(format!("http/2 response head: {e}")))
    })?;

    let has_body = !response.body.is_empty();
    let mut stream = responder
        .send_response(http_response, !has_body)
        .map_err(|e| {
            HexoraError::Network(NetworkError::Io(format!("http/2 send response: {e}")))
        })?;

    if has_body {
        stream.send_data(response.body.clone(), true).map_err(|e| {
            HexoraError::Network(NetworkError::Io(format!("http/2 send body: {e}")))
        })?;
    }
    Ok(())
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

    /// One observed exchange: url, status, scope decision, and the client and origin protocol
    /// versions (kept so a downgrade can be asserted on).
    type Seen = (String, u16, ScopeDecision, HttpVersion, HttpVersion);

    /// Records what the proxy observed, so tests can assert on capture.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Seen>>,
    }

    impl ExchangeObserver for Arc<Recorder> {
        fn observe(&self, exchange: &Exchange, decision: ScopeDecision) {
            self.seen.lock().unwrap().push((
                exchange.request.url(),
                exchange.response.status,
                decision,
                exchange.request.version,
                exchange.response.version,
            ));
        }
    }

    /// Records the WebSocket frames the relay observed.
    #[derive(Default)]
    struct WsRecorder {
        messages: Mutex<Vec<(WsDirection, u8, Vec<u8>)>>,
    }

    impl ExchangeObserver for Arc<WsRecorder> {
        fn observe(&self, _exchange: &Exchange, _decision: ScopeDecision) {}
        fn observe_websocket_message(
            &self,
            _request_id: RequestId,
            direction: WsDirection,
            opcode: u8,
            payload: &[u8],
        ) {
            self.messages
                .lock()
                .unwrap()
                .push((direction, opcode, payload.to_vec()));
        }
    }

    #[tokio::test]
    async fn the_relay_forwards_both_ways_verbatim_and_captures_each_frame() {
        use hexora_http::ws::{encode, Frame, Opcode};

        let (mut client_test, client_relay) = tokio::io::duplex(8192);
        let (upstream_relay, mut upstream_test) = tokio::io::duplex(8192);

        let recorder = Arc::new(WsRecorder::default());
        let observer: Arc<dyn ExchangeObserver> = Arc::new(recorder.clone());
        let request_id = RequestId::new();

        tokio::spawn(relay_websocket(
            client_relay,
            upstream_relay,
            Some(request_id),
            observer,
            Arc::new(PassThrough),
            Limits::default(),
            Vec::new(),
            Vec::new(),
        ));

        // Client → server: a masked text frame, as a browser sends.
        let client_frame = encode(
            &Frame {
                fin: true,
                rsv1: false,
                opcode: Opcode::Text,
                masked: true,
                payload: b"hi server".to_vec(),
            },
            Some([0x11, 0x22, 0x33, 0x44]),
        );
        client_test.write_all(&client_frame).await.unwrap();

        // The relay forwards the client's bytes to the upstream verbatim, mask and all.
        let mut forwarded = vec![0u8; client_frame.len()];
        upstream_test.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(
            forwarded, client_frame,
            "client frame relayed byte for byte"
        );

        // Server → client: an unmasked text frame back.
        let server_frame = encode(
            &Frame {
                fin: true,
                rsv1: false,
                opcode: Opcode::Text,
                masked: false,
                payload: b"hi client".to_vec(),
            },
            None,
        );
        upstream_test.write_all(&server_frame).await.unwrap();
        let mut back = vec![0u8; server_frame.len()];
        client_test.read_exact(&mut back).await.unwrap();
        assert_eq!(back, server_frame, "server frame relayed byte for byte");

        // Both frames were captured, with the payload unmasked and the direction right.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if recorder.messages.lock().unwrap().len() >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "frames were not captured"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let messages = recorder.messages.lock().unwrap();
        assert_eq!(
            messages[0],
            (WsDirection::ClientToServer, 0x1, b"hi server".to_vec())
        );
        assert_eq!(
            messages[1],
            (WsDirection::ServerToClient, 0x1, b"hi client".to_vec())
        );
    }

    /// Replaces every client message and drops every server message.
    struct WsEditor;

    #[async_trait::async_trait]
    impl Interceptor for WsEditor {
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
        fn intercepts_websocket(&self) -> bool {
            true
        }
        async fn on_websocket_message(
            &self,
            direction: WsDirection,
            _opcode: u8,
            _payload: &[u8],
        ) -> WsVerdict {
            match direction {
                WsDirection::ClientToServer => WsVerdict::Replace(b"EDITED".to_vec()),
                WsDirection::ServerToClient => WsVerdict::Drop,
            }
        }
    }

    #[tokio::test]
    async fn interception_replaces_a_client_frame_and_drops_a_server_frame() {
        use hexora_http::ws::{encode, Frame, FrameParser, Opcode};

        let (mut client_test, client_relay) = tokio::io::duplex(8192);
        let (upstream_relay, mut upstream_test) = tokio::io::duplex(8192);
        let observer: Arc<dyn ExchangeObserver> = Arc::new(NoObserver);

        tokio::spawn(relay_websocket(
            client_relay,
            upstream_relay,
            None,
            observer,
            Arc::new(WsEditor),
            Limits::default(),
            Vec::new(),
            Vec::new(),
        ));

        // Client sends "original"; the interceptor rewrites it to "EDITED".
        let client_frame = encode(
            &Frame {
                fin: true,
                rsv1: false,
                opcode: Opcode::Text,
                masked: true,
                payload: b"original".to_vec(),
            },
            Some([9, 8, 7, 6]),
        );
        client_test.write_all(&client_frame).await.unwrap();

        let mut parser = FrameParser::new(1 << 16);
        let mut buf = vec![0u8; 128];
        let n = upstream_test.read(&mut buf).await.unwrap();
        parser.push(&buf[..n]);
        let forwarded = parser.next_frame().unwrap().unwrap();
        assert_eq!(
            forwarded.payload, b"EDITED",
            "the client frame was rewritten"
        );
        assert!(forwarded.masked, "a re-encoded client frame is re-masked");

        // Server sends a frame; it is dropped and never reaches the client.
        let server_frame = encode(
            &Frame {
                fin: true,
                rsv1: false,
                opcode: Opcode::Text,
                masked: false,
                payload: b"secret".to_vec(),
            },
            None,
        );
        upstream_test.write_all(&server_frame).await.unwrap();

        let got = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client_test.read(&mut buf),
        )
        .await;
        match got {
            Err(_) => {}    // timed out: nothing forwarded — the drop worked
            Ok(Ok(0)) => {} // closed, also fine
            Ok(Ok(n)) => panic!("a dropped server frame reached the client: {n} bytes"),
            Ok(Err(_)) => {}
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

    /// Speaks CONNECT, negotiates HTTP/2 in the tunnel, and sends every path as a
    /// concurrent stream over the one connection — a browser opening h2 to the proxy.
    ///
    /// Returns each stream's status and body, and asserts h2 was actually negotiated so a
    /// silent fall back to HTTP/1.1 cannot make the test pass for the wrong reason.
    async fn through_tunnel_h2(
        proxy_port: u16,
        ca: &CertificateAuthority,
        target_host: &str,
        target_port: u16,
        paths: &[&str],
    ) -> Vec<(u16, String)> {
        let mut socket = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let connect = format!(
            "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        );
        socket.write_all(connect.as_bytes()).await.unwrap();
        let mut established = [0u8; 128];
        let n = socket.read(&mut established).await.unwrap();
        assert!(String::from_utf8_lossy(&established[..n]).starts_with("HTTP/1.1 200"));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.certificate_der().clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(target_host.to_string()).unwrap();
        let tls = connector.connect(name, socket).await.unwrap();
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"h2".as_ref()),
            "the proxy must negotiate h2 with a client that offers it"
        );

        let (send_request, connection) = ::h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        // Open every stream first, then read them, so they are genuinely concurrent.
        let mut futures = Vec::new();
        for path in paths {
            let sr = send_request.clone();
            let mut sr = sr.ready().await.unwrap();
            let request = http::Request::builder()
                .method("GET")
                .uri(format!("https://{target_host}{path}"))
                .body(())
                .unwrap();
            let (response, _) = sr.send_request(request, true).unwrap();
            futures.push(response);
        }

        let mut out = Vec::new();
        for response in futures {
            let response = response.await.unwrap();
            let status = response.status().as_u16();
            let mut body = response.into_body();
            let mut buf = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                let _ = body.flow_control().release_capacity(chunk.len());
                buf.extend_from_slice(&chunk);
            }
            out.push((status, String::from_utf8_lossy(&buf).into_owned()));
        }
        out
    }

    #[tokio::test]
    async fn the_proxy_serves_http2_to_the_browser_and_captures_every_stream() {
        let target = https_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;

        // The upstream authority is what the proxy connects to; the CONNECT names a host
        // whose leaf the CA can mint and whose name the upstream cert carries.
        let interception = InterceptionPolicy::intercept_all();
        let transport = TcpTransport::with_tls(hexora_http::TlsConfig::accept_any());
        let (port, recorder, ca) = proxy_with(Scope::new(), interception, Some(transport)).await;

        // The CONNECT authority (localhost:<upstream port>) is where the proxy forwards;
        // the upstream cert is for "localhost", accepted because the transport is accept-any.
        let responses =
            through_tunnel_h2(port, &ca, "localhost", target, &["/a", "/b", "/c"]).await;

        // Every stream got an answer over one h2 connection.
        assert_eq!(responses.len(), 3);
        for (status, body) in &responses {
            assert_eq!(*status, 200, "each h2 stream must be answered");
            assert_eq!(body, "hello");
        }

        // Each stream was demultiplexed into its own captured exchange, recorded as https.
        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 3, "each h2 stream must be captured separately");
        assert!(seen
            .iter()
            .all(|(url, status, ..)| url.starts_with("https://") && *status == 200));
        let paths: std::collections::HashSet<_> =
            seen.iter().map(|(url, ..)| url.clone()).collect();
        assert_eq!(
            paths.len(),
            3,
            "the three streams are three distinct requests"
        );

        let _ = target; // upstream handle kept alive for the duration of the test
    }

    /// An HTTP/2 upstream over TLS that answers every stream with `200` and `body`.
    async fn h2_upstream(body: &'static [u8]) -> u16 {
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
        config.alpn_protocols = vec![b"h2".to_vec()];

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
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let Ok(mut connection) = ::h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((request, mut responder))) = connection.accept().await {
                        let mut request_body = request.into_body();
                        while let Some(chunk) = request_body.data().await {
                            if let Ok(chunk) = chunk {
                                let _ = request_body.flow_control().release_capacity(chunk.len());
                            }
                        }
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = responder.send_response(response, false) {
                            let _ = send.send_data(bytes::Bytes::copy_from_slice(body), true);
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn a_downgrade_names_the_smuggling_primitives_it_would_carry() {
        // A clean request carries nothing.
        let clean = HttpRequest::get(HttpService::new("localhost", 443, true), "/");
        assert!(downgrade_smuggling_signals(&clean).is_empty());

        // A header value with an embedded CR/LF is a request-splitting primitive.
        let mut splitting = HttpRequest::get(HttpService::new("localhost", 443, true), "/");
        splitting.headers.append(hexora_types::http::Header {
            name: "X-Note".to_string(),
            value: bytes::Bytes::from_static(b"a\r\nInjected: 1"),
        });
        let signals = downgrade_smuggling_signals(&splitting);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].contains("X-Note"), "{signals:?}");

        // A Content-Length that disagrees with the body is the h2.CL desync.
        let mut desync = HttpRequest {
            body: bytes::Bytes::from_static(b"hello"),
            ..HttpRequest::get(HttpService::new("localhost", 443, true), "/")
        };
        desync.headers.set("Content-Length", "9999");
        let signals = downgrade_smuggling_signals(&desync);
        assert!(
            signals.iter().any(|s| s.contains("h2.CL desync")),
            "{signals:?}"
        );
    }

    #[tokio::test]
    async fn an_h2_request_to_an_h2_origin_is_forwarded_over_h2_not_downgraded() {
        let target = h2_upstream(b"hello").await;

        // Upstream h2 is enabled, as it is for the real proxy since M5.1d.
        let transport = TcpTransport::with_tls(hexora_http::TlsConfig::accept_any()).http2(true);
        let (port, recorder, ca) = proxy_with(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            Some(transport),
        )
        .await;

        let responses = through_tunnel_h2(port, &ca, "localhost", target, &["/a"]).await;
        assert_eq!(responses, vec![(200, "hello".to_string())]);

        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].3, HttpVersion::Http2, "the browser spoke h2");
        assert_eq!(
            seen[0].4,
            HttpVersion::Http2,
            "an h2 origin must be reached over h2, not downgraded"
        );
    }

    #[tokio::test]
    async fn an_h2_request_to_an_h1_origin_is_recorded_as_a_downgrade() {
        let target = https_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;

        let transport = TcpTransport::with_tls(hexora_http::TlsConfig::accept_any()).http2(true);
        let (port, recorder, ca) = proxy_with(
            Scope::new(),
            InterceptionPolicy::intercept_all(),
            Some(transport),
        )
        .await;

        let responses = through_tunnel_h2(port, &ca, "localhost", target, &["/a"]).await;
        assert_eq!(responses, vec![(200, "hello".to_string())]);

        // The evidence shows both halves of the translation: the browser spoke h2, the
        // origin answered h1. That difference is the downgrade.
        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].3, HttpVersion::Http2);
        assert_eq!(seen[0].4, HttpVersion::Http11);
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
