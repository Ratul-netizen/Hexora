//! # hexora-browser
//!
//! Driving the browser already on the machine over the **Chrome DevTools Protocol** (M18),
//! rather than shipping a 150 MB Chromium. This is **M18.a — the CDP transport**: the socket
//! and the message loop everything else rides.
//!
//! ## What CDP is, in one paragraph
//!
//! A DevTools-enabled browser exposes an HTTP endpoint (`/json/version`, `/json/list`) that
//! names a **WebSocket** URL; commands and their responses, and a stream of events, are JSON
//! messages over that socket. A command carries an `id`; its response carries the same `id`;
//! an event carries a `method` and no `id`. So the client's whole job is: send a command, read
//! frames until the matching `id` comes back, and buffer the events seen along the way.
//!
//! ## It reuses the WebSocket client (WS.d)
//!
//! CDP rides a WebSocket, and Hexora already has a hand-rolled WebSocket client
//! ([`hexora_http::ws::WsConnection`]). This layer is thin on purpose: endpoint discovery, an
//! id counter, and the classify-and-route loop. Launching the browser is M18.b; navigating and
//! capturing under the scope guard is M18.c.
//!
//! ## Honest about the dependency
//!
//! Nothing here ships a browser. If neither Chrome nor Edge is installed, the launch step
//! (M18.b) says so plainly; this transport simply connects to a DevTools endpoint a caller
//! points it at.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde_json::Value;

use hexora_engine::transport::{HttpTransport, Origin, SendOptions};
use hexora_http::ws::{self, Opcode, WsConnection};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_types::error::{HexoraError, ProtocolError, Result};
use hexora_types::http::{HttpRequest, HttpService};
use hexora_types::limits::Limits;

/// How long a single CDP command waits for its response before giving up.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// One CDP event: a `method` and its `params`, with no `id`.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    /// The event method, e.g. `"Page.loadEventFired"`.
    pub method: String,
    /// The event parameters, verbatim.
    pub params: Value,
}

/// A live CDP session over one DevTools WebSocket.
///
/// Commands are synchronous ([`Self::call`]); events seen while awaiting a response are
/// buffered and read with [`Self::next_event`] / [`Self::drain_events`].
#[derive(Debug)]
pub struct Cdp {
    conn: WsConnection,
    next_id: i64,
    events: VecDeque<CdpEvent>,
}

/// How an incoming CDP message routes.
#[derive(Debug, PartialEq, Eq)]
enum Incoming {
    /// A response to a command with this `id`.
    Response(i64),
    /// An event.
    Event,
    /// Neither — ignored.
    Other,
}

/// Classifies a decoded CDP message: a response carries an `id`, an event a `method`.
fn classify(message: &Value) -> Incoming {
    if let Some(id) = message.get("id").and_then(Value::as_i64) {
        return Incoming::Response(id);
    }
    if message.get("method").and_then(Value::as_str).is_some() {
        return Incoming::Event;
    }
    Incoming::Other
}

/// Reads the event out of a message already classified as one.
fn event_of(message: &Value) -> CdpEvent {
    CdpEvent {
        method: message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        params: message.get("params").cloned().unwrap_or(Value::Null),
    }
}

/// Turns a CDP `error` object into a Hexora error.
fn cdp_error(error: &Value) -> HexoraError {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown CDP error");
    HexoraError::Protocol(ProtocolError::Malformed {
        protocol: "CDP",
        reason: message.to_string(),
    })
}

fn malformed(reason: impl Into<String>) -> HexoraError {
    HexoraError::Protocol(ProtocolError::Malformed {
        protocol: "CDP",
        reason: reason.into(),
    })
}

impl Cdp {
    /// Connects to a DevTools WebSocket URL (`ws://host:port/devtools/browser/…`).
    pub async fn connect(ws_url: &str) -> Result<Cdp> {
        let (service, path) = HttpService::parse_url(ws_url)?;
        let conn =
            ws::connect(&service, &path, &TlsConfig::default(), &Limits::default()).await?;
        Ok(Cdp {
            conn,
            next_id: 1,
            events: VecDeque::new(),
        })
    }

    /// Sends a CDP command and returns its `result`, buffering any events seen meanwhile.
    ///
    /// `params` of [`Value::Null`] sends no `params` field. A CDP `error` response, a closed
    /// socket, or no answer within the timeout is an error.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;

        let mut message = serde_json::Map::new();
        message.insert("id".into(), Value::from(id));
        message.insert("method".into(), Value::from(method));
        if !params.is_null() {
            message.insert("params".into(), params);
        }
        let text = serde_json::to_string(&Value::Object(message))
            .map_err(|e| malformed(format!("serialising the command: {e}")))?;
        self.conn.send_text(&text).await?;

        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(malformed(format!("no response to {method} within the timeout")));
            }
            let Some(frame) = self.conn.recv(remaining).await? else {
                return Err(malformed(format!(
                    "the CDP connection closed while awaiting {method}"
                )));
            };
            match frame.opcode {
                Opcode::Text => {
                    let value: Value = serde_json::from_slice(&frame.payload)
                        .map_err(|e| malformed(format!("a CDP message was not JSON: {e}")))?;
                    match classify(&value) {
                        Incoming::Response(rid) if rid == id => {
                            if let Some(error) = value.get("error") {
                                return Err(cdp_error(error));
                            }
                            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                        }
                        // A response to some other command (shouldn't happen with synchronous
                        // calls, but harmless): ignore it.
                        Incoming::Response(_) => {}
                        Incoming::Event => self.events.push_back(event_of(&value)),
                        Incoming::Other => {}
                    }
                }
                Opcode::Close => {
                    return Err(malformed(format!(
                        "the browser closed the CDP connection during {method}"
                    )))
                }
                // Control frames and continuations are not part of a CDP exchange; keep reading.
                _ => {}
            }
        }
    }

    /// Returns the next buffered event, or reads from the socket until one arrives or `timeout`
    /// elapses. A response with no matching pending call cannot occur here, so it is ignored.
    pub async fn next_event(&mut self, timeout: Duration) -> Result<Option<CdpEvent>> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let Some(frame) = self.conn.recv(remaining).await? else {
                return Ok(None);
            };
            if frame.opcode == Opcode::Text {
                let value: Value = serde_json::from_slice(&frame.payload)
                    .map_err(|e| malformed(format!("a CDP message was not JSON: {e}")))?;
                if classify(&value) == Incoming::Event {
                    return Ok(Some(event_of(&value)));
                }
            }
        }
    }

    /// Takes the events buffered so far, in order.
    pub fn drain_events(&mut self) -> Vec<CdpEvent> {
        self.events.drain(..).collect()
    }
}

/// Discovers the browser-level DevTools WebSocket URL from its `/json/version` endpoint.
///
/// The DevTools HTTP interface is the local control channel to the browser, not traffic to a
/// target, so it goes straight over the transport rather than the scope guard.
pub async fn discover_ws_url(host: &str, port: u16) -> Result<String> {
    let service = HttpService::new(host, port, false);
    let request = HttpRequest::get(service, "/json/version");
    let transport = TcpTransport::new();
    let exchange = transport
        .send(request, SendOptions::interactive(Origin::Repeater))
        .await?;

    let value: Value = serde_json::from_slice(&exchange.response.body)
        .map_err(|e| malformed(format!("/json/version was not JSON: {e}")))?;
    value
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| malformed("/json/version had no webSocketDebuggerUrl"))
}

/// Discovers, connects, and returns the browser's product string (e.g. `HeadlessChrome/…`).
///
/// The smallest end-to-end use of this layer, and the shape M18.b's launcher will call.
pub async fn browser_version(host: &str, port: u16) -> Result<String> {
    let ws_url = discover_ws_url(host, port).await?;
    let mut cdp = Cdp::connect(&ws_url).await?;
    let result = cdp.call("Browser.getVersion", Value::Null).await?;
    Ok(result
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_message_with_an_id_is_a_response() {
        let msg = json!({"id": 7, "result": {"product": "HeadlessChrome/120"}});
        assert_eq!(classify(&msg), Incoming::Response(7));
    }

    #[test]
    fn a_message_with_a_method_is_an_event() {
        let msg = json!({"method": "Page.loadEventFired", "params": {"timestamp": 1.0}});
        assert_eq!(classify(&msg), Incoming::Event);
        let event = event_of(&msg);
        assert_eq!(event.method, "Page.loadEventFired");
        assert_eq!(event.params, json!({"timestamp": 1.0}));
    }

    #[test]
    fn a_message_that_is_neither_is_other() {
        assert_eq!(classify(&json!({"hello": "world"})), Incoming::Other);
    }

    #[test]
    fn a_cdp_error_carries_its_message() {
        let error = json!({"code": -32000, "message": "Cannot navigate to invalid URL"});
        let mapped = cdp_error(&error).to_string();
        assert!(mapped.contains("Cannot navigate to invalid URL"), "{mapped}");
    }

    #[test]
    fn an_event_with_no_params_reads_as_null() {
        let event = event_of(&json!({"method": "Inspector.detached"}));
        assert_eq!(event.params, Value::Null);
    }

    /// Live smoke test: drives a real browser over CDP.
    ///
    /// Ignored by default because it needs a DevTools-enabled browser. Launch one and run it:
    ///
    /// ```console
    /// $ msedge --headless=new --remote-debugging-port=9222 --user-data-dir=/tmp/hx &
    /// $ HEXORA_CDP_PORT=9222 cargo test -p hexora-browser -- --ignored live_
    /// ```
    #[tokio::test]
    #[ignore = "needs a DevTools-enabled browser on HEXORA_CDP_PORT"]
    async fn live_browser_reports_its_version() {
        let port: u16 = std::env::var("HEXORA_CDP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(9222);
        let product = browser_version("127.0.0.1", port).await.unwrap();
        assert!(!product.is_empty());
        eprintln!("CDP browser product: {product}");
    }
}
