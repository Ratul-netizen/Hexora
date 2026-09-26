//! `hexora ws` — the captured WebSocket sessions and their message timelines.
//!
//! A WebSocket is not request/response, so it does not show up in `history` as one row: it
//! is a session of frames going both ways. This lists those sessions, and opens one as an
//! ordered, both-directions timeline — the read side of what the proxy captured in WS.a.

use std::path::Path;

use hexora_storage::CapturedExchange;
use hexora_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;
use hexora_types::ws::WsDirection;
use hexora_types::{HexoraError, Result};

/// `hexora ws list <project>` — the captured sessions.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let project = open(project)?;
    list_store(&project.traffic(), json)
}

/// `hexora ws show <project> <id>` — a session's message timeline.
pub fn show(project: &Path, id: &str, json: bool) -> Result<()> {
    let project = open(project)?;
    show_store(&project.traffic(), id, json)
}

fn list_store(store: &hexora_storage::TrafficStore, json: bool) -> Result<()> {
    let sessions = store.ws_sessions()?;

    if json {
        let items: Vec<_> = sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.request_id.to_string(),
                    "url": s.url,
                    "messages": s.messages,
                    "started_at": s.started_at,
                })
            })
            .collect();
        println!("{}", serde_json::json!(items));
        return Ok(());
    }

    if sessions.is_empty() {
        println!("No WebSocket sessions captured yet.");
        return Ok(());
    }

    println!("{:<38}  {:>8}  URL", "ID", "MESSAGES");
    for session in sessions {
        println!(
            "{:<38}  {:>8}  {}",
            session.request_id, session.messages, session.url
        );
    }
    Ok(())
}

fn show_store(store: &hexora_storage::TrafficStore, id: &str, json: bool) -> Result<()> {
    let request_id: RequestId = id
        .parse()
        .map_err(|_| HexoraError::invalid_input("id", format!("{id:?} is not a request id")))?;
    let messages = store.ws_messages(request_id)?;

    if json {
        let items: Vec<_> = messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id.to_string(),
                    "direction": m.direction.as_str(),
                    "opcode": m.opcode,
                    "size": m.payload.len(),
                    "sent_at": m.sent_at,
                    "preview": preview(&m.payload),
                })
            })
            .collect();
        println!("{}", serde_json::json!(items));
        return Ok(());
    }

    if messages.is_empty() {
        println!("No messages in this session (or no such session).");
        return Ok(());
    }

    for message in messages {
        // An arrow makes the direction scannable in a long timeline.
        let arrow = match message.direction {
            WsDirection::ClientToServer => "→",
            WsDirection::ServerToClient => "←",
        };
        println!(
            "{arrow} {:<8} {:>6}B  {}",
            opcode_name(message.opcode),
            message.payload.len(),
            preview(&message.payload)
        );
    }
    Ok(())
}

/// `hexora ws send <project> <url> [message]` — the WebSocket repeater.
///
/// Connects to a target, sends a message and listens for replies, recording the whole
/// session into the project like any captured one. Human-driven, so an out-of-scope target
/// is flagged and sent rather than refused.
pub fn send(
    project: &Path,
    url: &str,
    message: Option<&str>,
    listen_ms: u64,
    insecure: bool,
    json: bool,
) -> Result<()> {
    let project = open(project)?;
    let store = project.traffic();
    let (service, path) = HttpService::parse_url(url)?;

    if let Ok(scope) = project.settings().scope() {
        if !scope.contains(&service, &path) {
            eprintln!(
                "warning: {url} is not in the project scope; sending anyway — a human-driven \
                 request is flagged, not refused"
            );
        }
    }

    let tls = if insecure {
        hexora_http::TlsConfig::accept_any()
    } else {
        hexora_http::TlsConfig::verified()
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(e.to_string()))?;

    runtime.block_on(async move {
        let mut connection = hexora_http::ws::connect(&service, &path, &tls, &Limits::default()).await?;
        let request_id = record_handshake(&store, &service, &path)?;

        if let Some(msg) = message {
            connection.send_text(msg).await?;
            store.record_ws_message(request_id, WsDirection::ClientToServer, 0x1, msg.as_bytes())?;
            if !json {
                println!("→ text   {:>6}B  {}", msg.len(), preview(msg.as_bytes()));
            }
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(listen_ms);
        let mut received = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match connection.recv(remaining).await? {
                Some(frame) => {
                    let opcode = frame.opcode.as_u8();
                    store.record_ws_message(
                        request_id,
                        WsDirection::ServerToClient,
                        opcode,
                        &frame.payload,
                    )?;
                    if !json {
                        println!(
                            "← {:<6} {:>6}B  {}",
                            opcode_name(opcode),
                            frame.payload.len(),
                            preview(&frame.payload)
                        );
                    }
                    received.push((opcode, frame.payload));
                }
                None => break,
            }
        }
        let _ = connection.close().await;

        if json {
            let items: Vec<_> = received
                .iter()
                .map(|(opcode, payload)| {
                    serde_json::json!({
                        "opcode": opcode,
                        "size": payload.len(),
                        "preview": preview(payload),
                    })
                })
                .collect();
            println!("{}", serde_json::json!({ "sent": message, "received": items }));
        }

        Ok::<(), HexoraError>(())
    })
}

/// Records the WebSocket upgrade as an exchange, so the session's frames have a request to
/// anchor to — the same reason the proxy records the upgrade first.
fn record_handshake(
    store: &hexora_storage::TrafficStore,
    service: &HttpService,
    path: &str,
) -> Result<RequestId> {
    let mut headers = Headers::new();
    headers.set("Host", service.authority());
    headers.set("Upgrade", "websocket");
    headers.set("Connection", "Upgrade");
    let request = HttpRequest {
        service: service.clone(),
        method: "GET".to_string(),
        path: path.to_string(),
        version: HttpVersion::Http11,
        headers,
        body: bytes::Bytes::new(),
    };

    let mut response_headers = Headers::new();
    response_headers.set("Upgrade", "websocket");
    let response = HttpResponse {
        status: 101,
        reason: Some("Switching Protocols".to_string()),
        version: HttpVersion::Http11,
        headers: response_headers,
        body: bytes::Bytes::new(),
        truncated: false,
    };

    let captured = CapturedExchange {
        request,
        raw_request: None,
        response,
        encoded_body: None,
        content_encoding: None,
        origin: "repeater",
        identity: None,
        parent: None,
        quirks: Vec::new(),
        tls: None,
        duration_ms: 0,
    };
    Ok(store.record(&captured)?)
}

/// A short, printable preview of a payload — text as text, binary as a byte note.
fn preview(payload: &[u8]) -> String {
    match std::str::from_utf8(payload) {
        Ok(text) => {
            let text: String = text.chars().take(120).collect();
            text.replace(['\n', '\r'], " ")
        }
        Err(_) => format!("<{} binary bytes>", payload.len()),
    }
}

/// A human name for a WebSocket opcode.
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x0 => "cont",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xA => "pong",
        _ => "other",
    }
}

fn open(path: &Path) -> Result<hexora_storage::Project> {
    if !path.join("project.db").exists() {
        return Err(HexoraError::not_found(
            "project",
            path.display().to_string(),
        ));
    }
    crate::open_project(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_project_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = list(dir.path(), false).unwrap_err();
        assert_eq!(error.code(), "not_found");
    }

    #[test]
    fn a_bad_session_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        crate::project::init(&dir.path().join("eng"), Some("Acme"), true).unwrap();
        let error = show(&dir.path().join("eng"), "not-an-id", false).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn opcode_names_cover_the_common_frames() {
        assert_eq!(opcode_name(0x1), "text");
        assert_eq!(opcode_name(0x8), "close");
        assert_eq!(preview(b"hi\nthere"), "hi there");
        assert_eq!(preview(&[0xff, 0xfe]), "<2 binary bytes>");
    }
}
