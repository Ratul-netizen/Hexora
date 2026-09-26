//! `hexora ws` — the captured WebSocket sessions and their message timelines.
//!
//! A WebSocket is not request/response, so it does not show up in `history` as one row: it
//! is a session of frames going both ways. This lists those sessions, and opens one as an
//! ordered, both-directions timeline — the read side of what the proxy captured in WS.a.

use std::path::Path;

use hexora_types::ids::RequestId;
use hexora_types::ws::WsDirection;
use hexora_types::{HexoraError, Result};

/// `hexora ws <project> [id]` — list sessions, or show one's timeline.
pub fn run(project: &Path, id: Option<&str>, json: bool) -> Result<()> {
    let project = open(project)?;
    let store = project.traffic();
    match id {
        None => list(&store, json),
        Some(id) => show(&store, id, json),
    }
}

fn list(store: &hexora_storage::TrafficStore, json: bool) -> Result<()> {
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

fn show(store: &hexora_storage::TrafficStore, id: &str, json: bool) -> Result<()> {
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
        let error = run(dir.path(), None, false).unwrap_err();
        assert_eq!(error.code(), "not_found");
    }

    #[test]
    fn a_bad_session_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        crate::project::init(&dir.path().join("eng"), Some("Acme"), true).unwrap();
        let error = run(&dir.path().join("eng"), Some("not-an-id"), false).unwrap_err();
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
