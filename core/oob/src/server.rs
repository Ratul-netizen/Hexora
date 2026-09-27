//! The collaborator server: catches HTTP callbacks, records them, and answers polls.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hexora_types::error::{HexoraError, Result};

use crate::{token_of, Interaction};

/// The recorded interactions, keyed by token. Cloneable and shared across connections.
#[derive(Clone, Default)]
pub struct Store {
    inner: Arc<Mutex<HashMap<String, Vec<Interaction>>>>,
}

impl Store {
    fn record(&self, interaction: Interaction) {
        if let Ok(mut map) = self.inner.lock() {
            map.entry(interaction.token.clone()).or_default().push(interaction);
        }
    }

    /// Takes and clears the interactions recorded for `token`, so a poll returns what is new.
    fn drain(&self, token: &str) -> Vec<Interaction> {
        self.inner
            .lock()
            .ok()
            .and_then(|mut map| map.remove(token))
            .unwrap_or_default()
    }
}

/// A bound collaborator, ready to run.
pub struct Server {
    listener: TcpListener,
    store: Store,
}

impl Server {
    /// Binds the collaborator to `addr` (e.g. `0.0.0.0:80` in production, `127.0.0.1:0` in a test).
    pub async fn bind(addr: &str) -> Result<Server> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| HexoraError::invalid_input("listen", format!("{addr}: {e}")))?;
        Ok(Server {
            listener,
            store: Store::default(),
        })
    }

    /// The address it is actually listening on (the real port, when `:0` was requested).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.local_addr().ok()
    }

    /// Serves interactions forever.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    let store = self.store.clone();
                    tokio::spawn(async move {
                        let _ = handle(stream, peer, store).await;
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "collaborator accept failed");
                }
            }
        }
    }
}

/// Binds and runs the collaborator on `addr`. The one call a server binary makes.
pub async fn serve(addr: &str) -> Result<()> {
    let server = Server::bind(addr).await?;
    if let Some(local) = server.local_addr() {
        tracing::info!(%local, "collaborator listening");
    }
    server.run().await;
    Ok(())
}

/// Reads one request, records or answers it, and replies.
async fn handle(mut stream: TcpStream, peer: SocketAddr, store: Store) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let (method, path) = request_line(&head);
    let host = header(&head, "host").unwrap_or_default();

    // The poll endpoint the client reads its interactions from.
    if path.starts_with("/_hexora/poll") {
        let token = query_param(&path, "token").unwrap_or_default();
        let interactions = store.drain(&token);
        let body = serde_json::to_string(&interactions).unwrap_or_else(|_| "[]".into());
        return respond(&mut stream, "application/json", &body).await;
    }

    // Anything else is a potential callback: record it if it carries a token.
    if let Some(token) = token_of(&path, &host) {
        store.record(Interaction {
            token,
            protocol: "http".into(),
            method: method.to_string(),
            path: path.clone(),
            host: host.clone(),
            source: peer.ip().to_string(),
            at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
    }
    respond(&mut stream, "text/plain", "hexora-oob\n").await
}

/// Reads the request head (up to the blank line), bounded so a slow or hostile peer cannot
/// hold a connection open with an endless stream of headers.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .unwrap_or(Ok(0))?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The method and path from a request head.
fn request_line(head: &str) -> (&str, String) {
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/").to_string();
    (method, path)
}

/// A header value from the head, case-insensitively.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
    })
}

/// A query parameter from a request target.
fn query_param(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

/// Writes a minimal HTTP/1.1 response and closes.
async fn respond(stream: &mut TcpStream, content_type: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_poll_query_token_is_parsed() {
        assert_eq!(query_param("/_hexora/poll?token=abc", "token").as_deref(), Some("abc"));
        assert_eq!(query_param("/", "token"), None);
    }

    #[test]
    fn the_request_line_and_host_are_read() {
        let head = "POST /abc/x HTTP/1.1\r\nHost: oob.example\r\nAccept: */*\r\n\r\n";
        let (method, path) = request_line(head);
        assert_eq!(method, "POST");
        assert_eq!(path, "/abc/x");
        assert_eq!(header(head, "host").as_deref(), Some("oob.example"));
    }

    #[tokio::test]
    async fn a_callback_is_recorded_and_then_drained_by_a_poll() {
        let store = Store::default();
        store.record(Interaction {
            token: "tok1".into(),
            protocol: "http".into(),
            method: "GET".into(),
            path: "/tok1".into(),
            host: "h".into(),
            source: "1.2.3.4".into(),
            at: "now".into(),
        });
        let first = store.drain("tok1");
        assert_eq!(first.len(), 1);
        // Drained: a second poll sees nothing new.
        assert!(store.drain("tok1").is_empty());
    }
}
