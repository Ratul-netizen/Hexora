//! The collaborator server: catches HTTP callbacks, records them, and answers polls.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use nullhawk_types::error::{NullhawkError, Result};

use crate::{token_of, Interaction};

/// The recorded interactions, keyed by token. Cloneable and shared across connections and
/// across the HTTP and DNS listeners, so a poll returns callbacks of either kind.
#[derive(Clone, Default)]
pub(crate) struct Store {
    inner: Arc<Mutex<HashMap<String, Vec<Interaction>>>>,
}

impl Store {
    pub(crate) fn record(&self, interaction: Interaction) {
        if let Ok(mut map) = self.inner.lock() {
            map.entry(interaction.token.clone())
                .or_default()
                .push(interaction);
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

/// Runs the collaborator's HTTP listener on `addr`, recording callbacks into `store`.
pub(crate) async fn run_http(addr: &str, store: Store) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| NullhawkError::invalid_input("listen", format!("{addr}: {e}")))?;
    if let Ok(local) = listener.local_addr() {
        tracing::info!(%local, "collaborator HTTP listening");
    }
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let store = store.clone();
                tokio::spawn(async move {
                    let _ = handle(stream, peer, store).await;
                });
            }
            Err(error) => tracing::warn!(%error, "collaborator accept failed"),
        }
    }
}

/// Binds and runs the HTTP collaborator on `addr`. The one call an HTTP-only server makes.
pub async fn serve(addr: &str) -> Result<()> {
    run_http(addr, Store::default()).await
}

/// Reads one request, records or answers it, and replies.
async fn handle(mut stream: TcpStream, peer: SocketAddr, store: Store) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let (method, path) = request_line(&head);
    let host = header(&head, "host").unwrap_or_default();

    // The poll endpoint the client reads its interactions from.
    if path.starts_with("/_nullhawk/poll") {
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
    // A redirect hop. `?to=<url>` makes this callback answer 302 to that URL — the one
    // thing needed to test whether a server-side fetch *follows* a redirect off the host
    // it was pointed at, which is the open-redirect→SSRF primitive. The interaction is
    // recorded above first, so the callback proving the fetch reached here is never lost to
    // the redirect.
    if let Some(target) = query_param(&path, "to") {
        return redirect(&mut stream, &percent_decode(&target)).await;
    }
    respond(&mut stream, "text/plain", "nullhawk-oob\n").await
}

/// Writes a 302 to `location` and closes.
async fn redirect(stream: &mut TcpStream, location: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// Decodes `%XX` escapes in a query value. A server-side HTTP client may or may not encode
/// the redirect target it was handed, so the collaborator accepts both and decodes if it
/// must. Leaves anything that is not a valid escape exactly as written.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
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
        assert_eq!(
            query_param("/_nullhawk/poll?token=abc", "token").as_deref(),
            Some("abc")
        );
        assert_eq!(query_param("/", "token"), None);
    }

    #[test]
    fn a_redirect_target_is_read_whether_or_not_the_client_encoded_it() {
        // A fetch that was pointed at `/<token>?to=<url>` arrives either way, depending on
        // whether the server-side HTTP client re-encoded the target. Both must work.
        let plain = query_param("/tok?to=http://169.254.169.254/latest/meta-data/", "to").unwrap();
        assert_eq!(
            percent_decode(&plain),
            "http://169.254.169.254/latest/meta-data/"
        );

        let encoded =
            query_param("/tok?to=http%3A%2F%2F169.254.169.254%2Flatest%2F", "to").unwrap();
        assert_eq!(percent_decode(&encoded), "http://169.254.169.254/latest/");
    }

    #[test]
    fn percent_decode_leaves_a_stray_percent_alone() {
        assert_eq!(percent_decode("100%done"), "100%done");
        assert_eq!(percent_decode("a%2z"), "a%2z");
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
