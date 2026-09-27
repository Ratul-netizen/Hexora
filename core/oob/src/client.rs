//! The client: mint OOB payloads and poll the collaborator for the callbacks they provoke.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use hexora_types::error::{HexoraError, NetworkError, Result};

use crate::{fresh_token, Interaction};

/// How a payload carries its token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadMode {
    /// `http://host/<token>` — works without DNS, for a collaborator reached by address.
    Path,
    /// `http://<token>.domain/` — needs a wildcard DNS record, the Burp-Collaborator form.
    Subdomain,
}

/// A configured collaborator: where it lives, and how payloads embed their token.
#[derive(Debug, Clone)]
pub struct Collaborator {
    /// The collaborator's authority — `host`, `host:port`, or the base domain for subdomain mode.
    authority: String,
    mode: PayloadMode,
    scheme: String,
}

impl Collaborator {
    /// A collaborator reached over plain HTTP (payload callbacks and polling both).
    pub fn new(authority: impl Into<String>, mode: PayloadMode) -> Self {
        Self {
            authority: authority.into(),
            mode,
            scheme: "http".into(),
        }
    }

    /// Payloads use `https` (the callback URL); polling is still plain HTTP to the authority.
    pub fn https_payloads(mut self) -> Self {
        self.scheme = "https".into();
        self
    }

    /// Mints one payload: a fresh token and the URL to place in a target field.
    ///
    /// A callback to that URL will be recorded under the token, so [`Self::poll`] correlates it
    /// back to the request that carried the payload.
    pub fn mint(&self) -> (String, String) {
        let token = fresh_token();
        let url = match self.mode {
            PayloadMode::Path => format!("{}://{}/{token}", self.scheme, self.authority),
            PayloadMode::Subdomain => format!("{}://{token}.{}/", self.scheme, self.authority),
        };
        (token, url)
    }

    /// Polls the collaborator for interactions on `token`, taking what is new since the last poll.
    pub async fn poll(&self, token: &str) -> Result<Vec<Interaction>> {
        poll(&self.authority, token).await
    }
}

/// Polls a collaborator `authority` (`host` or `host:port`) for interactions on `token`.
pub async fn poll(authority: &str, token: &str) -> Result<Vec<Interaction>> {
    let target = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let mut stream = TcpStream::connect(&target)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    let request = format!(
        "GET /_hexora/poll?token={token} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;
    stream.flush().await.ok();

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| HexoraError::Network(NetworkError::Io(e.to_string())))?;

    let text = String::from_utf8_lossy(&raw);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    serde_json::from_str::<Vec<Interaction>>(body.trim()).map_err(|e| {
        HexoraError::Internal(format!("the collaborator poll response was not valid: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_payload_embeds_the_token_in_the_path() {
        let (token, url) = Collaborator::new("127.0.0.1:8080", PayloadMode::Path).mint();
        assert_eq!(url, format!("http://127.0.0.1:8080/{token}"));
    }

    #[test]
    fn a_subdomain_payload_embeds_the_token_as_a_label() {
        let (token, url) = Collaborator::new("oob.example", PayloadMode::Subdomain)
            .https_payloads()
            .mint();
        assert_eq!(url, format!("https://{token}.oob.example/"));
    }
}
