//! # nullhawk-oob
//!
//! Out-of-band interaction testing — Nullhawk's answer to Burp Collaborator. Some
//! vulnerabilities produce **no visible response**: a blind SSRF, a blind XXE that fetches a
//! URL, a blind injection that only triggers a DNS lookup. You confirm them by making the
//! target reach out to a server you control and *watching it arrive*.
//!
//! This is that server, self-hosted: a collaborator that catches HTTP callbacks, records each
//! with the unique token that provoked it, and hands them back to a client that polls. Point a
//! payload — `http://<token>.your-oob-domain/` or `http://your-oob-host/<token>` — at a target
//! field, and a callback proves the target processed it, with the source and time as evidence.
//!
//! ## What it is and is not
//!
//! HTTP interactions today ([`serve`]); DNS-only callbacks (a target that resolves but does
//! not connect) want a DNS server and are a later step, stated rather than pretended. Nothing
//! here ships a public domain: you run [`serve`] on a host you control, with a wildcard record
//! if you want subdomain payloads, and the tool talks to it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod dns;
mod server;

pub use client::{poll, Collaborator, PayloadMode};
pub use server::serve;

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use nullhawk_types::error::Result;

/// Runs the collaborator's HTTP and DNS listeners together, sharing one interaction store so a
/// poll returns callbacks of either kind. `answer_ip` is the address A queries are answered
/// with — a resolved payload then connects there, chaining DNS to HTTP.
pub async fn serve_all(http_addr: &str, dns_addr: &str, answer_ip: Ipv4Addr) -> Result<()> {
    let store = server::Store::default();
    let http = server::run_http(http_addr, store.clone());
    let dns = dns::run_dns(dns_addr, store, answer_ip);
    tokio::try_join!(http, dns)?;
    Ok(())
}

/// One recorded out-of-band interaction: a target reached the collaborator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interaction {
    /// The token the payload carried, correlating this to the request that provoked it.
    pub token: String,
    /// The protocol it arrived over (`http`).
    pub protocol: String,
    /// The request method.
    pub method: String,
    /// The request target.
    pub path: String,
    /// The `Host` header, as sent.
    pub host: String,
    /// The peer that connected — often the target itself, sometimes a proxy or resolver.
    pub source: String,
    /// When it arrived, RFC 3339.
    pub at: String,
}

/// A fresh, subdomain-safe correlation token.
///
/// Lowercase hex, unguessable: only a payload Nullhawk minted carries it, so an interaction that
/// bears it is one this run provoked, not background noise reaching a public host.
pub fn fresh_token() -> String {
    // 24 hex chars: unguessable, and safe as a DNS label and a path segment.
    uuid::Uuid::now_v7().simple().to_string()[..24].to_string()
}

/// Pulls the correlation token out of an incoming request's path or host.
///
/// Path first (`/<token>/…`, the form that works without DNS), then the leftmost host label
/// (`<token>.domain`, the form a wildcard record enables). `None` when neither carries one.
pub(crate) fn token_of(path: &str, host: &str) -> Option<String> {
    let segment = path
        .trim_start_matches('/')
        .split(['/', '?'])
        .next()
        .unwrap_or("");
    if !segment.is_empty() && segment != "_nullhawk" {
        return Some(segment.to_string());
    }
    let host = host.split(':').next().unwrap_or(host);
    let leftmost = host.split('.').next().unwrap_or("");
    // Long enough not to be an ordinary hostname label like `api` or `www`.
    if leftmost.len() >= 16 {
        return Some(leftmost.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_unique_and_label_safe() {
        let a = fresh_token();
        let b = fresh_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 24);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_token_is_read_from_the_path_first() {
        let t = fresh_token();
        assert_eq!(
            token_of(&format!("/{t}/x"), "oob.example").as_deref(),
            Some(t.as_str())
        );
    }

    #[test]
    fn a_token_is_read_from_a_subdomain_when_the_path_has_none() {
        let t = fresh_token();
        assert_eq!(
            token_of("/", &format!("{t}.oob.example")).as_deref(),
            Some(t.as_str())
        );
    }

    #[test]
    fn ordinary_requests_carry_no_token() {
        assert_eq!(token_of("/", "oob.example"), None);
        assert_eq!(token_of("/_nullhawk/poll", "oob.example"), None);
        assert_eq!(token_of("/", "www.oob.example"), None);
    }
}
