//! `hexora send` — issue a single request and print the exchange.
//!
//! The smallest thing that proves the engine works end to end, and genuinely useful
//! on its own: a `curl` that does not rewrite what you asked it to send.
//!
//! Requests go through [`ScopeGuard`] like everything else. This one is human-driven
//! (`Origin::Repeater`), so an out-of-scope target is **flagged rather than blocked** —
//! a tester typing a URL has made a decision. Automated subsystems get no such
//! latitude; see `docs/security-invariants.md`, invariant 1.

use std::sync::Arc;

use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_engine::transport::{HttpTransport, Origin, SendOptions};
use hexora_http::{ClientIdentity, TcpTransport, TlsConfig};
use hexora_types::http::{Header, HttpRequest, HttpService};
use hexora_types::redact::{is_sensitive_header, RedactionPolicy, REDACTED};
use hexora_types::scope::Scope;
use hexora_types::{HexoraError, Result};

/// Options for one `hexora send` invocation.
pub struct SendArgs<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub headers: &'a [String],
    pub body: Option<&'a str>,
    pub json: bool,
    /// Show `Authorization`, `Cookie` and friends in full.
    pub show_secrets: bool,
    /// Accept any TLS certificate. See [`hexora_types::tls::Verification::AcceptAny`].
    pub insecure: bool,
    /// Client certificate chain (PEM) for mTLS.
    pub client_cert: Option<&'a std::path::Path>,
    /// Client private key (PEM) for mTLS.
    pub client_key: Option<&'a std::path::Path>,
}

/// Sends one request and prints the result.
pub fn run(args: SendArgs<'_>) -> Result<()> {
    let (service, path) = parse_url(args.url)?;
    let request = build_request(service, &path, args.method, args.headers, args.body)?;

    // An empty scope blocks automated traffic but not a human's own request. The
    // decision is still computed so the user is told when they leave scope.
    let guard = ScopeGuard::new(build_transport(&args)?, Arc::new(Scope::new()));
    let options = SendOptions::interactive(Origin::Repeater);
    let decision = guard.decide(&request, &options);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    let exchange = runtime.block_on(guard.send(request, options))?;

    if args.json {
        print_json(&exchange, args.show_secrets);
    } else {
        print_human(&exchange, decision, args.show_secrets);
    }
    Ok(())
}

fn build_transport(args: &SendArgs<'_>) -> Result<TcpTransport> {
    let mut tls = if args.insecure {
        TlsConfig::accept_any()
    } else {
        TlsConfig::verified()
    };

    tls.client_identity = match (args.client_cert, args.client_key) {
        (Some(cert), Some(key)) => Some(ClientIdentity::from_pem_files(cert, key)?),
        (None, None) => None,
        // Half an identity is a misconfiguration, and silently ignoring it would look
        // like the server rejected the certificate.
        _ => {
            return Err(HexoraError::invalid_input(
                "client-cert",
                "--client-cert and --client-key must be given together",
            ))
        }
    };

    Ok(TcpTransport::with_tls(tls))
}

fn build_request(
    service: HttpService,
    path: &str,
    method: &str,
    extra_headers: &[String],
    body: Option<&str>,
) -> Result<HttpRequest> {
    let mut request = HttpRequest::get(service, path);
    request.method = method.to_ascii_uppercase();

    for raw in extra_headers {
        let (name, value) = raw.split_once(':').ok_or_else(|| {
            HexoraError::invalid_input("header", format!("{raw:?} is not in 'Name: Value' form"))
        })?;
        // Append, not set: sending two headers of the same name is a legitimate test.
        request
            .headers
            .append(Header::new(name.trim(), value.trim()));
    }

    if let Some(body) = body {
        request.body = bytes::Bytes::from(body.to_owned());
        // Only added when the user did not write their own framing, so a deliberately
        // ambiguous request stays ambiguous.
        if request.headers.count("Content-Length") == 0
            && request.headers.count("Transfer-Encoding") == 0
        {
            request
                .headers
                .set("Content-Length", body.len().to_string());
        }
    }

    Ok(request)
}

/// Parses an absolute HTTP URL into a service and an origin-form path.
///
/// Deliberately minimal and non-normalizing: whatever path the user wrote is what
/// gets sent, including the odd spellings that make a request interesting.
fn parse_url(url: &str) -> Result<(HttpService, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| HexoraError::invalid_input("url", "expected http:// or https://"))?;

    let secure = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        other => {
            return Err(HexoraError::invalid_input(
                "url",
                format!("unsupported scheme {other:?}"),
            ))
        }
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(HexoraError::invalid_input("url", "missing host"));
    }

    // Split host from port, taking the last colon so IPv6 literals in brackets survive.
    let (host, port) = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => {
            let port = authority[i + 1..].parse::<u16>().map_err(|_| {
                HexoraError::invalid_input("url", format!("invalid port {:?}", &authority[i + 1..]))
            })?;
            (&authority[..i], port)
        }
        _ => (authority, if secure { 443 } else { 80 }),
    };

    Ok((HttpService::new(host, port, secure), path))
}

fn render_header(name: &str, value: &str, show_secrets: bool) -> String {
    if show_secrets || !is_sensitive_header(name) {
        value.to_string()
    } else {
        format!("{REDACTED} (use --show-secrets)")
    }
}

fn print_human(
    exchange: &hexora_engine::transport::Exchange,
    decision: ScopeDecision,
    show_secrets: bool,
) {
    if let Some(tls) = &exchange.tls {
        eprintln!(
            "tls: {} · {} · alpn {}",
            tls.protocol,
            tls.cipher_suite,
            tls.alpn.as_deref().unwrap_or("none")
        );
        if let Some(leaf) = tls.peer_certificates.first() {
            eprintln!("     subject {}", leaf.subject);
            eprintln!("     expires {}", leaf.not_after);
        }
        for observation in tls.observations() {
            eprintln!("     ! {observation}");
        }
        eprintln!();
    }

    if decision == ScopeDecision::AllowedOutOfScope {
        eprintln!(
            "note: {} is not in the project scope",
            exchange.request.url()
        );
        eprintln!("      sent anyway because you asked for it directly\n");
    }

    let response = &exchange.response;
    println!(
        "{} {}{}",
        response.version,
        response.status,
        response
            .reason
            .as_deref()
            .map(|r| format!(" {r}"))
            .unwrap_or_default()
    );
    for header in response.headers.iter() {
        println!(
            "{}: {}",
            header.name,
            render_header(&header.name, &header.value_lossy(), show_secrets)
        );
    }
    println!();

    match std::str::from_utf8(&response.body) {
        Ok(text) => print!("{text}"),
        Err(_) => println!("<{} bytes of binary body>", response.body.len()),
    }
    if !response.body.is_empty() && !response.body.ends_with(b"\n") {
        println!();
    }

    if response.truncated {
        eprintln!("\nwarning: body truncated by the configured size limit");
    }
    eprintln!(
        "\n{} bytes in {} ms",
        response.body.len(),
        exchange.duration.as_millis()
    );
}

fn print_json(exchange: &hexora_engine::transport::Exchange, show_secrets: bool) {
    let policy = if show_secrets {
        RedactionPolicy::Disabled
    } else {
        RedactionPolicy::SensitiveHeaders
    };
    let response = &exchange.response;
    let headers: Vec<serde_json::Value> = response
        .headers
        .iter()
        .map(|h| {
            let value = h.value_lossy();
            serde_json::json!({
                "name": h.name,
                "value": policy.apply_header(&h.name, &value),
            })
        })
        .collect();

    let payload = serde_json::json!({
        "url": exchange.request.url(),
        "status": response.status,
        "reason": response.reason,
        "version": response.version.as_str(),
        "headers": headers,
        "body_bytes": response.body.len(),
        "body": String::from_utf8_lossy(&response.body),
        "truncated": response.truncated,
        "duration_ms": exchange.duration.as_millis(),
        "tls": exchange.tls,
    });
    println!("{payload}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_url() {
        let (service, path) = parse_url("http://example.com/a/b?c=d").unwrap();
        assert_eq!(service.host, "example.com");
        assert_eq!(service.port, 80);
        assert!(!service.secure);
        assert_eq!(path, "/a/b?c=d");
    }

    #[test]
    fn defaults_the_port_from_the_scheme() {
        assert_eq!(parse_url("http://example.com/").unwrap().0.port, 80);
        assert_eq!(parse_url("https://example.com/").unwrap().0.port, 443);
    }

    #[test]
    fn an_explicit_port_wins() {
        let (service, _) = parse_url("http://example.com:8080/x").unwrap();
        assert_eq!(service.port, 8080);
    }

    #[test]
    fn a_missing_path_becomes_root() {
        assert_eq!(parse_url("http://example.com").unwrap().1, "/");
    }

    #[test]
    fn the_path_is_not_normalized() {
        // The odd spellings are the interesting ones; they must survive verbatim.
        for path in ["/a/../b", "/%2e%2e/b", "//double", "/a%20b"] {
            let url = format!("http://example.com{path}");
            assert_eq!(parse_url(&url).unwrap().1, path);
        }
    }

    #[test]
    fn ipv6_literals_keep_their_brackets() {
        let (service, _) = parse_url("http://[::1]/x").unwrap();
        assert_eq!(service.host, "[::1]");
        assert_eq!(service.port, 80);
    }

    #[test]
    fn bad_urls_are_rejected() {
        for url in [
            "example.com",
            "ftp://example.com",
            "http://",
            "http://h:99999/",
        ] {
            assert!(parse_url(url).is_err(), "{url} should not parse");
        }
    }

    #[test]
    fn header_arguments_are_parsed_and_appended_in_order() {
        let service = HttpService::new("example.com", 80, false);
        let headers = vec!["X-A: 1".to_string(), "X-A: 2".to_string()];
        let request = build_request(service, "/", "GET", &headers, None).unwrap();
        assert_eq!(request.headers.count("X-A"), 2, "duplicates must survive");
    }

    #[test]
    fn a_malformed_header_argument_is_rejected() {
        let service = HttpService::new("example.com", 80, false);
        let headers = vec!["no-colon-here".to_string()];
        assert!(build_request(service, "/", "GET", &headers, None).is_err());
    }

    #[test]
    fn a_body_gets_a_content_length_unless_the_user_framed_it() {
        let service = HttpService::new("example.com", 80, false);
        let request = build_request(service.clone(), "/", "POST", &[], Some("abc")).unwrap();
        assert_eq!(
            request.headers.get("Content-Length").unwrap().value_lossy(),
            "3"
        );

        // A deliberately ambiguous request must stay ambiguous.
        let headers = vec!["Transfer-Encoding: chunked".to_string()];
        let request = build_request(service, "/", "POST", &headers, Some("abc")).unwrap();
        assert_eq!(request.headers.count("Content-Length"), 0);
    }

    #[test]
    fn sensitive_headers_are_hidden_unless_requested() {
        assert_eq!(
            render_header("Content-Type", "text/html", false),
            "text/html"
        );
        assert!(render_header("Authorization", "Bearer abc", false).starts_with(REDACTED));
        assert_eq!(
            render_header("Authorization", "Bearer abc", true),
            "Bearer abc"
        );
    }
}
