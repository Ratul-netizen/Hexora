//! `hexora oob` — the out-of-band collaborator: run it, mint payloads, poll for callbacks.
//!
//! Confirms blind vulnerabilities (SSRF, XXE, blind injection) by making the target reach out
//! to a server you control and watching it arrive. You run `oob serve` on a host you control,
//! mint a payload into a target field, and poll for the callback it provokes.

use std::sync::Arc;
use std::time::Duration;

use hexora_engine::guard::ScopeGuard;
use hexora_engine::transport::{HttpTransport, Origin, SendOptions};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_oob::{poll, serve, serve_all, Collaborator, PayloadMode};
use hexora_types::http::{HttpRequest, HttpService};
use hexora_types::scope::{Scope, ScopeRule};
use hexora_types::{HexoraError, Result};

/// Runtime for the blocking CLI to drive async OOB calls.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))
}

/// `hexora oob serve` — run the collaborator, catching HTTP (and optionally DNS) callbacks.
pub fn serve_cmd(listen: &str, dns: Option<&str>, answer_ip: &str) -> Result<()> {
    println!("Collaborator listening on {listen} (HTTP). Payloads that call back here are recorded.");
    let runtime = runtime()?;
    match dns {
        Some(dns_addr) => {
            let ip = answer_ip.parse().map_err(|_| {
                HexoraError::invalid_input("answer-ip", format!("{answer_ip:?} is not an IPv4 address"))
            })?;
            println!("DNS listening on {dns_addr}, answering A queries with {answer_ip}.");
            println!("Mint a subdomain payload with `oob mint --server <domain> --subdomain`; Ctrl-C to stop.");
            runtime.block_on(serve_all(listen, dns_addr, ip))
        }
        None => {
            println!("Mint one with `hexora oob mint --server <this host>`; Ctrl-C to stop.");
            runtime.block_on(serve(listen))
        }
    }
}

/// `hexora oob mint` — print a fresh payload URL and its token.
pub fn mint_cmd(server: &str, subdomain: bool, https: bool, json: bool) -> Result<()> {
    let mode = if subdomain {
        PayloadMode::Subdomain
    } else {
        PayloadMode::Path
    };
    let mut collaborator = Collaborator::new(server, mode);
    if https {
        collaborator = collaborator.https_payloads();
    }
    let (token, url) = collaborator.mint();

    if json {
        println!("{}", serde_json::json!({ "token": token, "payload": url }));
        return Ok(());
    }
    println!("payload: {url}");
    println!("token:   {token}");
    println!();
    println!("Place the payload in a field you suspect is processed out of band, then:");
    println!("  hexora oob poll --server {server} --token {token}");
    Ok(())
}

/// `hexora oob poll` — fetch the interactions recorded for a token.
pub fn poll_cmd(server: &str, token: &str, json: bool) -> Result<()> {
    let interactions = runtime()?.block_on(poll(server, token))?;

    if json {
        println!("{}", serde_json::to_string(&interactions).unwrap_or_else(|_| "[]".into()));
        return Ok(());
    }
    if interactions.is_empty() {
        println!("No interactions yet for {token}.");
        println!();
        println!("Nothing has called back. That is not proof of safety — a target may call");
        println!("back slowly, or only resolve DNS (not yet caught). Poll again in a moment.");
        return Ok(());
    }
    println!("{} interaction(s) — the target reached the collaborator:", interactions.len());
    for interaction in &interactions {
        println!(
            "  {} {} {} from {} at {}",
            interaction.protocol.to_uppercase(),
            interaction.method,
            interaction.path,
            interaction.source,
            interaction.at,
        );
    }
    println!();
    println!("A callback carrying this token proves the target processed the payload out of");
    println!("band — the confirmation a blind vulnerability otherwise cannot give.");
    Ok(())
}

/// Options for `hexora oob test`.
pub struct TestArgs<'a> {
    /// The target URL, with the query parameters to test (e.g. `?url=…`).
    pub url: &'a str,
    /// The collaborator authority to mint payloads against and poll.
    pub server: &'a str,
    /// The method (default GET).
    pub method: Option<&'a str>,
    /// Extra headers, `Name: value`.
    pub headers: &'a [String],
    /// Seconds to wait for callbacks before polling.
    pub wait: u64,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Do not ask before sending.
    pub yes: bool,
    pub json: bool,
}

/// `hexora oob test` — inject an OOB payload into each query parameter and poll for callbacks.
///
/// A callback proves the target used the parameter value to make an out-of-band request — a
/// blind SSRF, or an injection that fetched a URL. Blind by nature: the response says nothing,
/// so the collaborator is the only witness.
pub fn test_cmd(args: TestArgs<'_>) -> Result<()> {
    let (service, path) = HttpService::parse_url(args.url)?;
    let params = query_params(&path);
    if params.is_empty() {
        return Err(HexoraError::invalid_input(
            "url",
            "no query parameters to test; give a URL with a ?parameter=value to inject into",
        ));
    }

    if !args.json {
        println!("Out-of-band parameter test");
        println!("  target:       {} {}", args.method.unwrap_or("GET"), args.url);
        println!("  parameters:   {}", params.join(", "));
        println!("  collaborator: {}", args.server);
        println!();
        println!(
            "This sends {} request(s) with a collaborator payload in each parameter. Only test \
             systems you are authorized to test.",
            params.len()
        );
        if !args.yes && !crate::proxy::confirm("Send these probes?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(HexoraError::invalid_input(
            "--yes",
            "an OOB test sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let scope = Scope::new().include(ScopeRule::host(service.host.clone()));
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, Arc::new(scope));
    let collaborator = Collaborator::new(args.server, PayloadMode::Path);
    let options = SendOptions::automated(Origin::Scanner);
    let method = args.method.unwrap_or("GET").to_string();
    let extra = parse_headers(args.headers)?;

    let hits = runtime()?.block_on(async {
        // Send one probe per parameter, each carrying its own token.
        let mut probes: Vec<(String, String)> = Vec::new(); // (token, parameter)
        for param in &params {
            let (token, payload) = collaborator.mint();
            let mut request =
                HttpRequest::get(service.clone(), set_query_param(&path, param, &payload));
            request.method = method.clone();
            for (name, value) in &extra {
                request.headers.set(name, value.clone());
            }
            // Blind: the response tells us nothing, so it is not read.
            let _ = guard.send(request, options.clone()).await;
            probes.push((token, param.clone()));
        }

        // Give the target time to make its out-of-band request, then poll each token.
        tokio::time::sleep(Duration::from_secs(args.wait)).await;

        let mut hits: Vec<(String, Vec<hexora_oob::Interaction>)> = Vec::new();
        for (token, param) in &probes {
            let interactions = collaborator.poll(token).await.unwrap_or_default();
            if !interactions.is_empty() {
                hits.push((param.clone(), interactions));
            }
        }
        hits
    });

    if args.json {
        let payload = serde_json::json!({
            "target": args.url,
            "confirmed": !hits.is_empty(),
            "parameters": hits.iter().map(|(p, i)| serde_json::json!({
                "parameter": p,
                "interactions": i,
            })).collect::<Vec<_>>(),
        });
        println!("{payload}");
        return Ok(());
    }

    println!();
    if hits.is_empty() {
        println!("No out-of-band interactions. None of the {} parameter(s) caused a callback", params.len());
        println!("within {}s. That is not proof of safety — a target may call back more slowly,", args.wait);
        println!("or only resolve DNS (not yet caught). Raise --wait, or test again.");
    } else {
        println!("OUT-OF-BAND INTERACTION CONFIRMED ({}):", hits.len());
        for (param, interactions) in &hits {
            println!("  parameter `{param}` — the target reached the collaborator:");
            for interaction in interactions {
                println!(
                    "    {} {} {} from {} at {}",
                    interaction.protocol.to_uppercase(),
                    interaction.method,
                    interaction.path,
                    interaction.source,
                    interaction.at,
                );
            }
        }
        println!();
        println!("The target used a parameter value to make a request to a server it does not");
        println!("control — a blind SSRF or an injection that fetched a URL. The response never");
        println!("showed it; the callback is the proof.");
    }
    Ok(())
}

/// The names of the query parameters in a request target.
fn query_params(path: &str) -> Vec<String> {
    let Some((_, query)) = path.split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').map_or(pair, |(k, _)| k).to_string())
        .collect()
}

/// Replaces the value of `name` in the target's query string with a percent-encoded `value`.
fn set_query_param(path: &str, name: &str, value: &str) -> String {
    let (base, query) = path.split_once('?').unwrap_or((path, ""));
    let pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(k, _)| k);
            if key == name {
                format!("{name}={}", percent_encode(value))
            } else {
                pair.to_string()
            }
        })
        .collect();
    format!("{base}?{}", pairs.join("&"))
}

/// Percent-encodes a value for a query string.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Parses `Name: value` headers.
fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for item in raw {
        let (name, value) = item.split_once(':').ok_or_else(|| {
            HexoraError::invalid_input("header", format!("{item:?} is not `Name: value`"))
        })?;
        out.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parameters_are_enumerated() {
        assert_eq!(query_params("/s?url=x&q=y"), vec!["url", "q"]);
        assert!(query_params("/s").is_empty());
    }

    #[test]
    fn a_parameter_value_is_replaced_and_encoded() {
        let out = set_query_param("/s?url=orig&q=y", "url", "http://c/tok");
        assert_eq!(out, "/s?url=http%3A%2F%2Fc%2Ftok&q=y");
    }
}
