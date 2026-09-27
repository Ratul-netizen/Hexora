//! `hexora oob` — the out-of-band collaborator: run it, mint payloads, poll for callbacks.
//!
//! Confirms blind vulnerabilities (SSRF, XXE, blind injection) by making the target reach out
//! to a server you control and watching it arrive. You run `oob serve` on a host you control,
//! mint a payload into a target field, and poll for the callback it provokes.

use hexora_oob::{poll, serve, Collaborator, PayloadMode};
use hexora_types::{HexoraError, Result};

/// Runtime for the blocking CLI to drive async OOB calls.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))
}

/// `hexora oob serve` — run the collaborator, catching HTTP callbacks.
pub fn serve_cmd(listen: &str) -> Result<()> {
    println!("Collaborator listening on {listen}. Payloads that call back here are recorded.");
    println!("Mint one with `hexora oob mint --server <this host>`; Ctrl-C to stop.");
    runtime()?.block_on(serve(listen))
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
