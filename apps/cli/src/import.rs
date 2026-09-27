//! `nullhawk import openapi` — turn an API description into traffic the scanner can work over.
//!
//! An API has no HTML links, so the crawler cannot find its endpoints. Its OpenAPI/Swagger spec
//! is the map instead: this reads it, builds a request per operation (path parameters filled,
//! required query parameters appended), and — with `--send` — sends the safe ones through the
//! project's scope guard and records them, exactly as the crawler records what it fetches.
//!
//! # Safe by default, and it says what it will do
//!
//! Dry-run by default: it parses and lists, and sends nothing. `--send` sends only safe methods
//! (GET/HEAD/OPTIONS). A body-bearing or deleting operation (POST/PUT/PATCH/DELETE) is listed
//! but skipped unless `--include-writes` is given and confirmed, the same bargain the fuzzer and
//! crawler make. Everything goes through the guard, so an out-of-scope host is refused.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_import::{ApiSpec, Operation};
use nullhawk_storage::CapturedExchange;
use nullhawk_types::http::{HttpRequest, HttpService};
use nullhawk_types::{NullhawkError, Result};

/// Options for `nullhawk import openapi`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// The spec file (OpenAPI 3.x or Swagger 2.0, JSON or YAML).
    pub spec: &'a Path,
    /// Override the base URL the spec declares (or supply one it omits).
    pub base: Option<&'a str>,
    /// Send the safe operations and record them, rather than only listing.
    pub send: bool,
    /// Also send body-bearing / deleting operations (POST/PUT/PATCH/DELETE).
    pub include_writes: bool,
    /// The most requests to send.
    pub max: Option<usize>,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Send without asking.
    pub yes: bool,
    pub json: bool,
}

/// Whether a method is safe to replay automatically.
fn is_safe(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS")
}

/// Options for `nullhawk import graphql`.
pub struct GraphqlArgs<'a> {
    pub project: &'a Path,
    /// The introspection result (JSON).
    pub spec: &'a Path,
    /// The GraphQL endpoint to POST operations to.
    pub url: &'a str,
    /// Send the operations, rather than only listing.
    pub send: bool,
    /// Also send mutations (they change data).
    pub include_mutations: bool,
    /// The most requests to send.
    pub max: Option<usize>,
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

/// Reads a GraphQL introspection result and either lists or POSTs the operations it implies.
pub fn graphql(args: GraphqlArgs<'_>) -> Result<()> {
    let bytes = std::fs::read(args.spec).map_err(|e| {
        NullhawkError::invalid_input("spec", format!("{}: {e}", args.spec.display()))
    })?;
    let api = nullhawk_import::parse_introspection(&bytes)
        .map_err(|e| NullhawkError::invalid_input("spec", e.message))?;

    if !args.send {
        if args.json {
            let ops: Vec<_> = api
                .operations
                .iter()
                .map(|op| {
                    serde_json::json!({
                        "kind": op.kind,
                        "field": op.field,
                        "document": op.document,
                        "mutation": op.is_mutation(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({ "endpoint": args.url, "operations": ops })
            );
            return Ok(());
        }
        println!("GraphQL endpoint: {}", args.url);
        println!("{} operation(s):", api.operations.len());
        for op in &api.operations {
            let mark = if op.is_mutation() {
                "  [mutation — needs --include-mutations]"
            } else {
                ""
            };
            println!("  {}{mark}", op.document);
        }
        println!();
        println!("Nothing was sent. Re-run with --send to POST the queries into the project.");
        return Ok(());
    }

    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "an import sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let (service, path) = HttpService::parse_url(args.url)?;
    let project = crate::open_project(args.project)?;
    let scope = Arc::new(project.settings().scope()?);
    let attached = project.settings().attached_headers()?;

    let planned: Vec<&nullhawk_import::GraphqlOp> = api
        .operations
        .iter()
        .filter(|op| !op.is_mutation() || args.include_mutations)
        .take(args.max.unwrap_or(usize::MAX))
        .collect();
    let mutations = planned.iter().filter(|op| op.is_mutation()).count();

    if planned.is_empty() {
        println!(
            "No operations to send (all are mutations; pass --include-mutations to send them)."
        );
        return Ok(());
    }

    if !args.json {
        println!(
            "Importing {} GraphQL operation(s) to {}",
            planned.len(),
            args.url
        );
        if mutations > 0 {
            println!("{mutations} of them are mutations and will be sent because --include-mutations was given.");
        }
        println!();
        println!("This sends requests to the API. Only import schemas for systems you are authorized to test.");
        if !args.yes && !crate::proxy::confirm("Send these queries?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, scope);
    let store = project.traffic();
    let options = SendOptions::automated(Origin::Crawler);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;

    let mut recorded = 0usize;
    let mut failed = 0usize;
    runtime.block_on(async {
        for op in &planned {
            let mut request = HttpRequest::get(service.clone(), path.clone());
            request.method = "POST".to_string();
            request.headers.set("Content-Type", "application/json");
            for header in &attached {
                request
                    .headers
                    .set(&header.name, header.value_lossy().into_owned());
            }
            request
                .headers
                .set("Content-Length", op.body.len().to_string());
            request.body = op.body.clone().into_bytes().into();

            match guard.send(request, options.clone()).await {
                Ok(exchange) => {
                    let captured = CapturedExchange {
                        request: exchange.request.clone(),
                        raw_request: exchange.raw_request.clone(),
                        response: exchange.response.clone(),
                        encoded_body: exchange.encoded_body.clone(),
                        content_encoding: exchange.content_encoding.clone(),
                        origin: Origin::Crawler.as_str(),
                        identity: None,
                        parent: None,
                        quirks: Vec::new(),
                        tls: exchange.tls.clone(),
                        duration_ms: exchange.duration.as_millis().min(u128::from(u32::MAX)) as u32,
                    };
                    if store.record(&captured).is_ok() {
                        recorded += 1;
                    } else {
                        failed += 1;
                    }
                }
                Err(_) => failed += 1,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    if args.json {
        println!(
            "{}",
            serde_json::json!({ "recorded": recorded, "failed": failed })
        );
    } else {
        println!();
        println!("{recorded} operation(s) recorded into the project.");
        if failed > 0 {
            println!("{failed} did not complete (out of scope, or the host did not answer).");
        }
        println!(
            "Scan the new traffic with `nullhawk scan passive {}`.",
            args.project.display()
        );
    }
    Ok(())
}

/// Reads and parses the spec, resolves the base URL, and either lists or sends.
pub fn openapi(args: Args<'_>) -> Result<()> {
    let bytes = std::fs::read(args.spec).map_err(|e| {
        NullhawkError::invalid_input("spec", format!("{}: {e}", args.spec.display()))
    })?;
    let spec = nullhawk_import::parse(&bytes)
        .map_err(|e| NullhawkError::invalid_input("spec", e.message))?;

    let base = resolve_base(&spec, args.base)?;

    if !args.send {
        return list(&spec, &base, args.json);
    }

    send(&args, &spec, &base)
}

/// The base URL to build requests against: an explicit override, or the spec's first server.
fn resolve_base(spec: &ApiSpec, override_base: Option<&str>) -> Result<String> {
    if let Some(base) = override_base.map(str::trim).filter(|b| !b.is_empty()) {
        return Ok(base.trim_end_matches('/').to_string());
    }
    match spec.servers.first() {
        Some(server) => Ok(server.trim_end_matches('/').to_string()),
        None => Err(NullhawkError::invalid_input(
            "--base",
            "the spec declares no server URL, so give one with --base https://host",
        )),
    }
}

/// The absolute URL for an operation against the base.
fn url_for(base: &str, op: &Operation) -> String {
    let sep = if op.target.starts_with('/') { "" } else { "/" };
    format!("{base}{sep}{}", op.target)
}

/// Lists the operations without sending anything.
fn list(spec: &ApiSpec, base: &str, json: bool) -> Result<()> {
    if json {
        let ops: Vec<_> = spec
            .operations
            .iter()
            .map(|op| {
                serde_json::json!({
                    "method": op.method,
                    "url": url_for(base, op),
                    "template": op.template,
                    "summary": op.summary,
                    "safe": is_safe(&op.method),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "title": spec.title,
                "base": base,
                "operations": ops,
            })
        );
        return Ok(());
    }

    if let Some(title) = &spec.title {
        println!("{title}");
    }
    println!("Base: {base}");
    println!("{} operation(s):", spec.operations.len());
    for op in &spec.operations {
        let mark = if is_safe(&op.method) {
            ""
        } else {
            "  [write — needs --include-writes]"
        };
        println!("  {:<7} {}{mark}", op.method, url_for(base, op));
    }
    println!();
    println!("Nothing was sent. Re-run with --send to fetch the safe operations into the project.");
    Ok(())
}

/// Sends the selected operations through the guard and records them.
fn send(args: &Args<'_>, spec: &ApiSpec, base: &str) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let scope = Arc::new(project.settings().scope()?);
    let attached = project.settings().attached_headers()?;

    // Which operations will actually go out.
    let planned: Vec<&Operation> = spec
        .operations
        .iter()
        .filter(|op| is_safe(&op.method) || args.include_writes)
        .take(args.max.unwrap_or(usize::MAX))
        .collect();
    let writes = planned.iter().filter(|op| !is_safe(&op.method)).count();

    if planned.is_empty() {
        println!("No operations to send. The spec's operations are all writes; pass --include-writes to send them.");
        return Ok(());
    }

    if !args.json {
        println!("Importing {} operation(s) from {base}", planned.len());
        if writes > 0 {
            println!(
                "{writes} of them are writes (POST/PUT/PATCH/DELETE) and will be sent because \
                 --include-writes was given."
            );
        }
        println!();
        println!("This sends requests to the API. Only import specs for systems you are authorized to test.");
        if !args.yes && !crate::proxy::confirm("Send these requests?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "an import sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, scope);
    let store = project.traffic();
    let options = SendOptions::automated(Origin::Crawler);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;

    let mut recorded = 0usize;
    let mut failed = 0usize;
    runtime.block_on(async {
        for op in &planned {
            let url = url_for(base, op);
            let (service, path) = match HttpService::parse_url(&url) {
                Ok(parts) => parts,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };
            let mut request = HttpRequest::get(service, path);
            request.method = op.method.clone();
            for header in &attached {
                request
                    .headers
                    .set(&header.name, header.value_lossy().into_owned());
            }

            match guard.send(request, options.clone()).await {
                Ok(exchange) => {
                    let captured = CapturedExchange {
                        request: exchange.request.clone(),
                        raw_request: exchange.raw_request.clone(),
                        response: exchange.response.clone(),
                        encoded_body: exchange.encoded_body.clone(),
                        content_encoding: exchange.content_encoding.clone(),
                        origin: Origin::Crawler.as_str(),
                        identity: None,
                        parent: None,
                        quirks: Vec::new(),
                        tls: exchange.tls.clone(),
                        duration_ms: exchange.duration.as_millis().min(u128::from(u32::MAX)) as u32,
                    };
                    if store.record(&captured).is_ok() {
                        recorded += 1;
                    } else {
                        failed += 1;
                    }
                }
                Err(_) => failed += 1,
            }
            // A gentle pace, like the crawler's default, so an import is not a flood.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    if args.json {
        println!(
            "{}",
            serde_json::json!({ "recorded": recorded, "failed": failed, "base": base })
        );
    } else {
        println!();
        println!("{recorded} operation(s) recorded into the project.");
        if failed > 0 {
            println!("{failed} did not complete (out of scope, or the host did not answer).");
        }
        println!(
            "Scan the new traffic with `nullhawk scan passive {}`.",
            args.project.display()
        );
    }
    Ok(())
}
