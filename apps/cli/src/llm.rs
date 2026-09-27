//! `hexora llm` — test an LLM-backed endpoint for prompt injection.
//!
//! Points the injection probes at one endpoint the tester named. It sends traffic, so it is
//! gated like the active scanner and asks before sending. The endpoint's host is the scope:
//! naming it is the tester's consent, and the guard refuses anything else.

use std::sync::Arc;

use hexora_engine::guard::ScopeGuard;
use hexora_http::{TcpTransport, TlsConfig};
use hexora_llm::{test, test_leakage, test_output_handling, Target, PROMPT_PLACEHOLDER};
use hexora_types::http::{Header, HttpService};
use hexora_types::scope::{Scope, ScopeRule};
use hexora_types::{HexoraError, Result};

/// The default request body: an OpenAI-style chat call with the prompt in the user turn.
const DEFAULT_TEMPLATE: &str =
    r#"{"messages":[{"role":"user","content":"{{PROMPT}}"}]}"#;

/// Options for `hexora llm`.
pub struct Args<'a> {
    /// The endpoint URL.
    pub url: &'a str,
    /// The request body template, with `{{PROMPT}}` where the user prompt goes.
    pub template: Option<&'a str>,
    /// Read the template from a file instead.
    pub template_file: Option<&'a std::path::Path>,
    /// The method (default `POST`).
    pub method: Option<&'a str>,
    /// Extra headers, `Name: value`.
    pub headers: &'a [String],
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Do not ask before sending.
    pub yes: bool,
    pub json: bool,
}

/// Runs the prompt-injection probes against the endpoint.
pub fn run(args: Args<'_>) -> Result<()> {
    let (service, path) = HttpService::parse_url(args.url)?;

    let template = match (args.template, args.template_file) {
        (Some(_), Some(_)) => {
            return Err(HexoraError::invalid_input(
                "template",
                "pass --template or --template-file, not both",
            ))
        }
        (Some(t), None) => t.to_string(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| HexoraError::invalid_input("template-file", format!("{}: {e}", path.display())))?,
        (None, None) => DEFAULT_TEMPLATE.to_string(),
    };
    if !template.contains(PROMPT_PLACEHOLDER) {
        return Err(HexoraError::invalid_input(
            "template",
            format!("the body template must contain the {PROMPT_PLACEHOLDER} placeholder"),
        ));
    }

    let headers = parse_headers(args.headers)?;

    let target = Target {
        service: service.clone(),
        path,
        method: args.method.unwrap_or("POST").to_string(),
        headers,
        body_template: template,
    };

    if !args.json {
        println!("Prompt-injection test");
        println!("  endpoint: {} {}", target.method, args.url);
        let total = hexora_llm::probes().len() + hexora_llm::extraction_probes().len() + 1 + 2;
        println!(
            "  probes:   {} injection, {} extraction (+1 control), 2 output-handling",
            hexora_llm::probes().len(),
            hexora_llm::extraction_probes().len()
        );
        println!();
        println!("This sends {total} requests to the endpoint. Only test systems you are authorized to test.");
        if !args.yes && !crate::proxy::confirm("Send these probes?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(HexoraError::invalid_input(
            "--yes",
            "an LLM test sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    // The endpoint's host is the scope: the tester named it, and the guard refuses anything
    // a probe's payload might otherwise steer the request toward.
    let scope = Scope::new().include(ScopeRule::host(service.host.clone()));
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, Arc::new(scope));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;
    let report = runtime.block_on(test(&guard, &target));
    let leak = runtime.block_on(test_leakage(&guard, &target));
    let output = runtime.block_on(test_output_handling(&guard, &target));

    if args.json {
        print_json(args.url, &report, &leak, &output);
    } else {
        print_human(&report, &leak, &output);
    }
    Ok(())
}

fn parse_headers(raw: &[String]) -> Result<Vec<Header>> {
    let mut out = Vec::new();
    for item in raw {
        let (name, value) = item.split_once(':').ok_or_else(|| {
            HexoraError::invalid_input("header", format!("{item:?} is not `Name: value`"))
        })?;
        out.push(Header::new(name.trim(), value.trim()));
    }
    Ok(out)
}

fn print_human(
    report: &hexora_llm::Report,
    leak: &hexora_llm::LeakReport,
    output: &hexora_llm::OutputReport,
) {
    println!();
    println!("{} injection probe(s) sent.", report.tested);
    if report.vulnerable() {
        println!();
        println!("PROMPT INJECTION CONFIRMED ({}):", report.injections.len());
        for injection in &report.injections {
            println!(
                "  [{}] {} — the model emitted the injected canary {}",
                injection.probe_id,
                injection.category.label(),
                injection.canary
            );
        }
        println!();
        println!("The application's own instructions were overridden by user input: an");
        println!("injected instruction to output a random token was obeyed, and the token");
        println!("came back. Treat any downstream use of this model's output as attacker-");
        println!("controlled.");
    } else {
        println!();
        println!("No prompt injection confirmed. Each probe instructed the model to emit a");
        println!("random token; none came back. This is a refutation of these payloads, not");
        println!("a guarantee the endpoint is safe against all injection.");
    }

    // System-prompt / data leakage — leads, not confirmations.
    println!();
    if leak.any() {
        println!("POSSIBLE SYSTEM-PROMPT DISCLOSURE ({}) — leads to verify:", leak.disclosures.len());
        for disclosure in &leak.disclosures {
            println!(
                "  [{}] the model returned instruction-like content a benign question did not",
                disclosure.probe_id
            );
            println!("    signals: {}", disclosure.signals.join(", "));
            println!("    excerpt: {}", disclosure.snippet);
        }
        println!();
        println!("These are heuristic: a model can also invent plausible-looking instructions.");
        println!("Confirm the excerpt is the endpoint's actual hidden prompt before reporting.");
    } else {
        println!("No system-prompt disclosure elicited by the extraction probes.");
    }

    // Insecure output handling — the injection-to-impact chain.
    println!();
    if output.any() {
        println!("INSECURE OUTPUT HANDLING ({}):", output.findings.len());
        for finding in &output.findings {
            println!(
                "  [{}] the model emitted `<`/`>` unencoded — {}",
                finding.probe_id,
                finding.context.label()
            );
            println!("    marker returned raw: {}", finding.marker);
        }
        println!();
        println!("The model can be made to emit active characters that came back unencoded.");
        println!("Anywhere this output is rendered as markup — a chat UI, an email, a report —");
        println!("that is cross-site scripting via the model. Encode model output at the sink.");
    } else {
        println!("Model output came back encoded (or the marker did not survive): no unsafe");
        println!("output handling seen at this endpoint.");
    }

    let errors: Vec<&String> = report
        .errors
        .iter()
        .chain(leak.errors.iter())
        .chain(output.errors.iter())
        .collect();
    if !errors.is_empty() {
        println!();
        println!("Not sent ({}):", errors.len());
        for error in &errors {
            println!("  {error}");
        }
    }
}

fn print_json(
    url: &str,
    report: &hexora_llm::Report,
    leak: &hexora_llm::LeakReport,
    output: &hexora_llm::OutputReport,
) {
    println!(
        "{}",
        serde_json::json!({
            "endpoint": url,
            "tested": report.tested,
            "vulnerable": report.vulnerable(),
            "unsafe_output": output.findings.iter().map(|f| serde_json::json!({
                "probe": f.probe_id,
                "context": f.context.label(),
                "marker": f.marker,
            })).collect::<Vec<_>>(),
            "disclosures": leak.disclosures.iter().map(|d| serde_json::json!({
                "probe": d.probe_id,
                "signals": d.signals,
                "excerpt": d.snippet,
            })).collect::<Vec<_>>(),
            "injections": report.injections.iter().map(|i| serde_json::json!({
                "probe": i.probe_id,
                "category": i.category.label(),
                "canary": i.canary,
            })).collect::<Vec<_>>(),
            "errors": report.errors,
        })
    );
}
