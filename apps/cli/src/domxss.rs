//! `hexora domxss` — drive a real browser to find DOM-based XSS (Burp's DOM Invader).
//!
//! DOM XSS never reaches the server, so nothing in captured traffic can reveal it. This drives
//! an installed Chrome/Edge over CDP: it wraps the dangerous DOM sinks before the page loads,
//! navigates with a unique canary in each client-side source, and reports which sinks the canary
//! reached — a proven source→sink flow.

use std::time::Duration;

use hexora_types::{HexoraError, Result};

/// Options for `hexora domxss`.
pub struct Args<'a> {
    /// The page URL to test.
    pub url: &'a str,
    /// Show the browser window instead of running it headless.
    pub headed: bool,
    /// Seconds to wait for each navigation to load.
    pub timeout: u64,
    /// Do not ask before driving the browser.
    pub yes: bool,
    pub json: bool,
}

/// Runs the DOM-XSS test against one page.
pub fn run(args: Args<'_>) -> Result<()> {
    if !args.json {
        println!("DOM XSS test");
        println!("  page: {}", args.url);
        println!("  sources: location.hash, location.search");
        println!();
        println!("This launches a browser and navigates to the page with a canary in each source.");
        println!("Only test pages you are authorized to test.");
        if !args.yes && !crate::proxy::confirm("Drive the browser?")? {
            println!("Nothing was done.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(HexoraError::invalid_input(
            "--yes",
            "a DOM-XSS test drives a browser, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;
    let report = runtime.block_on(hexora_browser::domxss::test(
        args.url,
        !args.headed,
        Duration::from_secs(args.timeout),
    ))?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "target": report.target,
                "vulnerable": report.vulnerable(),
                "sources_tested": report.sources_tested,
                "hits": report.hits.iter().map(|h| serde_json::json!({
                    "source": h.source,
                    "sink": h.sink,
                    "sample": h.sample,
                })).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!();
    if report.vulnerable() {
        println!("DOM XSS FLOW CONFIRMED ({}):", report.hits.len());
        for hit in &report.hits {
            println!("  {} -> {}", hit.source, hit.sink);
            println!("    the sink received: {}", hit.sample);
        }
        println!();
        println!("A client-side source flowed into a dangerous sink inside the page's own");
        println!("JavaScript. Whether it is exploitable depends on the page's encoding and");
        println!("framework — confirm the canary can carry markup that the sink then parses.");
    } else {
        println!("No source reached an instrumented sink. That is a result about these two");
        println!("sources and the sinks this build wraps (innerHTML, outerHTML,");
        println!("insertAdjacentHTML, document.write, eval, string timers), not a guarantee.");
    }
    Ok(())
}
