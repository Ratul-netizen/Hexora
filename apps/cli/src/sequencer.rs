//! `nullhawk sequencer` — how unpredictable is this token?
//!
//! Burp's Sequencer, from samples a tester already has: session ids, CSRF tokens, reset
//! tokens. Feed it a file of tokens, or pull them from captured traffic (a response header, or a
//! named cookie), and it reports the entropy the sample shows and flags the ones that are
//! clearly guessable — a counter, a tiny alphabet, a value that repeats.

use std::path::Path;

use nullhawk_sequencer::{analyze, Report, Verdict};
use nullhawk_storage::repository::{Cursor, Limit};
use nullhawk_types::http::Headers;
use nullhawk_types::{NullhawkError, Result};

/// Options for `nullhawk sequencer`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// A file of tokens, one per line — the source when the tokens are already in hand.
    pub file: Option<&'a Path>,
    /// Extract the value of this response header from captured traffic.
    pub header: Option<&'a str>,
    /// Extract this named cookie's value from `Set-Cookie` in captured traffic.
    pub cookie: Option<&'a str>,
    /// Only consider exchanges matching this query when extracting from traffic.
    pub query: Option<&'a str>,
    /// The most exchanges to scan when extracting.
    pub limit: usize,
    pub json: bool,
}

/// Collects the tokens and analyses them.
pub fn run(args: Args<'_>) -> Result<()> {
    let tokens = match args.file {
        Some(path) => read_file(path)?,
        None => extract_from_traffic(&args)?,
    };

    if tokens.is_empty() {
        return Err(NullhawkError::invalid_input(
            "sequencer",
            "no tokens to analyse — check the --file, or the --header/--cookie and --query used \
             to extract them",
        ));
    }

    let report = analyze(&tokens);
    if args.json {
        print_json(&report);
    } else {
        print_human(&report);
    }
    Ok(())
}

/// Reads a token-per-line file.
fn read_file(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| NullhawkError::invalid_input("--file", format!("{}: {e}", path.display())))?;
    Ok(text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Pulls tokens out of captured traffic by header or cookie name.
fn extract_from_traffic(args: &Args<'_>) -> Result<Vec<String>> {
    let (source_header, cookie_name) = match (args.header, args.cookie) {
        (Some(h), None) => (h.to_string(), None),
        (None, Some(c)) => ("set-cookie".to_string(), Some(c.to_string())),
        (None, None) => {
            return Err(NullhawkError::invalid_input(
                "sequencer",
                "give a source: --file <path>, --header <name>, or --cookie <name>",
            ))
        }
        (Some(_), Some(_)) => {
            return Err(NullhawkError::invalid_input(
                "sequencer",
                "pass --header or --cookie, not both",
            ))
        }
    };

    let project = crate::open_project(args.project)?;
    let store = project.traffic();
    let query = match args.query {
        Some(q) => Some(
            nullhawk_query::Query::parse(q)
                .map_err(|e| NullhawkError::invalid_input("--query", e.message))?,
        ),
        None => None,
    };

    let mut tokens = Vec::new();
    let mut cursor: Option<Cursor> = None;
    'pages: loop {
        let page = store.history(cursor.as_ref(), Limit::new(500))?;
        for row in &page.items {
            if let Some(query) = &query {
                let record = store.query_record(row, query)?;
                if !query.matches(&record) {
                    continue;
                }
            }
            let Ok((_, _, _, headers_raw)) = store.response_head(row.id) else {
                continue;
            };
            let headers = Headers::from_block(&headers_raw);
            match &cookie_name {
                Some(name) => tokens.extend(cookie_values(&headers, name)),
                None => {
                    for header in headers.get_all(&source_header) {
                        tokens.push(header.value_lossy().trim().to_string());
                    }
                }
            }
            if tokens.len() >= args.limit {
                break 'pages;
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    tokens.retain(|t| !t.is_empty());
    Ok(tokens)
}

/// The values a named cookie takes across the `Set-Cookie` headers.
fn cookie_values(headers: &Headers, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for header in headers.get_all("set-cookie") {
        let value = header.value_lossy();
        // `name=value; attributes...` — take the value up to the first `;`.
        let pair = value.split(';').next().unwrap_or("");
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim().eq_ignore_ascii_case(name) {
                out.push(v.trim().to_string());
            }
        }
    }
    out
}

fn print_human(report: &Report) {
    println!(
        "{} sample(s), {} unique, {}-{} chars, charset of {}",
        report.samples, report.unique, report.min_len, report.max_len, report.charset_size
    );
    println!(
        "entropy: {:.2} bits/char -> ~{:.0} bits/token",
        report.bits_per_char, report.bits_per_token
    );
    println!();
    if report.signals.is_empty() {
        println!("No predictability signals.");
    } else {
        println!("Signals:");
        for signal in &report.signals {
            println!("  - {signal}");
        }
    }
    println!();
    println!("Verdict: {}", verdict_line(report.verdict));
    println!();
    println!(
        "An estimate from a sample: a token can look random and still come from a predictable"
    );
    println!("generator. This flags the clearly-weak ones; it does not certify the rest as safe.");
}

fn verdict_line(verdict: Verdict) -> String {
    match verdict {
        Verdict::Insufficient => {
            "insufficient samples — collect more before concluding anything".to_string()
        }
        Verdict::Weak => {
            "weak — these tokens are predictable and should not be relied on".to_string()
        }
        Verdict::Moderate => "moderate — some entropy, but not demonstrably strong".to_string(),
        Verdict::Strong => "strong — consistent with a well-generated random token".to_string(),
    }
}

fn print_json(report: &Report) {
    println!(
        "{}",
        serde_json::json!({
            "samples": report.samples,
            "unique": report.unique,
            "min_len": report.min_len,
            "max_len": report.max_len,
            "charset_size": report.charset_size,
            "bits_per_char": report.bits_per_char,
            "bits_per_token": report.bits_per_token,
            "signals": report.signals,
            "verdict": report.verdict.label(),
        })
    );
}
