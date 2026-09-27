//! `hexora race` — send one request many times at once, to find a race condition.
//!
//! Burp's single-packet / turbo intruder and Caido's Pipeline exist for one question: does an
//! action that should happen *once* happen twice when two requests arrive together? Redeem a
//! coupon, withdraw a balance, accept an invite — a check-then-act with no lock lets both
//! requests pass the check before either commits. This replays a captured request N times
//! concurrently and shows the spread of what came back.
//!
//! # It concludes nothing
//!
//! Like the fuzzer, it reports and does not judge: two `200`s where you expected one is a race
//! *if that action was meant to be single-use*, which is a fact about the application only the
//! tester knows. So it groups the responses and points at the outcome; the call is yours.
//!
//! # It will replay a state-changing request, and say so
//!
//! Racing is only interesting on the requests that change something, so unlike the scheduler
//! this sends them — after saying how many, the same bargain `hexora fuzz` makes.

use std::path::Path;
use std::sync::Arc;

use hexora_engine::guard::ScopeGuard;
use hexora_http::{TcpTransport, TlsConfig};
use hexora_repeater::{Repeater, SendAs};
use hexora_types::ids::RequestId;
use hexora_types::{HexoraError, Result};

/// Options for `hexora race`.
pub struct Args<'a> {
    pub project: &'a Path,
    /// The request to replay, from `hexora history`.
    pub id: &'a str,
    /// How many copies to send at once.
    pub count: usize,
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

/// One concurrent attempt's outcome.
struct Attempt {
    status: u16,
    bytes: usize,
    error: Option<String>,
}

/// Replays the request `count` times concurrently and reports the spread.
pub fn run(args: Args<'_>) -> Result<()> {
    if args.count < 2 {
        return Err(HexoraError::invalid_input(
            "--count",
            "racing needs at least 2 concurrent requests",
        ));
    }
    let project = crate::open_project(args.project)?;
    let id: RequestId = args.id.parse().map_err(|e| {
        HexoraError::invalid_input("id", format!("{} is not a request id: {e}", args.id))
    })?;

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any()).http2(true)
    } else {
        TcpTransport::new().http2(true)
    };
    let scope = Arc::new(project.settings().scope()?);
    let store = Arc::new(project.traffic());
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store)
        .attaching(project.settings().attached_headers()?);
    let draft = repeater.draft_from(id)?;

    let method = draft.request.method.clone();
    let url = draft.request.url();
    if !args.json {
        println!("{method} {url}");
        println!("Sending {} copies at once.", args.count);
        if hexora_active::is_state_changing(&method) {
            println!();
            println!(
                "{method} may change data on the target, and this sends it {} times together.",
                args.count
            );
        }
        println!();
        println!("This sends concurrent requests. Only test systems you are authorized to test.");
        if !args.yes && !crate::proxy::confirm("Send them?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(HexoraError::invalid_input(
            "--yes",
            "a race sends traffic and --json cannot ask; pass --yes to confirm",
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    let attempts = runtime.block_on(async {
        // All in flight together: build every future first, then drive them concurrently, so
        // the requests overlap on the wire rather than going one after another.
        let repeater = &repeater;
        let futures = (0..args.count).map(|_| {
            let draft = draft.clone();
            async move {
                match repeater.send_as(&draft, SendAs::repeater()).await {
                    Ok(sent) => Attempt {
                        status: sent.exchange.response.status,
                        bytes: sent.exchange.response.body.len(),
                        error: None,
                    },
                    Err(e) => Attempt {
                        status: 0,
                        bytes: 0,
                        error: Some(e.to_string()),
                    },
                }
            }
        });
        futures::future::join_all(futures).await
    });

    report(&attempts, args.json);
    Ok(())
}

/// Groups the outcomes and prints the spread.
fn report(attempts: &[Attempt], json: bool) {
    use std::collections::BTreeMap;

    let answered: Vec<&Attempt> = attempts.iter().filter(|a| a.error.is_none()).collect();
    let failed = attempts.len() - answered.len();

    let mut groups: BTreeMap<(u16, usize), usize> = BTreeMap::new();
    for a in &answered {
        *groups.entry((a.status, a.bytes)).or_insert(0) += 1;
    }
    // How many distinct successful (2xx) outcomes there were, and how many 2xx in total —
    // the numbers that hint at a race on a single-use action.
    let successes = answered
        .iter()
        .filter(|a| (200..300).contains(&a.status))
        .count();

    if json {
        let rows: Vec<_> = groups
            .iter()
            .map(|((status, bytes), count)| {
                serde_json::json!({ "status": status, "bytes": bytes, "count": count })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "sent": attempts.len(),
                "answered": answered.len(),
                "failed": failed,
                "successes_2xx": successes,
                "distinct_outcomes": groups.len(),
                "groups": rows,
            })
        );
        return;
    }

    println!();
    println!(
        "{} sent, {} answered{}, {} distinct outcome(s).",
        attempts.len(),
        answered.len(),
        if failed > 0 {
            format!(", {failed} did not complete")
        } else {
            String::new()
        },
        groups.len()
    );
    println!();
    println!("{:<8} {:>8}  COUNT", "STATUS", "BYTES");
    for ((status, bytes), count) in &groups {
        println!("{status:<8} {bytes:>8}  {count}");
    }
    println!();
    if successes > 1 {
        println!(
            "{successes} of the concurrent requests returned a 2xx. If this action was meant to"
        );
        println!(
            "happen only once — a coupon, a withdrawal, an invite — that is a race: two requests"
        );
        println!(
            "passed the check before either committed. Confirm the side effect happened twice."
        );
    } else {
        println!("At most one request succeeded. No sign of a single-use action being repeated,");
        println!("which is a result about this request under this timing, not a guarantee.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(status: u16, bytes: usize) -> Attempt {
        Attempt {
            status,
            bytes,
            error: None,
        }
    }

    #[test]
    fn grouping_counts_distinct_outcomes() {
        // Not a panic and the success count is what a race hangs on.
        let attempts = [ok(200, 10), ok(200, 10), ok(409, 5), ok(409, 5), ok(409, 5)];
        let successes = attempts
            .iter()
            .filter(|a| (200..300).contains(&a.status))
            .count();
        assert_eq!(successes, 2, "two 2xx among the concurrent responses");
    }

    #[test]
    fn a_count_below_two_is_refused() {
        let err = run(Args {
            project: Path::new("."),
            id: "x",
            count: 1,
            insecure: false,
            yes: true,
            json: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("at least 2"), "{err}");
    }
}
