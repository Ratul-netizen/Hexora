//! `hexora repeat` — take a request out of history, change it, send it again.
//!
//! The editing loop is deliberately the shell's rather than a bespoke one: the request
//! is written to a file, `$EDITOR` opens it, and whatever comes back is sent. A tester
//! already has an editor they are fast in, and a repeater that made them learn a worse
//! one would be a step backwards.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_repeater::{Repeater, ResponseDiff, Sent};
use hexora_types::ids::RequestId;
use hexora_types::raw::RequestMode;
use hexora_types::scope::Scope;
use hexora_types::{HexoraError, Result};

/// Options for `hexora repeat`.
pub struct RepeatArgs<'a> {
    pub project: &'a Path,
    pub id: &'a str,
    /// Open the request in `$EDITOR` before sending.
    pub edit: bool,
    /// Print the request that would be sent and stop.
    pub dry_run: bool,
    /// Show the response body as well as the head.
    pub show_body: bool,
    /// Do not verify upstream certificates.
    pub insecure: bool,
    /// Edit and send the request as bytes rather than as a message.
    pub raw: bool,
    pub json: bool,
}

/// Options for `hexora repeat --diff`.
pub struct DiffArgs<'a> {
    pub project: &'a Path,
    pub before: &'a str,
    pub after: &'a str,
    pub json: bool,
}

/// Options for `hexora repeat --tree`.
pub struct TreeArgs<'a> {
    pub project: &'a Path,
    pub id: &'a str,
    pub json: bool,
}

/// Loads a request, optionally edits it, sends it, and reports what changed.
pub fn run(args: RepeatArgs<'_>) -> Result<()> {
    let project = open(args.project)?;
    let id: RequestId = args.id.parse()?;
    let store = Arc::new(project.traffic());

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // An empty scope does not block a repeater send — the tester chose to send it —
    // but the decision is still reported so an accidental resend against production
    // is visible rather than silent.
    let guard = ScopeGuard::new(transport, Arc::new(Scope::new()));
    let repeater = Repeater::new(guard, store);

    let mut draft = repeater.draft_from(id)?;
    // Asked for explicitly, and it sticks: a request that was captured raw comes back
    // raw whether or not the flag is given, and `--raw` converts a structured one.
    // Nothing here switches a draft back, because that would be the tool deciding it
    // knew better than the bytes.
    if args.raw {
        draft = draft.into_raw();
    }
    if args.edit {
        let edited = edit_in_editor(&draft.to_raw())?;
        draft.apply_raw(&edited, repeater.limits())?;
    }

    let warnings = draft.warnings();
    let mode = draft.mode();

    if args.dry_run {
        if args.json {
            let payload = serde_json::json!({
                "request": String::from_utf8_lossy(&draft.to_raw()),
                "url": draft.request.url(),
                "mode": mode.as_str(),
                "warnings": warnings.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "scope": describe(repeater.decide(&draft)),
            });
            println!("{payload}");
        } else {
            print!("{}", String::from_utf8_lossy(&draft.to_raw()));
            println!();
            print_mode(mode);
            print_warnings(&warnings);
            println!("Not sent (--dry-run).");
        }
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    let sent = runtime.block_on(repeater.send(&draft))?;
    let diff = repeater.diff_against_parent(&sent)?;

    if args.json {
        print_json(&sent, diff.as_ref(), &warnings, args.show_body, mode);
    } else {
        print_mode(mode);
        print_human(&sent, diff.as_ref(), &warnings, args.show_body);
    }
    Ok(())
}

/// Says which mode the request went out in, before anything about the response.
///
/// Only for raw: structured is what every other command does, and a line saying so on
/// every send would be noise people stop reading. Raw is the one that changes what
/// "send this" means, so it is the one that gets announced.
fn print_mode(mode: RequestMode) {
    if mode == RequestMode::Raw {
        println!(
            "Raw mode: these bytes are sent exactly as written. Nothing is normalized, \
             framed or corrected."
        );
    }
}

/// Compares two stored exchanges without sending anything.
pub fn diff(args: DiffArgs<'_>) -> Result<()> {
    let project = open(args.project)?;
    let store = Arc::new(project.traffic());
    let repeater = Repeater::new(
        ScopeGuard::new(TcpTransport::new(), Arc::new(Scope::new())),
        store,
    );

    let diff = repeater.diff(args.before.parse()?, args.after.parse()?)?;
    if args.json {
        println!("{}", diff_json(&diff));
    } else {
        print_diff(&diff);
    }
    Ok(())
}

/// Prints every send derived from a request.
pub fn tree(args: TreeArgs<'_>) -> Result<()> {
    let project = open(args.project)?;
    let store = project.traffic();
    let root: RequestId = args.id.parse()?;
    let children = store.children(root)?;

    if args.json {
        let payload = serde_json::json!({
            "root": root.to_string(),
            "branches": children.iter().map(ToString::to_string).collect::<Vec<_>>(),
        });
        println!("{payload}");
        return Ok(());
    }

    let stored = store.request(root)?;
    println!(
        "{} {}{}",
        stored.method,
        stored.service.origin(),
        stored.path
    );
    println!("  {root}");
    if children.is_empty() {
        println!();
        println!("No variants yet. Create one with:");
        println!("  hexora repeat {} {root} --edit", args.project.display());
        return Ok(());
    }
    for (i, child) in children.iter().enumerate() {
        let last = i + 1 == children.len();
        let branch = if last { "└─" } else { "├─" };
        let variant = store.request(*child)?;
        let status = store
            .response_head(*child)
            .map(|(s, _, _, _)| s.to_string())
            .unwrap_or_else(|_| "—".into());
        println!(
            "  {branch} {child}  {status:>3} {} {}",
            variant.method, variant.path
        );
    }
    Ok(())
}

/// Opens the raw request in `$EDITOR` and returns what was saved.
fn edit_in_editor(original: &[u8]) -> Result<Vec<u8>> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| default_editor().to_string());

    let dir = std::env::temp_dir();
    let path: PathBuf = dir.join(format!("hexora-request-{}.http", std::process::id()));
    std::fs::write(&path, original)
        .map_err(|e| HexoraError::Internal(format!("writing {}: {e}", path.display())))?;

    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| {
            HexoraError::Internal(format!(
                "could not run {editor:?}: {e}. Set $EDITOR to an editor you have."
            ))
        })?;
    if !status.success() {
        // The file is left in place: an editor that exited badly may still have
        // saved work, and deleting it would throw that away.
        return Err(HexoraError::Internal(format!(
            "{editor} exited with {status}; the request is still at {}",
            path.display()
        )));
    }

    let edited = std::fs::read(&path)
        .map_err(|e| HexoraError::Internal(format!("reading {}: {e}", path.display())))?;
    let _ = std::fs::remove_file(&path);
    Ok(edited)
}

fn default_editor() -> &'static str {
    if cfg!(windows) {
        "notepad"
    } else {
        "vi"
    }
}

fn describe(decision: ScopeDecision) -> &'static str {
    match decision {
        ScopeDecision::Allowed => "in scope",
        ScopeDecision::AllowedOutOfScope => "out of scope",
        ScopeDecision::Refused => "refused",
    }
}

fn print_warnings(warnings: &[hexora_repeater::Warning]) {
    if warnings.is_empty() {
        return;
    }
    // Reported, never corrected: several of these are the point of the request.
    println!("Warnings (the request is sent exactly as written):");
    for warning in warnings {
        let marker = if warning.is_smuggling_signal() {
            "!"
        } else {
            "-"
        };
        println!("  {marker} {warning}");
    }
    println!();
}

fn print_human(
    sent: &Sent,
    diff: Option<&ResponseDiff>,
    warnings: &[hexora_repeater::Warning],
    show_body: bool,
) {
    print_warnings(warnings);

    let response = &sent.exchange.response;
    println!(
        "{} {} {}",
        response.version.as_str(),
        response.status,
        response.reason.as_deref().unwrap_or("")
    );
    for header in response.headers.iter() {
        println!("{}: {}", header.name, header.value_lossy());
    }
    println!();

    if show_body {
        let mut out = std::io::stdout();
        let _ = out.write_all(&response.body);
        let _ = out.flush();
        println!();
    } else {
        println!(
            "({} bytes of body; --show-body to print it)",
            response.body.len()
        );
    }

    println!();
    println!("Stored as {}", sent.id);
    if let Some(parent) = sent.parent {
        println!("Derived from {parent}");
    }
    if sent.decision == ScopeDecision::AllowedOutOfScope {
        println!("Note: this target is not in the project scope.");
    }

    if let Some(diff) = diff {
        println!();
        println!("vs the request it came from: {}", diff.summary());
        // Details only when there is something worth reading: after a resend the
        // headline is the point, and listing two noise headers under every send
        // trains people to skip the section that sometimes matters.
        if diff.is_interesting() {
            print_diff_details(diff);
        }
    }
}

/// Prints a comparison, headline first.
///
/// The headline is always printed, including when it is "identical". `hexora repeat
/// --diff` used to print nothing at all for two identical responses, which reads as a
/// command that failed rather than one with an answer — and "identical" is the whole
/// answer for an authorization comparison, where two principals receiving byte-for-byte
/// the same response *is* the finding.
fn print_diff(diff: &ResponseDiff) {
    println!("{}", diff.summary());
    for line in diff_details(diff) {
        println!("{line}");
    }
}

/// Prints the detail under a headline somebody else already wrote.
fn print_diff_details(diff: &ResponseDiff) {
    for line in diff_details(diff) {
        println!("{line}");
    }
}

/// The line-by-line detail under a comparison's headline.
///
/// Built as strings rather than printed directly so the rendering can be tested; the
/// bug this replaced was a comparison that rendered as nothing at all.
fn diff_details(diff: &ResponseDiff) -> Vec<String> {
    let mut lines = Vec::new();
    for change in &diff.changed_headers {
        lines.push(format!(
            "  ~ {}: {} → {}",
            change.name, change.before, change.after
        ));
    }
    for name in &diff.added_headers {
        lines.push(format!("  + {name}"));
    }
    for name in &diff.removed_headers {
        lines.push(format!("  - {name}"));
    }
    if let Some(offset) = diff.first_difference_at {
        lines.push(format!("  body first differs at byte {offset}"));
    }
    if diff.timing_is_significant() {
        lines.push(format!(
            "  timing moved {:+}ms — worth checking against a time-based payload",
            diff.timing_delta_ms()
        ));
    }
    lines
}

fn diff_json(diff: &ResponseDiff) -> serde_json::Value {
    serde_json::json!({
        "identical": diff.is_identical(),
        "interesting": diff.is_interesting(),
        "summary": diff.summary(),
        "status": diff.status,
        "body_length": diff.body_length,
        "bodies_identical": diff.bodies_identical,
        "first_difference_at": diff.first_difference_at,
        "changed_headers": diff.changed_headers.iter().map(|c| serde_json::json!({
            "name": c.name, "before": c.before, "after": c.after,
        })).collect::<Vec<_>>(),
        "added_headers": diff.added_headers,
        "removed_headers": diff.removed_headers,
        "timing_ms": [diff.timing.0, diff.timing.1],
        "timing_delta_ms": diff.timing_delta_ms(),
        "timing_significant": diff.timing_is_significant(),
    })
}

fn print_json(
    sent: &Sent,
    diff: Option<&ResponseDiff>,
    warnings: &[hexora_repeater::Warning],
    show_body: bool,
    mode: RequestMode,
) {
    let response = &sent.exchange.response;
    let payload = serde_json::json!({
        "id": sent.id.to_string(),
        "mode": mode.as_str(),
        "parent": sent.parent.map(|p| p.to_string()),
        "scope": describe(sent.decision),
        "status": response.status,
        "duration_ms": sent.exchange.duration.as_millis(),
        "response_bytes": response.body.len(),
        "body": show_body.then(|| String::from_utf8_lossy(&response.body).into_owned()),
        "warnings": warnings.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "diff": diff.map(diff_json),
    });
    println!("{payload}");
}

fn open(path: &Path) -> Result<hexora_storage::Project> {
    if !path.join("project.db").exists() {
        return Err(HexoraError::not_found(
            "project",
            path.display().to_string(),
        ));
    }
    crate::open_project(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &'static [u8]) -> hexora_types::http::HttpResponse {
        hexora_types::http::HttpResponse {
            status,
            reason: None,
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::from_static(body),
            truncated: false,
        }
    }

    #[test]
    fn two_identical_responses_still_produce_an_answer() {
        // The regression this guards: `--diff` printed nothing at all when the two
        // responses matched, which reads as a broken command. It is also the exact
        // case an authorization comparison cares about — two principals served the
        // same bytes is the finding, not the absence of one.
        let diff = ResponseDiff::compare(&response(200, b"same"), &response(200, b"same"), (1, 1));
        assert_eq!(diff.summary(), "identical");
        assert!(diff.is_identical());
    }

    #[test]
    fn a_changed_status_is_listed_in_the_detail() {
        let diff = ResponseDiff::compare(&response(200, b"a"), &response(403, b"b"), (1, 1));
        let detail = diff_details(&diff).join(" | ");
        assert!(detail.contains("body first differs"), "{detail}");
        assert!(diff.summary().contains("403"), "{}", diff.summary());
    }

    #[test]
    fn an_identical_comparison_has_no_detail_lines_to_show() {
        let diff = ResponseDiff::compare(&response(200, b"same"), &response(200, b"same"), (1, 1));
        assert!(
            diff_details(&diff).is_empty(),
            "the headline carries it; there is nothing underneath"
        );
    }

    fn project_with_one_exchange() -> (tempfile::TempDir, PathBuf, RequestId) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("repeat"), true).unwrap();

        let project = crate::open_project(&path).unwrap();
        let id = project
            .traffic()
            .record(&hexora_storage::CapturedExchange {
                request: hexora_types::http::HttpRequest::get(
                    hexora_types::http::HttpService::new("example.com", 443, true),
                    "/original",
                ),
                response: hexora_types::http::HttpResponse {
                    status: 200,
                    reason: Some("OK".into()),
                    version: hexora_types::http::HttpVersion::Http11,
                    headers: hexora_types::http::Headers::new(),
                    body: bytes::Bytes::from_static(b"body"),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "proxy",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 12,
            })
            .unwrap();
        (dir, path, id)
    }

    #[test]
    fn a_dry_run_prints_the_request_without_sending_it() {
        // The safety valve: a tester can see exactly what would leave the machine.
        let (_dir, path, id) = project_with_one_exchange();
        run(RepeatArgs {
            project: &path,
            id: &id.to_string(),
            edit: false,
            dry_run: true,
            show_body: false,
            insecure: false,
            raw: false,
            json: true,
        })
        .unwrap();
    }

    #[test]
    fn repeating_an_unknown_id_fails_before_any_network_access() {
        let (_dir, path, _id) = project_with_one_exchange();
        let err = run(RepeatArgs {
            project: &path,
            id: &RequestId::new().to_string(),
            edit: false,
            dry_run: false,
            show_body: false,
            insecure: false,
            raw: false,
            json: true,
        })
        .unwrap_err();
        assert_ne!(err.code(), "internal", "{err}");
    }

    #[test]
    fn a_malformed_id_is_rejected_as_bad_input() {
        let (_dir, path, _id) = project_with_one_exchange();
        let err = run(RepeatArgs {
            project: &path,
            id: "not-a-request-id",
            edit: false,
            dry_run: true,
            show_body: false,
            insecure: false,
            raw: false,
            json: true,
        })
        .unwrap_err();
        assert_ne!(err.code(), "internal", "{err}");
    }

    #[test]
    fn repeating_against_a_missing_project_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(RepeatArgs {
            project: &dir.path().join("nope"),
            id: &RequestId::new().to_string(),
            edit: false,
            dry_run: true,
            show_body: false,
            insecure: false,
            raw: false,
            json: true,
        })
        .unwrap_err();
        assert_eq!(err.code(), "not_found");
    }

    #[test]
    fn a_tree_with_no_variants_says_how_to_make_one() {
        let (_dir, path, id) = project_with_one_exchange();
        tree(TreeArgs {
            project: &path,
            id: &id.to_string(),
            json: false,
        })
        .unwrap();
    }

    #[test]
    fn a_tree_lists_the_variants_derived_from_a_request() {
        let (_dir, path, root) = project_with_one_exchange();
        let project = crate::open_project(&path).unwrap();
        let store = project.traffic();

        for suffix in ["/a", "/b"] {
            store
                .record(&hexora_storage::CapturedExchange {
                    request: hexora_types::http::HttpRequest::get(
                        hexora_types::http::HttpService::new("example.com", 443, true),
                        suffix,
                    ),
                    response: hexora_types::http::HttpResponse {
                        status: 403,
                        reason: Some("Forbidden".into()),
                        version: hexora_types::http::HttpVersion::Http11,
                        headers: hexora_types::http::Headers::new(),
                        body: bytes::Bytes::new(),
                        truncated: false,
                    },
                    encoded_body: None,
                    raw_request: None,
                    content_encoding: None,
                    origin: "repeater",
                    identity: None,
                    parent: Some(root),
                    quirks: Vec::new(),
                    tls: None,
                    duration_ms: 8,
                })
                .unwrap();
        }

        tree(TreeArgs {
            project: &path,
            id: &root.to_string(),
            json: true,
        })
        .unwrap();
    }

    #[test]
    fn two_stored_exchanges_can_be_diffed_without_sending_anything() {
        let (_dir, path, before) = project_with_one_exchange();
        let project = crate::open_project(&path).unwrap();
        let after = project
            .traffic()
            .record(&hexora_storage::CapturedExchange {
                request: hexora_types::http::HttpRequest::get(
                    hexora_types::http::HttpService::new("example.com", 443, true),
                    "/original",
                ),
                response: hexora_types::http::HttpResponse {
                    status: 403,
                    reason: Some("Forbidden".into()),
                    version: hexora_types::http::HttpVersion::Http11,
                    headers: hexora_types::http::Headers::new(),
                    body: bytes::Bytes::from_static(b"denied"),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "repeater",
                identity: None,
                parent: Some(before),
                quirks: Vec::new(),
                tls: None,
                duration_ms: 15,
            })
            .unwrap();

        diff(DiffArgs {
            project: &path,
            before: &before.to_string(),
            after: &after.to_string(),
            json: true,
        })
        .unwrap();
    }

    #[test]
    fn the_default_editor_is_one_the_platform_actually_has() {
        // A repeater whose edit command does not exist is a repeater that cannot edit.
        let editor = default_editor();
        assert!(!editor.is_empty());
        if cfg!(windows) {
            assert_eq!(editor, "notepad");
        }
    }
}
