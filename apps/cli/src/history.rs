//! `hexora history` — read back what the proxy captured.
//!
//! The proxy prints exchanges as they happen, which is useful while browsing and
//! useless afterwards. This reads the project instead, so a session from yesterday is
//! as available as the one running now.

use std::path::Path;

use hexora_storage::repository::{Cursor, Limit};
use hexora_types::ids::RequestId;
use hexora_types::{HexoraError, Result};

/// Options for `hexora history`.
pub struct HistoryArgs<'a> {
    pub project: &'a Path,
    pub limit: u32,
    pub after: Option<&'a str>,
    pub json: bool,
}

/// Options for `hexora history --body`.
pub struct BodyArgs<'a> {
    pub project: &'a Path,
    pub id: &'a str,
    /// Print the body as it arrived on the wire, before content decoding.
    pub wire: bool,
}

/// Lists captured exchanges, newest first.
pub fn list(args: HistoryArgs<'_>) -> Result<()> {
    let project = open(args.project)?;
    let store = project.traffic();

    let after = args.after.map(|c| Cursor(c.to_owned()));
    let page = store.history(after.as_ref(), Limit::new(args.limit))?;
    let total = store.count()?;

    if args.json {
        let items: Vec<_> = page
            .items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "id": item.id.to_string(),
                    "method": item.method,
                    "url": item.url,
                    "status": item.status,
                    "response_bytes": item.response_bytes,
                    "duration_ms": item.duration_ms,
                    "sent_at": item.sent_at,
                    "quirks": item.quirks,
                    "secure": item.secure,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "total": total,
            "items": items,
            "next": page.next.as_ref().map(|c| c.0.clone()),
        });
        println!("{payload}");
        return Ok(());
    }

    if page.items.is_empty() {
        println!("No captured traffic in {}.", args.project.display());
        println!();
        println!("Run the proxy against this project to record some:");
        println!("  hexora proxy --project {}", args.project.display());
        return Ok(());
    }

    println!(
        "{:<38} {:>3} {:<6} {:>8} {:>7}  URL",
        "ID", "", "METHOD", "BYTES", "TIME"
    );
    for item in &page.items {
        let status = item
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".into());
        let duration = item
            .duration_ms
            .map(|d| format!("{d}ms"))
            .unwrap_or_else(|| "—".into());
        // A trailing marker rather than a column, so the common case stays narrow.
        let quirks = if item.quirks.is_empty() {
            String::new()
        } else {
            format!("  [{}]", item.quirks.join(","))
        };
        println!(
            "{:<38} {status:>3} {:<6} {:>8} {duration:>7}  {}{quirks}",
            item.id.to_string(),
            item.method,
            item.response_bytes,
            item.url,
        );
    }

    println!();
    println!("{} of {total} shown", page.items.len());
    if let Some(next) = &page.next {
        println!(
            "Next page: hexora history {} --after {}",
            args.project.display(),
            next.0
        );
    }
    Ok(())
}

/// Writes one captured response body to stdout.
///
/// Raw bytes, unmodified: a body is evidence, and prettifying it here would mean the
/// thing piped into a diff or a hash is not the thing the server sent.
pub fn body(args: BodyArgs<'_>) -> Result<()> {
    use std::io::Write;

    let project = open(args.project)?;
    let id: RequestId = args.id.parse()?;
    let bytes = project.traffic().response_body(id, args.wire)?;

    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| HexoraError::Internal(format!("writing the body to stdout: {e}")))
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

    /// Returns the temporary root and the project directory inside it.
    ///
    /// A subdirectory, not the temporary root itself: `open_project` refuses a
    /// directory that already exists without a `project.db`, which is what stops a
    /// typo turning an unrelated folder into a project.
    fn project_with_traffic(exchanges: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("test"), true).unwrap();

        let project = crate::open_project(&path).unwrap();
        let store = project.traffic();
        for i in 0..exchanges {
            store
                .record(&hexora_storage::CapturedExchange {
                    request: hexora_types::http::HttpRequest::get(
                        hexora_types::http::HttpService::new("example.com", 443, true),
                        format!("/{i}"),
                    ),
                    response: hexora_types::http::HttpResponse {
                        status: 200,
                        reason: Some("OK".into()),
                        version: hexora_types::http::HttpVersion::Http11,
                        headers: hexora_types::http::Headers::new(),
                        body: bytes::Bytes::from(format!("body {i}")),
                        truncated: false,
                    },
                    encoded_body: None,
                    content_encoding: None,
                    origin: "proxy",
                    quirks: Vec::new(),
                    tls: None,
                    duration_ms: 5,
                })
                .unwrap();
        }
        (dir, path)
    }

    #[test]
    fn history_on_an_empty_project_says_so_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("empty"), true).unwrap();
        list(HistoryArgs {
            project: &path,
            limit: 100,
            after: None,
            json: false,
        })
        .unwrap();
    }

    #[test]
    fn history_on_a_missing_project_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = list(HistoryArgs {
            project: &dir.path().join("nope"),
            limit: 100,
            after: None,
            json: false,
        })
        .unwrap_err();
        assert_eq!(err.code(), "not_found");
    }

    #[test]
    fn history_lists_what_was_captured() {
        let (_dir, path) = project_with_traffic(3);
        list(HistoryArgs {
            project: &path,
            limit: 100,
            after: None,
            json: true,
        })
        .unwrap();
    }

    #[test]
    fn a_page_limit_is_honoured_and_offers_a_cursor() {
        let (_dir, path) = project_with_traffic(5);
        let project = crate::open_project(&path).unwrap();
        let page = project.traffic().history(None, Limit::new(2)).unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(page.next.is_some(), "a truncated page must offer a cursor");
    }

    #[test]
    fn a_body_can_be_read_back_by_id() {
        let (_dir, path) = project_with_traffic(1);
        let project = crate::open_project(&path).unwrap();
        let page = project.traffic().history(None, Limit::default()).unwrap();
        let id = page.items[0].id;

        body(BodyArgs {
            project: &path,
            id: &id.to_string(),
            wire: false,
        })
        .unwrap();
    }

    #[test]
    fn a_malformed_id_is_reported_as_bad_input_not_as_missing_traffic() {
        let (_dir, path) = project_with_traffic(1);
        let err = body(BodyArgs {
            project: &path,
            id: "not-a-uuid",
            wire: false,
        })
        .unwrap_err();
        assert_ne!(err.code(), "internal", "{err}");
    }
}
