//! The IPC command surface.
//!
//! Every command the frontend can invoke lives here, and nowhere else. Two reasons:
//!
//! * **Auditability.** The set of things the UI can ask the engine to do is the
//!   desktop client's whole attack surface. Keeping it in one module means reviewing
//!   it is reading one file. The functions are deliberately thin — the work lives in
//!   [`crate::state`], [`crate::preview`] and the core crates — so that this file
//!   stays readable as the surface grows.
//! * **Macro hygiene.** `#[tauri::command]` generates helper macros named after the
//!   function. In the crate root those collide with the re-export the macro also
//!   emits (`E0255`), so commands must live in a submodule.
//!
//! # Errors
//!
//! Commands return `Result<_, String>` because that is what crosses the IPC boundary
//! usefully. The string is the engine's own error message, which already names the
//! field or file at fault; nothing is invented here.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_proxy::{
    trust, CertificateAuthority, Fanout, InterceptionPolicy, ProjectCapture, ProxyConfig,
    ProxyServer, TrustState,
};
use hexora_repeater::{Repeater, Warning};
use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::Project;
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;
use hexora_types::scope::Scope;
use serde::Serialize;
use tauri::{Emitter, State};

use crate::preview::{header_block, BodyPreview};
use crate::state::{AppState, RunningProxy};

/// The event name carrying newly captured exchanges to the window.
pub const TRAFFIC_EVENT: &str = "hexora://traffic";

type CommandResult<T> = std::result::Result<T, String>;

/// Renders an engine error for the frontend.
fn fail(error: impl std::fmt::Display) -> String {
    error.to_string()
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// What the frontend needs in order to decide whether it can talk to this engine.
#[derive(Debug, Clone, Serialize)]
pub struct EngineInfo {
    /// The engine's package version.
    pub version: String,
    /// The IPC contract version.
    ///
    /// The UI refuses to proceed on a mismatch rather than misinterpreting messages
    /// from an engine it does not understand. A security tool that quietly displays
    /// the wrong request is worse than one that will not start.
    pub rpc_contract_version: u32,
    /// The project schema revision this build writes.
    pub schema_version: u32,
    /// The current development milestone, surfaced in the UI.
    pub milestone: &'static str,
}

/// Returns engine version and contract information.
#[tauri::command]
pub fn engine_info() -> EngineInfo {
    EngineInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        rpc_contract_version: hexora_types::RPC_CONTRACT_VERSION,
        schema_version: hexora_storage::migrations::target_version(),
        milestone: "M5",
    }
}

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

/// A project, as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    pub path: String,
    pub name: String,
    pub targets: u64,
    pub requests: u64,
    pub schema_version: u32,
}

/// Opens a project directory, creating it if it is not one yet.
#[tauri::command]
pub fn project_open(state: State<'_, AppState>, path: String) -> CommandResult<ProjectSummary> {
    let path = PathBuf::from(path);

    // Refused rather than adopted: turning an arbitrary folder into a project because
    // of a mistyped path is not recoverable by the person who did it.
    if path.exists() && !path.join("project.db").exists() && !is_empty_dir(&path) {
        return Err(format!(
            "{} exists and is not a Hexora project",
            path.display()
        ));
    }

    let existed = path.join("project.db").exists();
    let project = Project::open(&path).map_err(fail)?;
    let name = if existed {
        read_name(&project).map_err(fail)?
    } else {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Untitled engagement".to_string());
        write_name(&project, &name).map_err(fail)?;
        name
    };

    let summary = summarise(&path, &name, &project).map_err(fail)?;
    state.open_project(&path, name, project).map_err(fail)?;
    Ok(summary)
}

/// Reports the open project, if there is one.
#[tauri::command]
pub fn project_current(state: State<'_, AppState>) -> CommandResult<Option<ProjectSummary>> {
    let Some((path, name)) = state.project_summary().map_err(fail)? else {
        return Ok(None);
    };
    let project = Project::open(&path).map_err(fail)?;
    Ok(Some(summarise(&path, &name, &project).map_err(fail)?))
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

/// Where the proxy is, or that it is not running.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub address: Option<String>,
}

/// Starts the proxy against the open project.
#[tauri::command]
pub async fn proxy_start(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    listen: String,
    intercept_only: Vec<String>,
    insecure_upstream: bool,
) -> CommandResult<ProxyStatus> {
    let bind: SocketAddr = listen
        .parse()
        .map_err(|e| format!("{listen:?} is not an address to listen on: {e}"))?;

    let store = state.traffic().map_err(fail)?;
    let project = state.project_path().map_err(fail)?;

    let ca_dir = default_ca_dir()?;
    let ca = Arc::new(CertificateAuthority::load_or_create(&ca_dir).map_err(fail)?);

    let interception = if intercept_only.is_empty() {
        InterceptionPolicy::intercept_all()
    } else {
        InterceptionPolicy::only(intercept_only)
    };

    let transport = if insecure_upstream {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };

    // Capture first, notify second. If the notification observer ever fails, the
    // exchange has already been recorded.
    let observers = Fanout::new()
        .with(ProjectCapture::new(store))
        .with(WindowNotifier { app: app.clone() });

    let server = ProxyServer::bind(
        ProxyConfig {
            bind,
            interception,
            ..Default::default()
        },
        // An empty scope does not block proxied traffic: the tester's browser asked
        // for it, and the proxy must see a host before it can be scoped.
        Arc::new(Scope::new()),
        transport,
        Arc::new(observers),
        ca,
    )
    .await
    .map_err(fail)?;

    let addr = server.local_addr().map_err(fail)?;
    // tokio::spawn rather than tauri::async_runtime::spawn: the handle is stored in
    // AppState, which must not depend on Tauri. Tauri's runtime is tokio, and this
    // runs inside an async command, so the current runtime is the right one.
    let handle = tokio::spawn(async move {
        if let Err(e) = server.serve().await {
            tracing::error!("the proxy stopped: {e}");
        }
    });

    state
        .set_proxy(RunningProxy::new(addr, project, handle))
        .map_err(fail)?;

    Ok(ProxyStatus {
        running: true,
        address: Some(addr.to_string()),
    })
}

/// Stops the proxy.
#[tauri::command]
pub fn proxy_stop(state: State<'_, AppState>) -> CommandResult<ProxyStatus> {
    state.stop_proxy().map_err(fail)?;
    Ok(ProxyStatus {
        running: false,
        address: None,
    })
}

/// Reports whether the proxy is listening.
#[tauri::command]
pub fn proxy_status(state: State<'_, AppState>) -> CommandResult<ProxyStatus> {
    let address = state.proxy_address().map_err(fail)?;
    Ok(ProxyStatus {
        running: address.is_some(),
        address: address.map(|a| a.to_string()),
    })
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

/// One row of the history table.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryRow {
    pub id: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub response_bytes: u64,
    pub duration_ms: Option<u32>,
    pub sent_at: String,
    pub secure: bool,
    pub quirks: Vec<String>,
}

/// A page of history.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryPage {
    pub rows: Vec<HistoryRow>,
    pub next: Option<String>,
    pub total: u64,
}

/// Lists captured exchanges, newest first.
#[tauri::command]
pub fn history_list(
    state: State<'_, AppState>,
    after: Option<String>,
    limit: u32,
) -> CommandResult<HistoryPage> {
    let store = state.traffic().map_err(fail)?;
    let cursor = after.map(Cursor);
    let page = store
        .history(cursor.as_ref(), Limit::new(limit))
        .map_err(fail)?;
    let total = store.count().map_err(fail)?;

    Ok(HistoryPage {
        rows: page.items.into_iter().map(row).collect(),
        next: page.next.map(|c| c.0),
        total,
    })
}

/// A full exchange, ready to display.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeDetail {
    pub id: String,
    pub parent: Option<String>,
    pub origin: String,
    pub url: String,
    pub request_head: String,
    pub request_body: BodyPreview,
    pub response_head: String,
    pub response_body: BodyPreview,
    pub sent_at: String,
}

/// Reads one exchange in full.
#[tauri::command]
pub fn history_detail(state: State<'_, AppState>, id: String) -> CommandResult<ExchangeDetail> {
    let store = state.traffic().map_err(fail)?;
    let request_id: RequestId = id.parse().map_err(fail)?;

    let request = store.request(request_id).map_err(fail)?;
    let (status, reason, version, response_headers) =
        store.response_head(request_id).map_err(fail)?;
    let response_body = store.response_body(request_id, false).map_err(fail)?;

    let request_head = format!(
        "{} {} {}\r\n{}",
        request.method,
        request.path,
        request.http_version,
        header_block(&request.headers_raw)
    );
    let response_head = format!(
        "{version} {status}{}\r\n{}",
        reason.map(|r| format!(" {r}")).unwrap_or_default(),
        header_block(&response_headers)
    );

    Ok(ExchangeDetail {
        id,
        parent: request.parent.map(|p| p.to_string()),
        origin: request.origin,
        url: format!("{}{}", request.service.origin(), request.path),
        request_head,
        request_body: BodyPreview::of(&request.body),
        response_head,
        response_body: BodyPreview::of(&response_body),
        sent_at: request.sent_at,
    })
}

// ---------------------------------------------------------------------------
// Repeater
// ---------------------------------------------------------------------------

/// A request loaded for editing.
#[derive(Debug, Clone, Serialize)]
pub struct DraftView {
    pub raw: String,
    pub url: String,
    pub parent: Option<String>,
    pub warnings: Vec<String>,
}

/// Loads a stored request as an editable draft.
#[tauri::command]
pub fn repeater_draft(state: State<'_, AppState>, id: String) -> CommandResult<DraftView> {
    let repeater = build_repeater(&state, false)?;
    let draft = repeater
        .draft_from(id.parse().map_err(fail)?)
        .map_err(fail)?;

    Ok(DraftView {
        raw: String::from_utf8_lossy(&draft.to_raw()).into_owned(),
        url: draft.request.url(),
        parent: draft.parent.map(|p| p.to_string()),
        warnings: warnings(&draft.warnings()),
    })
}

/// What came back from a repeater send.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    pub id: String,
    pub parent: Option<String>,
    pub status: u16,
    pub duration_ms: u64,
    pub out_of_scope: bool,
    pub response_head: String,
    pub response_body: BodyPreview,
    pub warnings: Vec<String>,
    pub diff: Option<DiffView>,
}

/// A response comparison, as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct DiffView {
    pub summary: String,
    pub interesting: bool,
    pub identical: bool,
    pub status: Option<(u16, u16)>,
    pub changed_headers: Vec<(String, String, String)>,
    pub added_headers: Vec<String>,
    pub removed_headers: Vec<String>,
    pub first_difference_at: Option<usize>,
    pub timing_delta_ms: i64,
    pub timing_significant: bool,
}

/// Sends edited bytes and records the result.
#[tauri::command]
pub async fn repeater_send(
    state: State<'_, AppState>,
    raw: String,
    parent: Option<String>,
    insecure: bool,
) -> CommandResult<SendResult> {
    let repeater = build_repeater(&state, insecure)?;

    // The parent supplies the connection target, so editing `Host` tests virtual-host
    // routing rather than silently sending the request somewhere else.
    let parent_id: Option<RequestId> = match &parent {
        Some(id) => Some(id.parse().map_err(fail)?),
        None => None,
    };
    let mut draft = match parent_id {
        Some(id) => repeater.draft_from(id).map_err(fail)?,
        None => return Err("a repeater send needs a request to start from".to_string()),
    };
    draft
        .apply_raw(raw.as_bytes(), repeater.limits())
        .map_err(fail)?;

    let warnings = warnings(&draft.warnings());
    let sent = repeater.send(&draft).await.map_err(fail)?;
    let diff = repeater
        .diff_against_parent(&sent)
        .map_err(fail)?
        .map(diff_view);

    let response = &sent.exchange.response;
    let mut head = format!(
        "{} {}{}\r\n",
        response.version.as_str(),
        response.status,
        response
            .reason
            .as_ref()
            .map(|r| format!(" {r}"))
            .unwrap_or_default()
    );
    for header in response.headers.iter() {
        head.push_str(&format!("{}: {}\r\n", header.name, header.value_lossy()));
    }

    Ok(SendResult {
        id: sent.id.to_string(),
        parent: sent.parent.map(|p| p.to_string()),
        status: response.status,
        duration_ms: sent.exchange.duration.as_millis().min(u128::from(u64::MAX)) as u64,
        out_of_scope: sent.decision == ScopeDecision::AllowedOutOfScope,
        response_head: head,
        response_body: BodyPreview::of(&response.body),
        warnings,
        diff,
    })
}

/// Lists the variants derived from a request.
#[tauri::command]
pub fn repeater_tree(state: State<'_, AppState>, id: String) -> CommandResult<Vec<HistoryRow>> {
    let store = state.traffic().map_err(fail)?;
    let root: RequestId = id.parse().map_err(fail)?;
    let children = store.children(root).map_err(fail)?;

    // Read from history so the rows carry the same fields the table shows, rather
    // than a second, subtly different shape.
    let page = store.history(None, Limit::new(Limit::MAX)).map_err(fail)?;
    Ok(page
        .items
        .into_iter()
        .filter(|item| children.contains(&item.id))
        .map(row)
        .collect())
}

// ---------------------------------------------------------------------------
// Certificate authority
// ---------------------------------------------------------------------------

/// The CA and whether this machine trusts it.
#[derive(Debug, Clone, Serialize)]
pub struct CaStatus {
    pub directory: String,
    pub fingerprint: String,
    pub state: String,
    pub trusted: bool,
}

/// Reports the CA and its trust state.
#[tauri::command]
pub fn ca_status() -> CommandResult<CaStatus> {
    let dir = default_ca_dir()?;
    let ca = CertificateAuthority::load_or_create(&dir).map_err(fail)?;
    let state = trust::status(&ca.fingerprints());

    Ok(CaStatus {
        directory: dir.display().to_string(),
        fingerprint: ca.fingerprint_display(),
        trusted: state == TrustState::Trusted,
        state: state.to_string(),
    })
}

/// Installs the CA into this user's trust store.
///
/// The UI is responsible for asking first and for showing the fingerprint. This
/// command exists because someone pressed a button that said so; it is never called
/// as a side effect of anything.
#[tauri::command]
pub fn ca_install() -> CommandResult<CaStatus> {
    let dir = default_ca_dir()?;
    let ca = CertificateAuthority::load_or_create(&dir).map_err(fail)?;
    trust::install(&dir.join("hexora-ca.crt"), &ca.fingerprints()).map_err(fail)?;
    ca_status()
}

/// Removes the CA from this user's trust store, leaving the files.
#[tauri::command]
pub fn ca_untrust() -> CommandResult<CaStatus> {
    let dir = default_ca_dir()?;
    let ca = CertificateAuthority::load_or_create(&dir).map_err(fail)?;
    trust::uninstall(&ca.fingerprints()).map_err(fail)?;
    ca_status()
}

// ---------------------------------------------------------------------------
// Support
// ---------------------------------------------------------------------------

/// Pushes each captured exchange to the window.
struct WindowNotifier {
    app: tauri::AppHandle,
}

impl hexora_proxy::ExchangeObserver for WindowNotifier {
    fn observe(&self, exchange: &hexora_engine::transport::Exchange, decision: ScopeDecision) {
        // A summary, not the exchange: the row is what the table needs, and shipping
        // whole bodies through IPC for traffic nobody has clicked on would stall the
        // window during a crawl.
        let payload = serde_json::json!({
            "method": exchange.request.method,
            "url": exchange.request.url(),
            "status": exchange.response.status,
            "duration_ms": exchange.duration.as_millis(),
            "out_of_scope": decision == ScopeDecision::AllowedOutOfScope,
        });
        if let Err(e) = self.app.emit(TRAFFIC_EVENT, payload) {
            // Logged, never propagated: a closed window must not stop capture.
            tracing::debug!("could not notify the window of an exchange: {e}");
        }
    }
}

fn build_repeater(
    state: &State<'_, AppState>,
    insecure: bool,
) -> CommandResult<Repeater<TcpTransport>> {
    let store = state.traffic().map_err(fail)?;
    let transport = if insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    Ok(
        Repeater::new(ScopeGuard::new(transport, Arc::new(Scope::new())), store)
            .with_limits(Limits::default()),
    )
}

fn warnings(warnings: &[Warning]) -> Vec<String> {
    warnings.iter().map(ToString::to_string).collect()
}

fn diff_view(diff: hexora_repeater::ResponseDiff) -> DiffView {
    DiffView {
        summary: diff.summary(),
        interesting: diff.is_interesting(),
        identical: diff.is_identical(),
        status: diff.status,
        changed_headers: diff
            .changed_headers
            .iter()
            .map(|c| (c.name.clone(), c.before.clone(), c.after.clone()))
            .collect(),
        added_headers: diff.added_headers.clone(),
        removed_headers: diff.removed_headers.clone(),
        first_difference_at: diff.first_difference_at,
        timing_significant: diff.timing_is_significant(),
        timing_delta_ms: diff
            .timing_delta_ms()
            .clamp(i64::MIN as i128, i64::MAX as i128) as i64,
    }
}

fn row(item: hexora_storage::StoredTraffic) -> HistoryRow {
    HistoryRow {
        id: item.id.to_string(),
        method: item.method,
        url: item.url,
        status: item.status,
        response_bytes: item.response_bytes,
        duration_ms: item.duration_ms,
        sent_at: item.sent_at,
        secure: item.secure,
        quirks: item.quirks,
    }
}

fn summarise(
    path: &Path,
    name: &str,
    project: &Project,
) -> hexora_types::error::Result<ProjectSummary> {
    let conn = project.metadata().connection()?;
    let count = |table: &str| -> hexora_types::error::Result<i64> {
        // The table name is never user input: both call sites pass a literal.
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .map_err(|e| hexora_types::HexoraError::Storage(e.to_string()))
    };
    let targets = count("targets")?;
    let requests = count("requests")?;

    Ok(ProjectSummary {
        path: path.display().to_string(),
        name: name.to_string(),
        targets: targets as u64,
        requests: requests as u64,
        schema_version: project.metadata().schema_version()?,
    })
}

fn read_name(project: &Project) -> hexora_types::error::Result<String> {
    let conn = project.metadata().connection()?;
    Ok(conn
        .query_row("SELECT name FROM project LIMIT 1", [], |r| r.get(0))
        .unwrap_or_else(|_| "Untitled engagement".to_string()))
}

fn write_name(project: &Project, name: &str) -> hexora_types::error::Result<()> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    project
        .metadata()
        .connection()?
        .execute(
            "INSERT INTO project (id, name, created_at, updated_at)              VALUES ('prj_default', ?1, ?2, ?2)",
            hexora_storage::rusqlite::params![name, now],
        )
        .map_err(|e| hexora_types::HexoraError::Storage(e.to_string()))?;
    Ok(())
}

fn is_empty_dir(path: &Path) -> bool {
    std::fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
}

/// Where the CA lives when nobody has said otherwise.
///
/// The same location the CLI uses, so `hexora ca --status` in a terminal reports on
/// the same certificate the window installed.
fn default_ca_dir() -> CommandResult<PathBuf> {
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| "cannot determine a home directory".to_string())?;
    Ok(PathBuf::from(base).join(".hexora").join("ca"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shell_reports_the_same_contract_version_as_the_core() {
        let info = engine_info();
        assert_eq!(
            info.rpc_contract_version,
            hexora_types::RPC_CONTRACT_VERSION
        );
        assert_eq!(
            info.schema_version,
            hexora_storage::migrations::target_version()
        );
    }

    #[test]
    fn engine_info_serializes_for_the_frontend() {
        let json = serde_json::to_value(engine_info()).unwrap();
        // The frontend keys off this field to decide whether it can proceed.
        assert!(json.get("rpc_contract_version").is_some(), "{json}");
    }

    #[test]
    fn a_history_row_carries_every_column_the_table_renders() {
        // A missing field renders as an empty cell rather than an error, so the shape
        // is asserted here instead of being discovered by eye.
        let row = row(hexora_storage::StoredTraffic {
            id: RequestId::new(),
            target: hexora_types::ids::TargetId::new(),
            method: "GET".into(),
            url: "https://example.com/".into(),
            status: Some(200),
            response_bytes: 10,
            duration_ms: Some(5),
            sent_at: "2026-01-01T00:00:00Z".into(),
            quirks: vec!["BareLf".into()],
            secure: true,
        });
        let json = serde_json::to_value(&row).unwrap();
        for key in [
            "id",
            "method",
            "url",
            "status",
            "response_bytes",
            "duration_ms",
            "sent_at",
            "secure",
            "quirks",
        ] {
            assert!(json.get(key).is_some(), "{key} missing from {json}");
        }
    }

    #[test]
    fn the_ca_directory_matches_the_one_the_cli_uses() {
        // Otherwise the window installs one certificate and `hexora ca --status`
        // reports on another.
        let dir = default_ca_dir().unwrap();
        assert!(dir.ends_with("ca"), "{dir:?}");
        assert!(dir.to_string_lossy().contains(".hexora"), "{dir:?}");
    }

    #[test]
    fn an_empty_directory_may_become_a_project_but_a_full_one_may_not() {
        // A mistyped path must not quietly adopt somebody's Documents folder.
        let dir = tempfile::tempdir().unwrap();
        assert!(is_empty_dir(dir.path()));

        std::fs::write(dir.path().join("notes.txt"), "unrelated").unwrap();
        assert!(!is_empty_dir(dir.path()));
    }

    #[test]
    fn a_diff_view_reports_a_timing_delta_the_ui_can_render() {
        let before = hexora_types::http::HttpResponse {
            status: 200,
            reason: None,
            version: hexora_types::http::HttpVersion::Http11,
            headers: hexora_types::http::Headers::new(),
            body: bytes::Bytes::from_static(b"x"),
            truncated: false,
        };
        let diff = hexora_repeater::ResponseDiff::compare(&before, &before, (100, 4200));
        let view = diff_view(diff);

        assert_eq!(view.timing_delta_ms, 4100);
        assert!(view.timing_significant);
        assert!(view.interesting, "a slow identical response is the signal");
    }
}
