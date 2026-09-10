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

use hexora_authz::construct::ConstructionPlan;
use hexora_authz::{analysis, AuthzTester, Cell, Plan, Verdict};
use hexora_engine::guard::{ScopeDecision, ScopeGuard};
use hexora_http::{TcpTransport, TlsConfig};
use hexora_proxy::{
    trust, CertificateAuthority, Fanout, InterceptionPolicy, ProjectCapture, ProxyConfig,
    ProxyServer, TrustState,
};
use hexora_repeater::{Repeater, Warning};
use hexora_report::{Format, Report, ReportOptions};
use hexora_storage::repository::{Cursor, Limit};
use hexora_storage::{FindingFilter, Project, Recorded};
use hexora_types::finding::{Confidence, Evidence, FindingStatus, Severity};
use hexora_types::identity::{Credential, Identity, PrivilegeLevel};
use hexora_types::ids::RequestId;
use hexora_types::limits::Limits;
use hexora_types::object::{ObjectDeclaration, ObjectLocation};
use hexora_types::redact::Secret;
use hexora_types::scope::{PathMatch, SchemeMatch, Scope, ScopeRule};
use serde::{Deserialize, Serialize};
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
        milestone: "M12.7",
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
    /// The identity the request was sent as, for rows an authorization run produced.
    /// `None` for proxy traffic, which carries whatever credential the browser had.
    pub identity: Option<String>,
    /// `structured` or `raw`. A raw row was sent byte for byte, so its method and
    /// path are a reading of those bytes rather than a description of them.
    pub mode: String,
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
    /// How the request reached the socket.
    pub mode: String,
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

    // A request that was sent raw is shown as the bytes that were sent. Rebuilding it
    // from the columns would put CRLF where the tester wrote LF, and a tidy request
    // line where they may have written something else — a pane that exists to be
    // evidence, showing a request nobody sent.
    let request_head = match (request.mode, &request.raw) {
        (hexora_types::raw::RequestMode::Raw, Some(bytes)) => {
            let raw = hexora_types::raw::RawRequest::new(request.service.clone(), bytes.clone())
                .map_err(fail)?;
            String::from_utf8_lossy(&raw.head()).into_owned()
        }
        _ => format!(
            "{} {} {}\r\n{}",
            request.method,
            request.path,
            request.http_version,
            header_block(&request.headers_raw)
        ),
    };
    let response_head = format!(
        "{version} {status}{}\r\n{}",
        reason.map(|r| format!(" {r}")).unwrap_or_default(),
        header_block(&response_headers)
    );

    Ok(ExchangeDetail {
        id,
        parent: request.parent.map(|p| p.to_string()),
        mode: request.mode.as_str().to_string(),
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
    /// `structured` or `raw` — what pressing Send will actually do with these bytes.
    pub mode: String,
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
        mode: draft.mode().as_str().to_string(),
    })
}

/// What came back from a repeater send.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    pub id: String,
    pub parent: Option<String>,
    /// How the request went out.
    pub mode: String,
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
    request_mode: Option<String>,
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
    // The window asks for a mode explicitly. A request captured raw is already raw
    // when it loads, and asking for raw on a structured draft converts it — which is
    // the only way that conversion ever happens.
    if request_mode.as_deref() == Some("raw") {
        draft = draft.into_raw();
    }
    draft
        .apply_raw(raw.as_bytes(), repeater.limits())
        .map_err(fail)?;

    let warnings = warnings(&draft.warnings());
    let mode = draft.mode();
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
        mode: mode.as_str().to_string(),
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
// Scope
// ---------------------------------------------------------------------------

/// The project's scope, as two lists of readable rules.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeView {
    pub included: Vec<String>,
    pub excluded: Vec<String>,
}

/// Reads the project's scope.
#[tauri::command]
pub fn scope_list(state: State<'_, AppState>) -> CommandResult<ScopeView> {
    let project = open(&state)?;
    Ok(scope_view(&project.settings().scope().map_err(fail)?))
}

/// Declares a host as authorized, or as excluded.
///
/// Returns the whole scope rather than an acknowledgement: widening scope is a
/// decision a tester may have to justify later, so the window shows what it now is
/// rather than what was just added to it.
#[tauri::command]
pub fn scope_add(
    state: State<'_, AppState>,
    host: String,
    path_prefix: Option<String>,
    exclude: bool,
) -> CommandResult<ScopeView> {
    let host = host.trim().to_string();
    if host.is_empty() {
        return Err("a scope rule needs a host".to_string());
    }

    let project = open(&state)?;
    let settings = project.settings();
    let mut scope = settings.scope().map_err(fail)?;

    let rule = ScopeRule {
        host,
        ports: Vec::new(),
        scheme: SchemeMatch::Any,
        path: match path_prefix
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            None => PathMatch::Any,
            Some(prefix) => PathMatch::Prefix {
                value: prefix.to_string(),
            },
        },
    };

    let target = if exclude {
        &mut scope.exclude
    } else {
        &mut scope.include
    };
    if target.contains(&rule) {
        return Err(format!("{} is already in the project scope", rule.host));
    }
    target.push(rule);

    settings.set_scope(&scope).map_err(fail)?;
    Ok(scope_view(&scope))
}

/// Removes every rule for a host, from both lists.
#[tauri::command]
pub fn scope_remove(state: State<'_, AppState>, host: String) -> CommandResult<ScopeView> {
    let project = open(&state)?;
    let settings = project.settings();
    let mut scope = settings.scope().map_err(fail)?;

    let before = scope.include.len() + scope.exclude.len();
    scope.include.retain(|rule| rule.host != host);
    scope.exclude.retain(|rule| rule.host != host);
    if before == scope.include.len() + scope.exclude.len() {
        return Err(format!("no scope rule for {host}"));
    }

    settings.set_scope(&scope).map_err(fail)?;
    Ok(scope_view(&scope))
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// An identity, as the window may show it.
///
/// There is no credential field, in any variant. This is the type that reaches the
/// frontend, and a credential that reaches the frontend is a credential in a devtools
/// console, a screenshot and a crash report.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityView {
    pub id: String,
    pub label: String,
    pub privilege: String,
    /// The *kind* of credential — `bearer`, `cookie`, `none` — never its value.
    pub credential: String,
    pub owns: Vec<String>,
}

/// Lists the identities a project can test as.
#[tauri::command]
pub fn identities_list(state: State<'_, AppState>) -> CommandResult<Vec<IdentityView>> {
    let project = open(&state)?;
    Ok(project
        .identities()
        .list()
        .map_err(fail)?
        .iter()
        .map(identity_view)
        .collect())
}

/// Adds an identity.
///
/// The credential comes either from an environment variable this process can read, or
/// from a value the tester typed. The environment route is offered first and is the
/// one the CLI allows at all: a value typed here crosses the IPC boundary, which is a
/// smaller exposure than a command line that `ps` and shell history can read, but not
/// no exposure. The UI says so at the point of entry rather than here.
#[tauri::command]
pub fn identity_add(
    state: State<'_, AppState>,
    label: String,
    privilege: String,
    kind: String,
    secret: Option<String>,
    from_env: Option<String>,
    owns: Vec<String>,
) -> CommandResult<IdentityView> {
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err("an identity needs a label".to_string());
    }
    let privilege = parse_privilege(&privilege)?;

    let value = match (from_env.as_deref(), secret.as_deref()) {
        (Some(name), _) if !name.trim().is_empty() => Some(
            std::env::var(name.trim())
                .map_err(|_| format!("environment variable {} is not set", name.trim()))?,
        ),
        (_, Some(value)) if !value.is_empty() => Some(value.to_string()),
        _ => None,
    };

    let credential = match value {
        None if privilege == PrivilegeLevel::Anonymous => Credential::None,
        None => {
            return Err(
                "give a credential, either by naming an environment variable or by \
                 entering the value"
                    .to_string(),
            )
        }
        Some(value) => build_credential(&kind, value)?,
    };

    let identity = Identity {
        id: hexora_types::ids::IdentityId::new(),
        label,
        privilege,
        credential,
        extra_headers: Vec::new(),
        owned_object_ids: owns
            .into_iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect(),
    };

    let project = open(&state)?;
    project.identities().put(&identity).map_err(fail)?;
    Ok(identity_view(&identity))
}

/// Removes an identity. Traffic already sent as it is kept, and still names it.
#[tauri::command]
pub fn identity_remove(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    let project = open(&state)?;
    let identity_id: hexora_types::ids::IdentityId = id.parse().map_err(fail)?;
    if !project.identities().delete(identity_id).map_err(fail)? {
        return Err(format!("no identity {id}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Declared objects
// ---------------------------------------------------------------------------

/// A declared object identifier, as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectView {
    pub id: String,
    pub name: String,
    pub value: String,
    /// The owning identity's label, so the list can be read against the claim a
    /// finding makes rather than against an id.
    pub owner: String,
    pub owner_id: String,
    pub location: String,
    pub source_request: Option<String>,
}

/// Lists the objects a project has declared.
#[tauri::command]
pub fn objects_list(state: State<'_, AppState>) -> CommandResult<Vec<ObjectView>> {
    let project = open(&state)?;
    let identities = project.identities();
    Ok(project
        .objects()
        .list()
        .map_err(fail)?
        .into_iter()
        .map(|declaration| object_view(&declaration, &identities))
        .collect())
}

/// Declares an object identifier and who owns it.
///
/// Data entry: nothing is sent. Given a request the value appears in, the location is
/// discovered rather than typed — a tester who has just found an identifier should
/// not also have to count path segments.
#[tauri::command]
pub fn object_add(
    state: State<'_, AppState>,
    value: String,
    owner: String,
    name: String,
    in_request: Option<String>,
) -> CommandResult<Vec<ObjectView>> {
    let project = open(&state)?;
    let identities = project.identities();
    let owner = resolve_identity(&identities, &owner)?;
    let store = project.objects();

    let declarations = match in_request.as_deref().filter(|id| !id.trim().is_empty()) {
        Some(id) => {
            let request_id: RequestId = id.parse().map_err(fail)?;
            let stored = project.traffic().request(request_id).map_err(fail)?;
            let request = rebuild(&stored);
            let locations = hexora_authz::construct::locate(&request, &value);
            if locations.is_empty() {
                return Err(format!(
                    "{value:?} does not appear in that request — not in the path, the \
                     query, a header or the body. Credential headers are never \
                     searched: an Authorization value is a session, not an object."
                ));
            }
            locations
                .into_iter()
                .map(|location| {
                    ObjectDeclaration::new(&name, &value, owner.id, location)
                        .map(|d| d.found_in(request_id))
                        .map_err(fail)
                })
                .collect::<CommandResult<Vec<_>>>()?
        }
        // Without a request to look in there is nowhere to discover. Recording a
        // place it was not found would be a lie a later run would act on.
        None => vec![
            ObjectDeclaration::new(&name, &value, owner.id, ObjectLocation::Anywhere)
                .map_err(fail)?,
        ],
    };

    for declaration in &declarations {
        store.put(declaration).map_err(fail)?;
    }
    objects_list(state)
}

// ---------------------------------------------------------------------------
// Identifier suggestions
// ---------------------------------------------------------------------------

/// One reason a value was suggested, for the window.
#[derive(Debug, Clone, Serialize)]
pub struct SignalView {
    pub kind: String,
    pub weight: i32,
    pub detail: String,
}

/// A suggested identifier, as the window shows it.
///
/// There is deliberately no `owner` field, and there is no command that would fill
/// one in. Ownership belongs to [`ObjectView`], which a human produces by declaring
/// it — a suggestion that could carry an owner would be an assertion nobody made.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateView {
    pub id: String,
    pub value: String,
    pub location: String,
    pub status: String,
    pub score: i32,
    pub strength: String,
    pub occurrences: u32,
    pub live_observations: u32,
    pub signals: Vec<SignalView>,
    pub source_request: Option<String>,
}

fn candidate_view(candidate: &hexora_types::candidate::IdentifierCandidate) -> CandidateView {
    CandidateView {
        id: candidate.id.to_string(),
        value: candidate.value.clone(),
        location: candidate.descriptor.clone(),
        status: candidate.status.as_str().to_string(),
        score: candidate.score,
        strength: candidate.strength().as_str().to_string(),
        occurrences: candidate.occurrences,
        live_observations: candidate.live_observations,
        signals: candidate
            .signals
            .iter()
            .map(|signal| SignalView {
                kind: signal.kind.as_str().to_string(),
                weight: signal.weight,
                detail: signal.detail.clone(),
            })
            .collect(),
        source_request: candidate.source_request.map(|id| id.to_string()),
    }
}

/// Lists the suggestions a project holds, strongest first.
#[tauri::command]
pub fn candidates_list(state: State<'_, AppState>) -> CommandResult<Vec<CandidateView>> {
    let project = open(&state)?;
    Ok(project
        .candidates()
        .list(&hexora_storage::CandidateFilter::default())
        .map_err(fail)?
        .iter()
        .map(candidate_view)
        .collect())
}

/// Reads captured traffic and offers what it finds.
///
/// Sends nothing, changes no stored request or response, and creates no finding. It
/// is a read of the project against itself, which is why the button is safe to press
/// at any point in an engagement.
#[tauri::command]
pub fn candidates_analyze(state: State<'_, AppState>) -> CommandResult<Vec<CandidateView>> {
    let project = open(&state)?;
    hexora_authz::suggest::analyze(
        &project.traffic(),
        &project.objects(),
        &project.candidates(),
    )
    .map_err(fail)?;
    candidates_list(state)
}

/// Records a human's decision about a suggestion.
///
/// Accepting means "this is an identifier". It does not create an
/// [`ObjectDeclaration`], because that would need an owner nobody has named.
#[tauri::command]
pub fn candidate_decide(
    state: State<'_, AppState>,
    id: String,
    status: String,
) -> CommandResult<Vec<CandidateView>> {
    let project = open(&state)?;
    let candidate_id: hexora_types::ids::CandidateId = id.parse().map_err(fail)?;
    let status = hexora_types::candidate::CandidateStatus::parse(&status)
        .ok_or_else(|| format!("{status:?} is not a status a suggestion can be in"))?;
    project
        .candidates()
        .set_status(candidate_id, status)
        .map_err(fail)?;
    candidates_list(state)
}

/// Removes a declaration. Requests already constructed from it keep their record of
/// the substitution they made.
#[tauri::command]
pub fn object_remove(state: State<'_, AppState>, id: String) -> CommandResult<Vec<ObjectView>> {
    let project = open(&state)?;
    let object_id = id.parse().map_err(fail)?;
    if !project.objects().delete(object_id).map_err(fail)? {
        return Err(format!("no object declaration {id}"));
    }
    objects_list(state)
}

// ---------------------------------------------------------------------------
// Authorization matrix
// ---------------------------------------------------------------------------

/// One identity's row in the matrix.
#[derive(Debug, Clone, Serialize)]
pub struct CellView {
    pub identity: String,
    pub label: String,
    pub privilege: String,
    pub request: Option<String>,
    pub status: Option<u16>,
    pub similarity: f32,
    pub outcome: String,
    pub verdict: String,
    pub violation: bool,
    pub leaked_object_ids: Vec<String>,
    pub own_object_ids: Vec<String>,
    pub reproduced: bool,
    pub error: Option<String>,
    /// Why a violation was demoted, when it was.
    pub note: Option<String>,
}

/// One constructed cross-identity attempt, as the window shows it.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptView {
    pub sender: String,
    pub object_name: String,
    pub object_value: String,
    pub owner: String,
    /// What was replaced, and where — the whole substitution in one line.
    pub substitution: String,
    pub location: String,
    pub original_value: String,
    pub request: Option<String>,
    /// The sender's own unmodified send, which the attempt is compared against.
    pub control: Option<String>,
    pub status: Option<u16>,
    pub similarity: f32,
    pub outcome: String,
    pub verdict: String,
    pub violation: bool,
    pub disclosed_object_ids: Vec<String>,
    pub echoed: bool,
    pub own_object_ids: Vec<String>,
    pub reproduced: bool,
    pub error: Option<String>,
    pub note: Option<String>,
}

/// A finished matrix and what it concluded.
#[derive(Debug, Clone, Serialize)]
pub struct MatrixView {
    pub base: String,
    pub method: String,
    pub url: String,
    pub owner: CellView,
    pub cells: Vec<CellView>,
    /// Whether an unauthenticated request received the same resource, which demotes
    /// every per-identity verdict on the endpoint.
    pub appears_public: bool,
    /// Requests that were built rather than replayed, when the run asked for them.
    pub constructed: Vec<AttemptView>,
    /// Combinations that produced no constructed request, and why.
    pub not_constructed: Vec<String>,
    /// The candidate findings the run supports, worst first.
    pub findings: Vec<FindingRow>,
    /// How many of those were written into the project, and how many were updates of
    /// a claim it already held.
    pub saved: usize,
    pub updated: usize,
}

/// What to run, as one argument.
///
/// A struct rather than eight parameters: the run has eight knobs and every one of
/// them changes what the traffic will be, so they are named at the call site in the
/// frontend as well as here.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthzRequest {
    /// The captured request to replay.
    pub id: String,
    /// The identity that request belongs to, by label or id.
    pub owner: String,
    /// Who to replay it as. Empty means every other identity in the project.
    pub identities: Vec<String>,
    /// Whether to add an unauthenticated control.
    pub anonymous: bool,
    /// Whether to replay each violation once more before reporting it.
    pub verify: bool,
    /// Whether to skip verifying the target's TLS certificate.
    pub insecure: bool,
    /// Set by the UI once the tester has confirmed a state-changing replay.
    pub confirm_state_changing: bool,
    /// Whether to write the findings into the project.
    pub save: bool,
    /// Whether to also build cross-identity requests from the declared objects.
    pub construct: bool,
    /// The most constructed requests this run may send.
    pub max_attempts: usize,
}

/// Replays a captured request as several identities.
#[tauri::command]
pub async fn authz_run(
    state: State<'_, AppState>,
    request: AuthzRequest,
) -> CommandResult<MatrixView> {
    let AuthzRequest {
        id,
        owner,
        identities,
        anonymous,
        verify,
        insecure,
        confirm_state_changing,
        save,
        construct,
        max_attempts,
    } = request;
    let project = open(&state)?;
    let base: RequestId = id.parse().map_err(fail)?;
    let identity_store = project.identities();
    let store = Arc::new(project.traffic());

    let owner = resolve_identity(&identity_store, &owner)?;
    let others = if identities.is_empty() {
        identity_store
            .list()
            .map_err(fail)?
            .into_iter()
            .filter(|identity| identity.id != owner.id)
            .collect()
    } else {
        identities
            .iter()
            .map(|who| resolve_identity(&identity_store, who))
            .collect::<CommandResult<Vec<_>>>()?
    };
    if others.is_empty() {
        return Err("there is nobody to compare against: add a second identity first".to_string());
    }

    let transport = if insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    // The project's own scope, not an empty one. A matrix is automated traffic, and
    // the guard refuses automated traffic to hosts nobody has declared.
    let scope = Arc::new(project.settings().scope().map_err(fail)?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store.clone());
    let tester = AuthzTester::new(repeater, store.clone(), identity_store);

    let method = tester.method_of(base).map_err(fail)?;
    if Plan::is_state_changing(&method) && !confirm_state_changing {
        return Err(format!(
            "{method} may change data on the target, and this run would send it {} \
             times. Confirm before running it.",
            others.len() + 1
        ));
    }

    let mut plan = Plan::new(base, owner, others);
    plan.anonymous_control = anonymous;
    plan.verify = verify;

    let matrix = tester.run(&plan).await.map_err(fail)?;
    let target = store.target_of(base).map_err(fail)?;
    let mut findings = analysis::findings(&matrix, target);

    // Constructed attempts run after the matrix and against the same base request, so
    // a tester who only wanted the replay results already has them if this fails.
    let construction = if construct {
        let declarations = project.objects().list().map_err(fail)?;
        if declarations.is_empty() {
            return Err(
                "no objects are declared in this project, so there is nothing \
                        to construct a request for. Declare one first."
                    .to_string(),
            );
        }
        let senders = std::iter::once(plan.owner.clone())
            .chain(plan.others.iter().cloned())
            .collect();
        let construction = tester
            .construct(
                &ConstructionPlan::new(base, senders, declarations)
                    .with_limit(max_attempts)
                    .verifying(verify),
            )
            .await
            .map_err(fail)?;
        findings.extend(analysis::construction_findings(&construction, target));
        Some(construction)
    } else {
        None
    };

    let mut saved = 0;
    let mut updated = 0;
    if save {
        let store = project.findings();
        for finding in &findings {
            match store.record(finding).map_err(fail)? {
                Recorded::Created(_) => saved += 1,
                Recorded::Updated(_) => updated += 1,
            }
        }
    }

    Ok(MatrixView {
        base: matrix.base.to_string(),
        method: matrix.method.clone(),
        url: matrix.url.clone(),
        owner: cell_view(&matrix.owner),
        cells: matrix.cells.iter().map(cell_view).collect(),
        appears_public: matrix.appears_public,
        constructed: construction
            .as_ref()
            .map(|c| c.attempts.iter().map(attempt_view).collect())
            .unwrap_or_default(),
        not_constructed: construction
            .as_ref()
            .map(|c| c.skipped.clone())
            .unwrap_or_default(),
        findings: findings.iter().map(finding_row).collect(),
        saved,
        updated,
    })
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// One row of the findings list.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRow {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub status: String,
    /// Whether this may be presented as an issue rather than a lead.
    pub actionable: bool,
    pub evidence_count: usize,
    pub updated_at: String,
}

/// A page of findings.
#[derive(Debug, Clone, Serialize)]
pub struct FindingsPage {
    pub rows: Vec<FindingRow>,
    pub next: Option<String>,
    pub total: u64,
}

/// Lists findings, worst first.
#[tauri::command]
pub fn findings_list(
    state: State<'_, AppState>,
    severity: Option<String>,
    status: Option<String>,
    actionable: bool,
    after: Option<String>,
    limit: u32,
) -> CommandResult<FindingsPage> {
    let project = open(&state)?;
    let store = project.findings();

    let filter = FindingFilter {
        min_severity: severity.as_deref().map(parse_severity).transpose()?,
        status: status.as_deref().map(parse_status).transpose()?,
        target: None,
        actionable_only: actionable,
    };
    let page = store
        .list(&filter, after.map(Cursor).as_ref(), Limit::new(limit))
        .map_err(fail)?;

    Ok(FindingsPage {
        rows: page.items.iter().map(finding_row).collect(),
        next: page.next.map(|c| c.0),
        total: store.count().map_err(fail)?,
    })
}

/// A finding in full, with its evidence resolved against the project's traffic.
#[derive(Debug, Clone, Serialize)]
pub struct FindingDetail {
    pub row: FindingRow,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub reproduction: String,
    pub location: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub cvss: Option<String>,
    pub created_at: String,
    /// Each piece of evidence as a sentence, with the request ids it rests on so the
    /// window can open them in history.
    pub evidence: Vec<EvidenceView>,
}

/// One piece of evidence, and the exchanges behind it.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceView {
    pub summary: String,
    /// Request ids this evidence cites, in the order they should be read.
    pub requests: Vec<String>,
}

/// Reads one finding in full.
#[tauri::command]
pub fn findings_detail(state: State<'_, AppState>, id: String) -> CommandResult<FindingDetail> {
    let project = open(&state)?;
    let finding = project
        .findings()
        .get(id.parse().map_err(fail)?)
        .map_err(fail)?;

    Ok(FindingDetail {
        row: finding_row(&finding),
        description: finding.description.clone(),
        impact: finding.impact.clone(),
        remediation: finding.remediation.clone(),
        reproduction: finding.reproduction.clone(),
        location: finding
            .location
            .as_ref()
            .map(|l| format!("{:?} {}", l.part, l.name)),
        cwe: finding.cwe.clone(),
        owasp: finding.owasp.clone(),
        cvss: finding.cvss.clone(),
        created_at: finding.created_at.to_rfc3339(),
        evidence: finding.evidence.iter().map(evidence_view).collect(),
    })
}

/// Records a human judgement about a finding.
#[tauri::command]
pub fn findings_triage(
    state: State<'_, AppState>,
    id: String,
    status: String,
) -> CommandResult<FindingRow> {
    let project = open(&state)?;
    let store = project.findings();
    let finding_id = id.parse().map_err(fail)?;
    store
        .set_status(finding_id, parse_status(&status)?)
        .map_err(fail)?;
    Ok(finding_row(&store.get(finding_id).map_err(fail)?))
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// A rendered report, and what it concluded.
#[derive(Debug, Clone, Serialize)]
pub struct ReportView {
    pub format: String,
    pub headline: String,
    pub content: String,
    pub findings: usize,
    pub leads: usize,
    pub caveats: Vec<String>,
    /// Where it was written, when it was written anywhere.
    pub path: Option<String>,
    pub bytes: usize,
}

/// Renders the open project as a report, optionally writing it to disk.
///
/// A render sends no traffic and changes no triage state, which is why the window can
/// offer a live preview of it without asking first.
#[tauri::command]
pub fn report_render(
    state: State<'_, AppState>,
    format: String,
    title: Option<String>,
    severity: Option<String>,
    actionable: bool,
    show_secrets: bool,
    save_to: Option<String>,
) -> CommandResult<ReportView> {
    let project = open(&state)?;
    let requested = parse_format(&format)?;

    let report = Report::build(
        &project,
        &ReportOptions {
            title: title.filter(|t| !t.trim().is_empty()),
            min_severity: severity.as_deref().map(parse_severity).transpose()?,
            actionable_only: actionable,
            body_excerpt_bytes: 2048,
            redaction: if show_secrets {
                hexora_types::redact::RedactionPolicy::Disabled
            } else {
                hexora_types::redact::RedactionPolicy::SensitiveHeaders
            },
            generated_at: chrono::Utc::now(),
        },
    )
    .map_err(fail)?;

    let content = report.render(requested);
    let path = match save_to.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        None => None,
        Some(path) => {
            std::fs::write(path, &content).map_err(|e| format!("{path}: {e}"))?;
            Some(path.to_string())
        }
    };

    Ok(ReportView {
        format: format.to_ascii_lowercase(),
        headline: report.headline(),
        bytes: content.len(),
        findings: report.findings.len(),
        leads: report.leads.len(),
        caveats: report.caveats.clone(),
        content,
        path,
    })
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
        identity: item.identity,
        mode: item.mode.as_str().to_string(),
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

/// Opens the project the window is working in.
///
/// A fresh handle each time rather than one held open in [`AppState`]: SQLite
/// connections are pooled underneath, and a command that borrowed a long-lived
/// project would have to decide what happens when the tester opens another one.
fn open(state: &State<'_, AppState>) -> CommandResult<Project> {
    let path = state.project_path().map_err(fail)?;
    Project::open(&path).map_err(fail)
}

fn scope_view(scope: &Scope) -> ScopeView {
    ScopeView {
        included: scope.include.iter().map(rule_line).collect(),
        excluded: scope.exclude.iter().map(rule_line).collect(),
    }
}

/// One scope rule, as a line a tester can read back and recognise.
fn rule_line(rule: &ScopeRule) -> String {
    let scheme = match rule.scheme {
        SchemeMatch::Any => "",
        SchemeMatch::HttpOnly => "http://",
        SchemeMatch::HttpsOnly => "https://",
    };
    let path = match &rule.path {
        PathMatch::Any => String::new(),
        PathMatch::Prefix { value } => format!("{value}*"),
        PathMatch::Exact { value } => value.clone(),
    };
    format!("{scheme}{}{path}", rule.host)
}

fn identity_view(identity: &Identity) -> IdentityView {
    IdentityView {
        id: identity.id.to_string(),
        label: identity.label.clone(),
        privilege: privilege_name(identity.privilege).to_string(),
        credential: credential_kind(&identity.credential).to_string(),
        owns: identity.owned_object_ids.clone(),
    }
}

fn privilege_name(privilege: PrivilegeLevel) -> &'static str {
    match privilege {
        PrivilegeLevel::Anonymous => "anonymous",
        PrivilegeLevel::User => "user",
        PrivilegeLevel::Elevated => "elevated",
        PrivilegeLevel::Administrator => "administrator",
    }
}

/// The kind of credential, never its value.
fn credential_kind(credential: &Credential) -> &'static str {
    match credential {
        Credential::None => "none",
        Credential::Bearer { .. } => "bearer",
        Credential::Basic { .. } => "basic",
        Credential::Cookie { .. } => "cookie",
        Credential::Header { name, .. } => {
            // Named rather than described: an API key in `X-Api-Key` and one in
            // `Authorization` behave differently, and the list is read to check that
            // the identity was set up the way the application expects.
            let _ = name;
            "header"
        }
    }
}

fn parse_privilege(value: &str) -> CommandResult<PrivilegeLevel> {
    match value.to_ascii_lowercase().as_str() {
        "anonymous" | "anon" => Ok(PrivilegeLevel::Anonymous),
        "user" => Ok(PrivilegeLevel::User),
        "elevated" => Ok(PrivilegeLevel::Elevated),
        "administrator" | "admin" => Ok(PrivilegeLevel::Administrator),
        other => Err(format!(
            "{other:?} is not one of anonymous, user, elevated, administrator"
        )),
    }
}

/// Builds a credential from the kind the UI offered and the value it collected.
///
/// Anything not recognised is taken as a header name, which is how API keys arrive.
/// The name is used as typed: Hexora sends header names as written, and an
/// application that accepts only one casing is a finding rather than something to
/// paper over.
fn build_credential(kind: &str, value: String) -> CommandResult<Credential> {
    match kind.to_ascii_lowercase().as_str() {
        "bearer" => Ok(Credential::Bearer {
            token: Secret::new(value),
        }),
        "cookie" => Ok(Credential::Cookie {
            value: Secret::new(value),
        }),
        "basic" => {
            let (username, password) = value
                .split_once(':')
                .ok_or_else(|| "basic credentials are given as username:password".to_string())?;
            Ok(Credential::Basic {
                username: username.to_string(),
                password: Secret::new(password.to_string()),
            })
        }
        "none" => Ok(Credential::None),
        _ => Ok(Credential::Header {
            name: kind.to_string(),
            value: Secret::new(value),
        }),
    }
}

/// Finds an identity by id first, then by label.
///
/// Id first because it is unambiguous: a project with two identities labelled "Admin"
/// can still be driven precisely.
fn resolve_identity(store: &hexora_storage::IdentityStore, who: &str) -> CommandResult<Identity> {
    if let Ok(id) = who.parse() {
        if let Ok(identity) = store.get(id) {
            return Ok(identity);
        }
    }
    store.by_label(who).map_err(fail)
}

fn object_view(
    declaration: &ObjectDeclaration,
    identities: &hexora_storage::IdentityStore,
) -> ObjectView {
    ObjectView {
        id: declaration.id.to_string(),
        name: declaration.name.clone(),
        value: declaration.value.clone(),
        owner: identities
            .get(declaration.owner)
            .map(|i| i.label)
            .unwrap_or_else(|_| declaration.owner.to_string()),
        owner_id: declaration.owner.to_string(),
        location: declaration.location.describe(),
        source_request: declaration.source_request.map(|r| r.to_string()),
    }
}

/// Rebuilds a message model from a stored request, so a declared value can be looked
/// for in the target, the headers and the body.
fn rebuild(stored: &hexora_storage::StoredRequest) -> hexora_types::http::HttpRequest {
    let mut request = hexora_types::http::HttpRequest::get(stored.service.clone(), &stored.path);
    request.method = stored.method.clone();
    request.body = bytes::Bytes::from(stored.body.clone());
    for line in String::from_utf8_lossy(&stored.headers_raw)
        .split("\r\n")
        .flat_map(|l| l.split(LF))
    {
        if let Some((name, value)) = line.split_once(':') {
            request
                .headers
                .append(hexora_types::http::Header::new(name.trim(), value.trim()));
        }
    }
    request
}

/// Split on bare LF as well as CRLF: a stored block came off the wire, and the wire
/// is not always well behaved.
const LF: char = '\n';

fn attempt_view(attempt: &hexora_authz::construct::Attempt) -> AttemptView {
    AttemptView {
        sender: attempt.sender_label.clone(),
        object_name: attempt.object_name.clone(),
        object_value: attempt.object_value.clone(),
        owner: attempt.owner_label.clone(),
        substitution: attempt.describe_substitution(),
        location: attempt.location.describe(),
        original_value: attempt.original_value.clone(),
        request: attempt.request.map(|r| r.to_string()),
        control: attempt.control.map(|r| r.to_string()),
        status: attempt.status,
        similarity: attempt.similarity,
        outcome: attempt.outcome.as_str().to_string(),
        verdict: verdict_word(attempt.verdict).to_string(),
        violation: attempt.is_violation(),
        disclosed_object_ids: attempt.disclosed_object_ids.clone(),
        echoed: attempt.echoed,
        own_object_ids: attempt.own_object_ids.clone(),
        reproduced: attempt.reproduced,
        error: attempt.error.clone(),
        note: attempt.note.clone(),
    }
}

fn cell_view(cell: &Cell) -> CellView {
    CellView {
        identity: cell.identity.to_string(),
        label: cell.label.clone(),
        privilege: privilege_name(cell.privilege).to_string(),
        request: cell.request.map(|r| r.to_string()),
        status: cell.status,
        similarity: cell.similarity,
        outcome: cell.outcome.as_str().to_string(),
        verdict: verdict_word(cell.verdict).to_string(),
        violation: cell.verdict == Verdict::Violation,
        leaked_object_ids: cell.leaked_object_ids.clone(),
        own_object_ids: cell.own_object_ids.clone(),
        reproduced: cell.reproduced,
        error: cell.error.clone(),
        note: cell.note.clone(),
    }
}

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Expected => "expected",
        Verdict::Violation => "violation",
        Verdict::Inconclusive => "inconclusive",
    }
}

fn finding_row(finding: &hexora_types::finding::Finding) -> FindingRow {
    FindingRow {
        id: finding.id.to_string(),
        title: finding.title.clone(),
        severity: severity_word(finding.severity).to_string(),
        confidence: confidence_word(finding.confidence).to_string(),
        status: status_word(finding.status).to_string(),
        actionable: finding.confidence.is_actionable(),
        evidence_count: finding.evidence.len(),
        updated_at: finding.updated_at.to_rfc3339(),
    }
}

/// One piece of evidence as a sentence, plus the requests it rests on.
///
/// The ids travel separately from the prose so the window can offer them as links
/// into history. A claim whose evidence cannot be opened is a claim nobody can check.
fn evidence_view(evidence: &Evidence) -> EvidenceView {
    match evidence {
        Evidence::Exchange {
            request,
            response,
            note,
        } => EvidenceView {
            summary: match response {
                Some(response) => format!("{note} (response {response})"),
                None => note.clone(),
            },
            requests: vec![request.to_string()],
        },
        Evidence::Comparison {
            baseline,
            variant,
            difference,
        } => EvidenceView {
            summary: difference.clone(),
            requests: vec![baseline.to_string(), variant.to_string()],
        },
        Evidence::ResponseExcerpt {
            response,
            offset,
            excerpt,
        } => EvidenceView {
            summary: format!("from response {response} at byte {offset}: {excerpt}"),
            requests: Vec::new(),
        },
        Evidence::OutOfBand {
            request,
            interaction,
            protocol,
        } => EvidenceView {
            summary: format!("{protocol} interaction {interaction} attributed to this request"),
            requests: vec![request.to_string()],
        },
        Evidence::Timing {
            request,
            baseline_ms,
            variant_ms,
        } => EvidenceView {
            summary: format!("timing: baseline {baseline_ms:?} ms, variant {variant_ms:?} ms"),
            requests: vec![request.to_string()],
        },
    }
}

fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_word(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Reported => "reported",
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Confirmed => "confirmed",
    }
}

fn status_word(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::New => "new",
        FindingStatus::Triaged => "triaged",
        FindingStatus::Confirmed => "confirmed",
        FindingStatus::FalsePositive => "false-positive",
        FindingStatus::Duplicate => "duplicate",
        FindingStatus::Reported => "reported",
        FindingStatus::Fixed => "fixed",
        FindingStatus::Accepted => "accepted",
    }
}

fn parse_severity(value: &str) -> CommandResult<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        other => Err(format!(
            "{other:?} is not one of info, low, medium, high, critical"
        )),
    }
}

/// Accepts the hyphenated form the UI shows as well as the stored form.
fn parse_status(value: &str) -> CommandResult<FindingStatus> {
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "new" => Ok(FindingStatus::New),
        "triaged" => Ok(FindingStatus::Triaged),
        "confirmed" => Ok(FindingStatus::Confirmed),
        "false_positive" => Ok(FindingStatus::FalsePositive),
        "duplicate" => Ok(FindingStatus::Duplicate),
        "reported" => Ok(FindingStatus::Reported),
        "fixed" => Ok(FindingStatus::Fixed),
        "accepted" => Ok(FindingStatus::Accepted),
        other => Err(format!(
            "{other:?} is not one of new, triaged, confirmed, false-positive, \
             duplicate, reported, fixed, accepted"
        )),
    }
}

fn parse_format(value: &str) -> CommandResult<Format> {
    match value.to_ascii_lowercase().as_str() {
        "markdown" | "md" => Ok(Format::Markdown),
        "html" => Ok(Format::Html),
        "json" => Ok(Format::Json),
        other => Err(format!("{other:?} is not one of markdown, html, json")),
    }
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
            identity: Some("User B".into()),
            mode: hexora_types::raw::RequestMode::Structured,
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
    fn an_identity_view_never_carries_the_credential() {
        // This is the type that reaches the frontend. A credential here is a
        // credential in a devtools console and in every screenshot of the window.
        let identity = Identity::bearer("User B", "sk-live-not-a-real-token");
        let json = serde_json::to_string(&identity_view(&identity)).unwrap();

        assert!(!json.contains("sk-live-not-a-real-token"), "{json}");
        assert!(json.contains("\"credential\":\"bearer\""), "{json}");
        assert!(json.contains("User B"), "{json}");
    }

    #[test]
    fn an_attempt_view_says_what_was_substituted_and_carries_no_credential() {
        let attempt = hexora_authz::construct::Attempt {
            sender: hexora_types::ids::IdentityId::new(),
            sender_label: "User B".into(),
            declaration: hexora_types::ids::ObjectId::new(),
            object_name: "account".into(),
            object_value: "acct-1000".into(),
            owner: hexora_types::ids::IdentityId::new(),
            owner_label: "User A".into(),
            location: ObjectLocation::PathSegment { index: 1 },
            original_value: "acct-2000".into(),
            request: Some(RequestId::new()),
            control: Some(RequestId::new()),
            status: Some(200),
            similarity: 1.0,
            outcome: hexora_authz::Outcome::Allowed,
            verdict: Verdict::Violation,
            disclosed_object_ids: vec!["alice@example.com".into()],
            echoed: true,
            own_object_ids: Vec::new(),
            reproduced: true,
            error: None,
            note: None,
        };

        let view = attempt_view(&attempt);
        assert!(view.violation);
        assert_eq!(view.substitution, "acct-2000 → acct-1000 in path segment 1");

        // Whatever else changes, the shape that crosses the IPC boundary has no field
        // a credential could travel in.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("credential").is_none());
        assert!(json.get("token").is_none());
        for key in ["sender", "object_value", "owner", "substitution", "request"] {
            assert!(json.get(key).is_some(), "{key} missing from {json}");
        }
    }

    #[test]
    fn declaring_an_object_records_where_it_was_found_rather_than_guessing() {
        // The window offers a request to look in; the location comes from the value
        // actually being there, which is why a declaration that points nowhere is
        // refused rather than recorded.
        let mut request = hexora_types::http::HttpRequest::get(
            hexora_types::http::HttpService::new("api.example.com", 443, true),
            "/accounts/acct-1000",
        );
        request.headers.set("Authorization", "Bearer acct-1000");

        let found = hexora_authz::construct::locate(&request, "acct-1000");
        assert_eq!(found, vec![ObjectLocation::PathSegment { index: 1 }]);
        assert!(
            !found
                .iter()
                .any(|l| matches!(l, ObjectLocation::Header { .. })),
            "a credential header is never an object location"
        );
    }

    #[test]
    fn a_scope_rule_reads_back_as_the_line_a_tester_typed() {
        assert_eq!(
            rule_line(&ScopeRule::host("api.example.com")),
            "api.example.com"
        );
        assert_eq!(
            rule_line(&ScopeRule::host("api.example.com").with_prefix("/v1")),
            "api.example.com/v1*"
        );
    }

    #[test]
    fn adding_a_scope_rule_returns_the_whole_scope_not_an_acknowledgement() {
        // Widening scope is a decision a tester may have to justify later, so the
        // window is given what the scope now is rather than what was just added.
        let scope = Scope::new()
            .include(ScopeRule::host("api.example.com"))
            .exclude(ScopeRule::host("admin.example.com"));
        let view = scope_view(&scope);

        assert_eq!(view.included, vec!["api.example.com"]);
        assert_eq!(view.excluded, vec!["admin.example.com"]);
    }

    #[test]
    fn a_comparison_keeps_both_request_ids_so_the_window_can_open_them() {
        let baseline = RequestId::new();
        let variant = RequestId::new();
        let view = evidence_view(&Evidence::Comparison {
            baseline,
            variant,
            difference: "User B received acct-1000".into(),
        });

        assert_eq!(
            view.requests,
            vec![baseline.to_string(), variant.to_string()]
        );
        assert!(view.summary.contains("acct-1000"));
    }

    #[test]
    fn an_excerpt_cites_no_request_rather_than_a_made_up_one() {
        let view = evidence_view(&Evidence::ResponseExcerpt {
            response: hexora_types::ids::ResponseId::new(),
            offset: 412,
            excerpt: "acct-1000".into(),
        });
        assert!(view.requests.is_empty());
        assert!(view.summary.contains("412"), "{}", view.summary);
    }

    #[test]
    fn a_finding_row_says_whether_the_claim_may_be_reported() {
        let mut finding = a_finding();
        finding.confidence = Confidence::Tentative;
        assert!(
            !finding_row(&finding).actionable,
            "a similarity match is a lead, and the list has to say so"
        );

        finding.confidence = Confidence::Firm;
        assert!(finding_row(&finding).actionable);
    }

    #[test]
    fn triage_states_are_accepted_in_the_form_the_window_shows_them() {
        assert_eq!(
            parse_status("false-positive").unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(status_word(FindingStatus::FalsePositive), "false-positive");
        assert!(parse_status("wontfix")
            .unwrap_err()
            .contains("false-positive"));
    }

    #[test]
    fn an_unknown_report_format_lists_the_ones_that_exist() {
        assert_eq!(parse_format("MD").unwrap(), Format::Markdown);
        let error = parse_format("pdf").unwrap_err();
        assert!(error.contains("markdown"), "{error}");
    }

    #[test]
    fn a_matrix_cell_carries_the_request_id_a_finding_would_cite() {
        let request = RequestId::new();
        let cell = Cell {
            identity: hexora_types::ids::IdentityId::new(),
            label: "User B".into(),
            privilege: PrivilegeLevel::User,
            request: Some(request),
            status: Some(200),
            similarity: 1.0,
            outcome: hexora_authz::Outcome::Allowed,
            verdict: Verdict::Violation,
            leaked_object_ids: vec!["acct-1000".into()],
            own_object_ids: Vec::new(),
            reproduced: true,
            error: None,
            note: None,
        };

        let view = cell_view(&cell);
        assert_eq!(view.request.as_deref(), Some(request.to_string().as_str()));
        assert!(view.violation);
        assert_eq!(view.verdict, "violation");
        assert_eq!(view.leaked_object_ids, vec!["acct-1000"]);
    }

    #[test]
    fn an_anonymous_identity_may_be_added_with_no_credential_at_all() {
        // Every other privilege level needs one: an identity that was supposed to
        // carry a session and does not would score as "denied" everywhere and look
        // like an application doing its job.
        assert!(matches!(
            build_credential("none", String::new()).unwrap(),
            Credential::None
        ));
        assert!(build_credential("basic", "no-colon".into()).is_err());
    }

    /// A finding shaped like the ones the authorization subsystem produces.
    fn a_finding() -> hexora_types::finding::Finding {
        let now = chrono::Utc::now();
        hexora_types::finding::Finding {
            id: hexora_types::ids::FindingId::new(),
            target: hexora_types::ids::TargetId::new(),
            title: "Broken object-level authorization in GET /accounts/{id}".into(),
            severity: Severity::High,
            confidence: Confidence::Firm,
            location: None,
            description: String::new(),
            impact: String::new(),
            remediation: String::new(),
            reproduction: "Send it as somebody else.".into(),
            evidence: vec![Evidence::Comparison {
                baseline: RequestId::new(),
                variant: RequestId::new(),
                difference: "User B received acct-1000".into(),
            }],
            cwe: None,
            owasp: None,
            cvss: None,
            source: hexora_types::finding::FindingSource::AuthorizationTest,
            created_at: now,
            updated_at: now,
            status: FindingStatus::New,
        }
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
