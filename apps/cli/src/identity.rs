//! `nullhawk identity` — the principals a project can test as.
//!
//! Credentials are taken from the environment or a file, never from a command-line
//! argument. On a shared machine `ps` shows every running process's arguments, and a
//! shell writes them to history; a session token pasted into `--token` is a token
//! leaked to anybody with an account on the box. The failure is silent, which is
//! exactly why the option does not exist.

use std::path::Path;
use std::sync::Arc;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_repeater::{Repeater, SendAs};
use nullhawk_storage::IdentityStore;
use nullhawk_types::http::Headers;
use nullhawk_types::identity::{Credential, Identity, PrivilegeLevel};
use nullhawk_types::ids::RequestId;
use nullhawk_types::redact::Secret;
use nullhawk_types::{Header, NullhawkError, Result};

/// Options for `nullhawk identity add`.
pub struct AddArgs<'a> {
    pub project: &'a Path,
    pub label: &'a str,
    pub privilege: &'a str,
    /// Environment variable holding the credential value.
    pub from_env: Option<&'a str>,
    /// File holding the credential value.
    pub from_file: Option<&'a Path>,
    /// `bearer`, `cookie`, `basic` or a header name.
    pub kind: &'a str,
    /// Cookie names that identify the caller, for a cookie credential.
    ///
    /// Without these a cookie jar is compared whole, and a real one holds a dozen
    /// values of which three change between requests — so nothing ever matches.
    pub session_cookies: &'a [String],
    /// Object identifiers known to belong to this identity.
    pub owns: &'a [String],
    /// Extra headers, in `Name: Value` form.
    pub headers: &'a [String],
    pub json: bool,
}

/// Adds an identity to a project.
pub fn add(args: AddArgs<'_>) -> Result<()> {
    let store = crate::open_project(args.project)?.identities();
    let privilege = parse_privilege(args.privilege)?;

    let credential = if privilege == PrivilegeLevel::Anonymous
        && args.from_env.is_none()
        && args.from_file.is_none()
    {
        Credential::None
    } else {
        build_credential(args.kind, read_secret(&args)?)?
    };

    let identity = Identity {
        id: nullhawk_types::ids::IdentityId::new(),
        label: args.label.to_string(),
        privilege,
        credential,
        extra_headers: parse_headers(args.headers)?,
        owned_object_ids: args.owns.to_vec(),
        session_cookies: args.session_cookies.to_vec(),
        // A hand-added identity has no recorded login to replay; `browse --record-login` sets it.
        login_request: None,
    };
    store.put(&identity)?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "id": identity.id.to_string(),
                "label": identity.label,
                "privilege": args.privilege,
            })
        );
    } else {
        println!(
            "Added {} ({}) as {}",
            identity.label, args.privilege, identity.id
        );
        if identity.owned_object_ids.is_empty() {
            println!();
            println!("No owned object identifiers were declared. Authorization results for");
            println!("this identity will rest on response similarity alone, which is weaker");
            println!("evidence — see `nullhawk identity add --owns`.");
        }
    }
    Ok(())
}

/// Prints every identity in a project.
///
/// Never prints credential material, in any output mode. An identity list is
/// something a tester pastes into a ticket or a screenshot without thinking about it.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let opened = crate::open_project(project)?;
    let identities = opened.identities().list()?;

    // How much of the captured traffic these identities actually account for.
    //
    // Asked here because this is where somebody looks to see whether their engagement
    // is set up, and because not asking it cost an evening: a whole run against a real
    // target, an identity declared and a session adopted, and not one captured request
    // carried a credential. Every check said so in its own words, one endpoint at a
    // time, and none of them said the thing that mattered.
    let coverage =
        nullhawk_authz::session::coverage(&opened.traffic(), &identities, COVERAGE_SAMPLE)
            .unwrap_or_default();

    if json {
        let rows: Vec<_> = identities
            .iter()
            .map(|identity| {
                serde_json::json!({
                    "id": identity.id.to_string(),
                    "label": identity.label,
                    "privilege": privilege_name(identity.privilege),
                    "credential": credential_kind(&identity.credential),
                    "owns": identity.owned_object_ids,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "identities": rows,
                "coverage": {
                    "examined": coverage.examined,
                    "with_authorization": coverage.with_authorization,
                    "with_cookies": coverage.with_cookies,
                    "attributable": coverage.attributable,
                },
            })
        );
        return Ok(());
    }

    if identities.is_empty() {
        println!("No identities. Add one with `nullhawk identity add`.");
        println!();
        println!("{}", coverage.describe());
        return Ok(());
    }

    println!(
        "{:<24} {:<14} {:<10} OWNS",
        "LABEL", "PRIVILEGE", "CREDENTIAL"
    );
    for identity in &identities {
        println!(
            "{:<24} {:<14} {:<10} {}",
            truncate(&identity.label, 24),
            privilege_name(identity.privilege),
            credential_kind(&identity.credential),
            if identity.owned_object_ids.is_empty() {
                "—".to_string()
            } else {
                identity.owned_object_ids.join(", ")
            }
        );
    }

    // What a credential says about its own lifetime, before somebody spends a run
    // finding out. A token that expired an hour ago will answer 401 to everything, and
    // a run that sends twenty requests to learn that charges the target for it.
    let now = chrono::Utc::now().timestamp();
    let expired: Vec<&str> = identities
        .iter()
        .filter(|identity| identity.credential_expired(now))
        .map(|identity| identity.label.as_str())
        .collect();

    for identity in &identities {
        if let Some(lifetime) = identity.lifetime() {
            println!();
            println!("{}: {}", identity.label, lifetime.describe(now));
        }
    }

    if !expired.is_empty() {
        println!();
        println!("Refresh before running anything: nullhawk identity refresh <project> <who>");
        println!("(log in through the proxy first — an expired token cannot renew itself)");
    }

    println!();
    println!("{}", coverage.describe());
    Ok(())
}

/// How many recent exchanges the coverage line reads.
///
/// A ceiling rather than a target: the answer to "does this project hold authenticated
/// traffic" does not need every row, and `identity list` should not take a second.
const COVERAGE_SAMPLE: usize = 300;

/// Removes an identity by label or id.
pub fn remove(project: &Path, who: &str, json: bool) -> Result<()> {
    let store = crate::open_project(project)?.identities();
    let identity = resolve(&store, who)?;
    store.delete(identity.id)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "removed": identity.id.to_string() })
        );
    } else {
        println!("Removed {}.", identity.label);
        println!("Traffic already sent as it is kept, and still names it.");
    }
    Ok(())
}

/// Finds an identity by id first, then by label.
///
/// Id first because it is unambiguous: a project with two identities labelled "Admin"
/// can still be driven precisely.
pub fn resolve(store: &IdentityStore, who: &str) -> Result<Identity> {
    if let Ok(id) = who.parse() {
        if let Ok(identity) = store.get(id) {
            return Ok(identity);
        }
    }
    Ok(store.by_label(who)?)
}

/// Reads the credential value from wherever the tester put it.
fn read_secret(args: &AddArgs<'_>) -> Result<String> {
    match (args.from_env, args.from_file) {
        (Some(name), None) => std::env::var(name).map_err(|_| {
            NullhawkError::invalid_input(
                "--from-env",
                format!("environment variable {name} is not set"),
            )
        }),
        (None, Some(path)) => Ok(std::fs::read_to_string(path)
            .map_err(|e| {
                NullhawkError::invalid_input("--from-file", format!("{}: {e}", path.display()))
            })?
            // A file written by `echo` ends in a newline, and a newline inside an
            // Authorization header value is a request-splitting bug waiting to happen.
            .trim()
            .to_string()),
        (None, None) => Err(NullhawkError::invalid_input(
            "credential",
            "give the credential with --from-env or --from-file (never on the command \
             line, where `ps` and shell history can read it)",
        )),
        (Some(_), Some(_)) => Err(NullhawkError::invalid_input(
            "credential",
            "--from-env and --from-file are mutually exclusive",
        )),
    }
}

/// Drops a leading auth scheme, so a pasted header value works as a token.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> &'a str {
    let trimmed = value.trim();
    match trimmed.len() > scheme.len()
        && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme)
        && trimmed.as_bytes()[scheme.len()] == b' '
    {
        true => trimmed[scheme.len() + 1..].trim_start(),
        false => trimmed,
    }
}

fn build_credential(kind: &str, value: String) -> Result<Credential> {
    match kind.to_ascii_lowercase().as_str() {
        // Stored without the scheme, because `Credential::apply` writes `Bearer ` back
        // on. Copying a whole `Authorization:` value out of a captured request is the
        // obvious way to get a token, and keeping the prefix here sends
        // `Authorization: Bearer Bearer eyJ...` — which the application rejects, while
        // every attribution silently fails to match and cross-identity testing reports
        // that nobody owns the traffic. Both failures look like something else.
        "bearer" => Ok(Credential::Bearer {
            token: Secret::new(strip_scheme(&value, "bearer").to_string()),
        }),
        "cookie" => Ok(Credential::Cookie {
            value: Secret::new(value),
        }),
        "basic" => {
            let (username, password) = value.split_once(':').ok_or_else(|| {
                NullhawkError::invalid_input(
                    "credential",
                    "basic credentials must be given as username:password",
                )
            })?;
            Ok(Credential::Basic {
                username: username.to_string(),
                password: Secret::new(password.to_string()),
            })
        }
        "none" => Ok(Credential::None),
        // Anything else is taken as a header name, which is how API keys arrive:
        // `--kind X-API-Key`. The name is taken from what the tester typed rather than
        // from the lowercased copy used for matching — Nullhawk sends header names as
        // written, and an application that only accepts one casing is a finding, not
        // something to paper over.
        _ => Ok(Credential::Header {
            name: kind.to_string(),
            value: Secret::new(value),
        }),
    }
}

fn parse_headers(headers: &[String]) -> Result<Vec<Header>> {
    headers
        .iter()
        .map(|raw| {
            let (name, value) = raw.split_once(':').ok_or_else(|| {
                NullhawkError::invalid_input("--header", format!("{raw:?} is not 'Name: Value'"))
            })?;
            Ok(Header::new(name.trim(), value.trim()))
        })
        .collect()
}

fn parse_privilege(value: &str) -> Result<PrivilegeLevel> {
    match value.to_ascii_lowercase().as_str() {
        "anonymous" | "anon" => Ok(PrivilegeLevel::Anonymous),
        "user" => Ok(PrivilegeLevel::User),
        "elevated" => Ok(PrivilegeLevel::Elevated),
        "administrator" | "admin" => Ok(PrivilegeLevel::Administrator),
        other => Err(NullhawkError::invalid_input(
            "--privilege",
            format!("{other:?} is not one of anonymous, user, elevated, administrator"),
        )),
    }
}

pub fn privilege_name(privilege: PrivilegeLevel) -> &'static str {
    match privilege {
        PrivilegeLevel::Anonymous => "anonymous",
        PrivilegeLevel::User => "user",
        PrivilegeLevel::Elevated => "elevated",
        PrivilegeLevel::Administrator => "administrator",
    }
}

fn credential_kind(credential: &Credential) -> &'static str {
    match credential {
        Credential::None => "none",
        Credential::Bearer { .. } => "bearer",
        Credential::Basic { .. } => "basic",
        Credential::Cookie { .. } => "cookie",
        Credential::Header { .. } => "header",
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_string()
    } else {
        let kept: String = value.chars().take(width.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Options for `nullhawk identity refresh`.
pub struct RefreshArgs<'a> {
    pub project: &'a Path,
    /// Which identity, by label or id.
    pub who: &'a str,
    /// Show what would be adopted without storing it.
    pub dry_run: bool,
    /// How many recent exchanges to look through.
    pub limit: usize,
    /// Only adopt a session seen on this host.
    pub host: Option<&'a str>,
    pub json: bool,
}

/// Adopts a newer session for an identity, from traffic a person generated.
///
/// A captured credential decays, and a stale one turns every authorization result into
/// "could not be established". The fix is not to record the login and replay it — that
/// means storing a password, and it fails against captcha, MFA and SSO, which is most
/// real targets. It is to let the person log in the way they already do, through the
/// proxy, and notice.
pub fn refresh(args: RefreshArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let identities = project.identities();
    let identity = resolve(&identities, args.who)?;

    let traffic = project.traffic();
    let scope = project.settings().scope()?;
    let found =
        nullhawk_authz::session::find_renewal(&traffic, &scope, &identity, args.limit, args.host)?;

    let Some(renewal) = found else {
        if args.json {
            println!("{}", serde_json::json!({ "renewed": false }));
            return Ok(());
        }
        println!(
            "No newer session for {} in the last {} exchange(s).",
            identity.label, args.limit
        );
        println!();
        println!("Log in through the proxy and run this again. Only proxy traffic counts:");
        println!("a credential Nullhawk sent itself is one it may have broken on purpose.");
        return Ok(());
    };

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "renewed": !args.dry_run,
                "identity": identity.label,
                "source": renewal.source.to_string(),
                "host": renewal.host,
                "sent_at": renewal.sent_at,
                "slot": renewal.slot,
                "bytes": renewal.length,
            })
        );
        if args.dry_run {
            return Ok(());
        }
        let mut updated = identity.clone();
        updated.credential = renewal.credential(&identity.credential);
        identities.put(&updated)?;
        return Ok(());
    }

    // The value is never printed. A host, a time and a size are enough to decide
    // whether this is the session you just created, and nothing like enough to use.
    println!("Found a newer {} for {}:", renewal.slot, identity.label);
    println!("  from {} at {}", renewal.host, renewal.sent_at);
    println!(
        "  {} bytes, captured by the proxy as {}",
        renewal.length, renewal.source
    );

    if args.dry_run {
        println!();
        println!("Not stored (--dry-run).");
        return Ok(());
    }

    let mut updated = identity.clone();
    updated.credential = renewal.credential(&identity.credential);
    identities.put(&updated)?;

    println!();
    println!("{} now authenticates with it.", identity.label);
    println!("Re-run `nullhawk scan active` — the results that said the credential may no");
    println!("longer be valid can be established now.");
    Ok(())
}

/// Options for `nullhawk identity renew`.
pub struct RenewArgs<'a> {
    pub project: &'a Path,
    /// The identity to update.
    pub who: &'a str,
    /// The captured login/refresh request to replay. Defaults to the identity's recorded login.
    pub from: Option<&'a str>,
    /// Read the new session from this cookie in the response's `Set-Cookie`.
    pub cookie: Option<&'a str>,
    /// Or from this response header's value.
    pub header: Option<&'a str>,
    /// Or from this dot-path in the response's JSON body (e.g. `data.accessToken`).
    pub json_field: Option<&'a str>,
    /// Work out what would happen and send nothing.
    pub dry_run: bool,
    pub insecure: bool,
    pub json: bool,
}

/// Renews an identity's session by replaying a recorded login and reading the new token out
/// of *its response*.
///
/// This is the complement to `refresh`: `refresh` adopts a credential a browser already sent
/// through the proxy, and refuses anything Nullhawk sent itself; `renew` deliberately re-runs a
/// login or token-refresh request and takes the fresh token from the response. It is for API
/// token and refresh-endpoint flows — not password logins behind captcha, MFA or SSO, which
/// this cannot and should not automate. The tester names the request, so the replay is their
/// decision, and the token is never printed.
pub fn renew(args: RenewArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let identities = project.identities();
    let identity = resolve(&identities, args.who)?;
    let kind = credential_kind_key(&identity.credential)?;

    // The request to replay: the one named, or the login `browse --record-login` recorded.
    let request_id: RequestId = match args.from {
        Some(raw) => raw.parse().map_err(|e| {
            NullhawkError::invalid_input("--from", format!("{raw} is not a request id: {e}"))
        })?,
        None => identity.login_request.ok_or_else(|| {
            NullhawkError::invalid_input(
                "--from",
                "this identity has no recorded login to replay. Record one with `nullhawk \
                 browse <project> --record-login`, or name a captured login request with --from",
            )
        })?,
    };

    // Where the new token is: as named, or — when nothing was said and the identity has a
    // recorded session cookie — that cookie.
    let named = [args.cookie, args.header, args.json_field]
        .iter()
        .filter(|s| s.is_some())
        .count();
    if named > 1 {
        return Err(NullhawkError::invalid_input(
            "source",
            "name only one of --cookie, --header or --json-field",
        ));
    }
    let cookie: Option<String> = if named == 0 {
        identity.session_cookies.first().cloned()
    } else {
        args.cookie.map(str::to_string)
    };
    if cookie.is_none() && args.header.is_none() && args.json_field.is_none() {
        return Err(NullhawkError::invalid_input(
            "source",
            "say where the new token is in the login response: --cookie <name>, --header <name>, \
             or --json-field <path>. A login recorded with --record-login defaults to its \
             session cookie",
        ));
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let scope = Arc::new(project.settings().scope()?);
    let store = Arc::new(project.traffic());
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store)
        .attaching(project.settings().attached_headers()?);
    let draft = repeater.draft_from(request_id)?;

    if args.dry_run {
        println!(
            "Would replay {} {} and read the new session from {}.",
            draft.request.method,
            draft.request.url(),
            describe_source(cookie.as_deref(), args.header, args.json_field)
        );
        println!("Nothing was sent.");
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;
    let sent = runtime.block_on(repeater.send_as(&draft, SendAs::repeater()))?;
    let response = &sent.exchange.response;

    let new_value = if let Some(name) = cookie.as_deref() {
        let value = cookie_value(&response.headers, name).ok_or_else(|| {
            NullhawkError::invalid_input(
                "--cookie",
                format!(
                    "the login response set no `{name}` cookie (status {})",
                    response.status
                ),
            )
        })?;
        // A Cookie credential is the whole `Cookie:` header; store the pair so it is sent back
        // as `name=value`. Other credential kinds take the bare value.
        match kind.as_str() {
            "cookie" => format!("{name}={value}"),
            _ => value,
        }
    } else if let Some(name) = args.header {
        response
            .headers
            .get(name)
            .map(|h| h.value_lossy().trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                NullhawkError::invalid_input(
                    "--header",
                    format!(
                        "the login response had no `{name}` header (status {})",
                        response.status
                    ),
                )
            })?
    } else {
        let path = args.json_field.unwrap();
        json_field(response.body.as_ref(), path).ok_or_else(|| {
            NullhawkError::invalid_input(
                "--json-field",
                format!(
                    "the login response body has no string at `{path}` (status {})",
                    response.status
                ),
            )
        })?
    };

    let credential = build_credential(&kind, new_value)?;
    let mut updated = identity.clone();
    updated.credential = credential;
    identities.put(&updated)?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "renewed": true,
                "identity": identity.label,
                "source": sent.id.to_string(),
                "status": response.status,
            })
        );
    } else {
        println!(
            "Renewed the session for `{}` from {} (status {}).",
            identity.label,
            describe_source(cookie.as_deref(), args.header, args.json_field),
            response.status
        );
        println!("The new credential is stored; the token itself is not printed.");
    }
    Ok(())
}

/// The credential kind key for `build_credential`, or an error when there is no session to renew.
fn credential_kind_key(credential: &Credential) -> Result<String> {
    match credential {
        Credential::None => Err(NullhawkError::invalid_input(
            "identity",
            "this identity is anonymous — there is no session to renew",
        )),
        Credential::Bearer { .. } => Ok("bearer".to_string()),
        Credential::Cookie { .. } => Ok("cookie".to_string()),
        Credential::Basic { .. } => Err(NullhawkError::invalid_input(
            "identity",
            "a basic-auth password is not a session; `renew` does not apply to it",
        )),
        Credential::Header { name, .. } => Ok(name.clone()),
    }
}

/// A named cookie's value from the response's `Set-Cookie` headers.
fn cookie_value(headers: &Headers, name: &str) -> Option<String> {
    for header in headers.get_all("set-cookie") {
        let value = header.value_lossy();
        let pair = value.split(';').next().unwrap_or("");
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// A string (or number) at a dot-path in a JSON body, e.g. `data.accessToken`.
fn json_field(body: &[u8], path: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut current = &root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// How the new token is being read, for messages.
fn describe_source(cookie: Option<&str>, header: Option<&str>, json_field: Option<&str>) -> String {
    if let Some(name) = cookie {
        format!("the `{name}` cookie in the response")
    } else if let Some(name) = header {
        format!("the `{name}` response header")
    } else if let Some(path) = json_field {
        format!("`{path}` in the response body")
    } else {
        "the response".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TOKEN: &str = "TEST_TOKEN_NOT_A_SECRET";

    #[test]
    fn a_bearer_credential_is_built_from_the_value_alone() {
        match build_credential("bearer", TEST_TOKEN.into()).unwrap() {
            Credential::Bearer { token } => assert_eq!(token.expose(), TEST_TOKEN),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_named_cookie_is_read_out_of_set_cookie() {
        let mut headers = Headers::new();
        headers.append(Header::new("Set-Cookie", "other=1; Path=/"));
        headers.append(Header::new(
            "Set-Cookie",
            "session=abc123; Path=/; HttpOnly",
        ));
        assert_eq!(
            cookie_value(&headers, "session"),
            Some("abc123".to_string())
        );
        assert_eq!(cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn a_json_field_is_read_by_dot_path() {
        let body = br#"{"data":{"accessToken":"tok-9"},"n":42}"#;
        assert_eq!(
            json_field(body, "data.accessToken"),
            Some("tok-9".to_string())
        );
        assert_eq!(json_field(body, "n"), Some("42".to_string()));
        assert_eq!(json_field(body, "data.missing"), None);
        assert_eq!(json_field(b"not json", "x"), None);
    }

    #[test]
    fn renew_refuses_an_anonymous_or_basic_identity() {
        assert!(credential_kind_key(&Credential::None).is_err());
        assert!(credential_kind_key(&Credential::Basic {
            username: "u".into(),
            password: "p".to_string().into(),
        })
        .is_err());
        assert_eq!(
            credential_kind_key(&Credential::Cookie {
                value: "x".to_string().into()
            })
            .unwrap(),
            "cookie"
        );
    }

    #[test]
    fn an_unknown_kind_is_taken_as_a_header_name() {
        match build_credential("X-API-Key", TEST_TOKEN.into()).unwrap() {
            Credential::Header { name, .. } => assert_eq!(name, "X-API-Key"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn basic_credentials_must_carry_a_colon() {
        assert!(build_credential("basic", "no-colon-here".into()).is_err());
    }

    #[test]
    fn a_credential_given_nowhere_is_refused_with_the_reason_why() {
        let args = AddArgs {
            project: Path::new("."),
            label: "User A",
            privilege: "user",
            from_env: None,
            from_file: None,
            kind: "bearer",
            owns: &[],
            session_cookies: &[],
            headers: &[],
            json: false,
        };
        let error = read_secret(&args).unwrap_err().to_string();
        assert!(error.contains("--from-env"), "{error}");
        assert!(
            error.contains("shell history"),
            "the message has to say why, or people will look for the flag that does \
             not exist: {error}"
        );
    }

    #[test]
    fn a_credential_read_from_a_file_loses_its_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, format!("{TEST_TOKEN}\n")).unwrap();

        let args = AddArgs {
            project: Path::new("."),
            label: "User A",
            privilege: "user",
            from_env: None,
            from_file: Some(&path),
            kind: "bearer",
            owns: &[],
            session_cookies: &[],
            headers: &[],
            json: false,
        };
        assert_eq!(read_secret(&args).unwrap(), TEST_TOKEN);
    }

    #[test]
    fn privilege_names_are_accepted_in_the_forms_people_type() {
        assert_eq!(
            parse_privilege("admin").unwrap(),
            PrivilegeLevel::Administrator
        );
        assert_eq!(parse_privilege("ANON").unwrap(), PrivilegeLevel::Anonymous);
        assert!(parse_privilege("root").is_err());
    }

    #[test]
    fn extra_headers_are_parsed_as_name_and_value() {
        let headers = parse_headers(&["X-Tenant: acme".to_string()]).unwrap();
        assert_eq!(headers[0].name, "X-Tenant");
        assert_eq!(headers[0].value_lossy(), "acme");
        assert!(parse_headers(&["not a header".to_string()]).is_err());
    }
}
