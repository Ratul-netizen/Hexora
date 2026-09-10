//! `hexora identity` — the principals a project can test as.
//!
//! Credentials are taken from the environment or a file, never from a command-line
//! argument. On a shared machine `ps` shows every running process's arguments, and a
//! shell writes them to history; a session token pasted into `--token` is a token
//! leaked to anybody with an account on the box. The failure is silent, which is
//! exactly why the option does not exist.

use std::path::Path;

use hexora_storage::IdentityStore;
use hexora_types::identity::{Credential, Identity, PrivilegeLevel};
use hexora_types::redact::Secret;
use hexora_types::{Header, HexoraError, Result};

/// Options for `hexora identity add`.
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
        id: hexora_types::ids::IdentityId::new(),
        label: args.label.to_string(),
        privilege,
        credential,
        extra_headers: parse_headers(args.headers)?,
        owned_object_ids: args.owns.to_vec(),
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
            println!("evidence — see `hexora identity add --owns`.");
        }
    }
    Ok(())
}

/// Prints every identity in a project.
///
/// Never prints credential material, in any output mode. An identity list is
/// something a tester pastes into a ticket or a screenshot without thinking about it.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let identities = crate::open_project(project)?.identities().list()?;

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
        println!("{}", serde_json::json!({ "identities": rows }));
        return Ok(());
    }

    if identities.is_empty() {
        println!("No identities. Add one with `hexora identity add`.");
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
    Ok(())
}

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
            HexoraError::invalid_input(
                "--from-env",
                format!("environment variable {name} is not set"),
            )
        }),
        (None, Some(path)) => Ok(std::fs::read_to_string(path)
            .map_err(|e| {
                HexoraError::invalid_input("--from-file", format!("{}: {e}", path.display()))
            })?
            // A file written by `echo` ends in a newline, and a newline inside an
            // Authorization header value is a request-splitting bug waiting to happen.
            .trim()
            .to_string()),
        (None, None) => Err(HexoraError::invalid_input(
            "credential",
            "give the credential with --from-env or --from-file (never on the command \
             line, where `ps` and shell history can read it)",
        )),
        (Some(_), Some(_)) => Err(HexoraError::invalid_input(
            "credential",
            "--from-env and --from-file are mutually exclusive",
        )),
    }
}

fn build_credential(kind: &str, value: String) -> Result<Credential> {
    match kind.to_ascii_lowercase().as_str() {
        "bearer" => Ok(Credential::Bearer {
            token: Secret::new(value),
        }),
        "cookie" => Ok(Credential::Cookie {
            value: Secret::new(value),
        }),
        "basic" => {
            let (username, password) = value.split_once(':').ok_or_else(|| {
                HexoraError::invalid_input(
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
        // from the lowercased copy used for matching — Hexora sends header names as
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
                HexoraError::invalid_input("--header", format!("{raw:?} is not 'Name: Value'"))
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
        other => Err(HexoraError::invalid_input(
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
