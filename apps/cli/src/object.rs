//! `hexora object` — the identifiers a tester says belong to somebody.
//!
//! Declaring an object is data entry and nothing else. It sends no traffic, and it is
//! not evidence of ownership: it is the tester's assertion, which every finding built
//! on it says out loud. Running the test is a separate, explicit act
//! (`hexora authz --construct`).
//!
//! The location is discovered rather than typed. A tester who has just found
//! `invoice-1001` in a captured request should not also have to count path segments,
//! so `--in-request` looks for the value and records where it actually was. Declaring
//! it in a place it is not found is refused, because a declaration that points
//! nowhere produces attempts that go nowhere.

use std::path::Path;

use hexora_authz::construct::locate;
use hexora_types::object::{ObjectDeclaration, ObjectLocation};
use hexora_types::{HexoraError, Result};

/// Options for `hexora object add`.
pub struct AddArgs<'a> {
    pub project: &'a Path,
    /// The identifier itself, exactly as it appears in a request.
    pub value: &'a str,
    /// The identity that owns it, by label or id.
    pub owner: &'a str,
    /// What kind of object it is, e.g. `invoice`.
    pub name: &'a str,
    /// A captured request the value appears in.
    pub in_request: Option<&'a str>,
    pub json: bool,
}

/// Declares an object identifier and who owns it.
pub fn add(args: AddArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let identities = project.identities();
    let owner = crate::identity::resolve(&identities, args.owner)?;
    let store = project.objects();

    let declarations = match args.in_request {
        Some(id) => from_request(&project, id, args.value, args.name, &owner)?,
        None => vec![ObjectDeclaration::new(
            args.name,
            args.value,
            owner.id,
            // Without a request to look in there is nowhere to discover, and saying
            // "byte 0 of the body" would be a lie a later run would act on. The run
            // substitutes it wherever the sender's own object sits instead.
            ObjectLocation::Anywhere,
        )?],
    };

    for declaration in &declarations {
        store.put(declaration)?;
    }

    if args.json {
        let rows: Vec<_> = declarations
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id.to_string(),
                    "name": d.name,
                    "value": d.value,
                    "owner": owner.label,
                    "location": d.location.describe(),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "declared": rows }));
        return Ok(());
    }

    for declaration in &declarations {
        println!(
            "Declared {} {} as {}'s, at {}.",
            declaration.name,
            declaration.value,
            owner.label,
            declaration.location.describe()
        );
    }
    println!();
    println!("Nothing has been sent. Construct cross-identity attempts with:");
    println!(
        "  hexora authz {} <request-id> --as-identity <who> --construct",
        args.project.display()
    );
    Ok(())
}

/// Finds a declared value in a captured request, and records where it was.
fn from_request(
    project: &hexora_storage::Project,
    id: &str,
    value: &str,
    name: &str,
    owner: &hexora_types::identity::Identity,
) -> Result<Vec<ObjectDeclaration>> {
    let request_id: hexora_types::ids::RequestId = id.parse()?;
    let stored = project.traffic().request(request_id)?;

    // Rebuilt rather than re-parsed: `locate` needs a message model, and the fields
    // the store keeps are enough to look in the target, the headers and the body.
    let mut request = hexora_types::http::HttpRequest::get(stored.service.clone(), &stored.path);
    request.method = stored.method.clone();
    request.body = bytes::Bytes::from(stored.body.clone());
    for line in String::from_utf8_lossy(&stored.headers_raw)
        .split("\r\n")
        .flat_map(|l| l.split('\n'))
    {
        if let Some((header, header_value)) = line.split_once(':') {
            request.headers.append(hexora_types::http::Header::new(
                header.trim(),
                header_value.trim(),
            ));
        }
    }

    let locations = locate(&request, value);
    if locations.is_empty() {
        return Err(HexoraError::invalid_input(
            "--in-request",
            format!(
                "{value:?} does not appear in {id} — not in the path, the query, a \
                 header or the body. A declaration that points nowhere would construct \
                 attempts that go nowhere. (Credential headers are never searched: an \
                 Authorization value is a session, not an object.)"
            ),
        ));
    }

    locations
        .into_iter()
        .map(|location| {
            Ok(ObjectDeclaration::new(name, value, owner.id, location)?.found_in(request_id))
        })
        .collect()
}

/// Prints every declaration in a project.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let project_handle = crate::open_project(project)?;
    let identities = project_handle.identities();
    let declarations = project_handle.objects().list()?;

    let label_of = |id: hexora_types::ids::IdentityId| {
        identities
            .get(id)
            .map(|i| i.label)
            .unwrap_or_else(|_| id.to_string())
    };

    if json {
        let rows: Vec<_> = declarations
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id.to_string(),
                    "name": d.name,
                    "value": d.value,
                    "owner": label_of(d.owner),
                    "location": d.location.describe(),
                    "source_request": d.source_request.map(|r| r.to_string()),
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "objects": rows }));
        return Ok(());
    }

    if declarations.is_empty() {
        println!("No objects declared in {}.", project.display());
        println!();
        println!("An authorization matrix replays a request as written. Declaring who");
        println!("owns an identifier is what lets Hexora build the request nobody sent:");
        println!(
            "  hexora object add {} <value> --owner <who> --in-request <request-id>",
            project.display()
        );
        return Ok(());
    }

    println!(
        "{:<38} {:<14} {:<24} {:<22} WHERE",
        "ID", "NAME", "VALUE", "OWNER"
    );
    for declaration in &declarations {
        println!(
            "{:<38} {:<14} {:<24} {:<22} {}",
            declaration.id.to_string(),
            truncate(&declaration.name, 14),
            truncate(&declaration.value, 24),
            truncate(&label_of(declaration.owner), 22),
            declaration.location.describe(),
        );
    }
    Ok(())
}

/// Removes a declaration by id.
pub fn remove(project: &Path, id: &str, json: bool) -> Result<()> {
    let store = crate::open_project(project)?.objects();
    let object_id = id.parse()?;
    if !store.delete(object_id)? {
        return Err(HexoraError::not_found("object declaration", id.to_string()));
    }

    if json {
        println!("{}", serde_json::json!({ "removed": id }));
    } else {
        println!("Removed {id}.");
        println!("Requests already constructed from it are kept, and still name the");
        println!("substitution they made.");
    }
    Ok(())
}

/// A short label for a table, cut at a width.
fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut out: String = value.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_value_is_cut_rather_than_wrapping_the_table() {
        assert_eq!(truncate("acct-1000", 24), "acct-1000");
        assert_eq!(truncate("aaaaaaaaaa", 5), "aaaa…");
    }

    #[test]
    fn declaring_against_a_missing_project_says_so() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), "unrelated").unwrap();
        let error = list(dir.path(), true).unwrap_err();
        assert_eq!(error.code(), "invalid_input");
    }

    #[test]
    fn listing_an_empty_project_explains_what_a_declaration_is_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        crate::project::init(&path, Some("Acme"), true).unwrap();
        list(&path, true).unwrap();
    }
}
