//! `hexora project` subcommands.

use std::path::Path;

use hexora_storage::{migrations, rusqlite};
use hexora_types::{HexoraError, Result};

/// Creates a new project directory.
pub fn init(path: &Path, name: Option<&str>, json: bool) -> Result<()> {
    if path.join("project.db").exists() {
        return Err(HexoraError::invalid_input(
            "path",
            format!("{} is already a Hexora project", path.display()),
        ));
    }

    let name = name
        .map(str::to_owned)
        .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "Untitled engagement".to_string());

    let project = crate::open_project(path)?;
    let now = now_rfc3339();
    project
        .metadata()
        .connection()
        .map_err(HexoraError::from)?
        .execute(
            "INSERT INTO project (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
            rusqlite_params(&name, &now),
        )
        .map_err(|e| HexoraError::Storage(e.to_string()))?;

    if json {
        let payload = serde_json::json!({
            "created": path.display().to_string(),
            "name": name,
            "schema_version": migrations::target_version(),
        });
        println!("{payload}");
    } else {
        println!("Created project {name:?} at {}", path.display());
        println!();
        println!("The project scope is empty, which means no automated component will");
        println!("send any traffic. Add authorized hosts before scanning.");
    }
    Ok(())
}

/// Prints information about an existing project.
pub fn info(path: &Path, json: bool) -> Result<()> {
    if !path.join("project.db").exists() {
        return Err(HexoraError::not_found("project", path.display().to_string()));
    }
    let project = crate::open_project(path)?;
    let conn = project.metadata().connection().map_err(HexoraError::from)?;

    let (name, created_at): (String, String) = conn
        .query_row("SELECT name, created_at FROM project LIMIT 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|e| HexoraError::Storage(e.to_string()))?;

    let targets = count(&conn, "targets")?;
    let requests = count(&conn, "requests")?;
    let findings = count(&conn, "findings")?;
    let schema = project.metadata().schema_version().map_err(HexoraError::from)?;

    if json {
        let payload = serde_json::json!({
            "name": name,
            "created_at": created_at,
            "schema_version": schema,
            "targets": targets,
            "requests": requests,
            "findings": findings,
        });
        println!("{payload}");
    } else {
        println!("{name}");
        println!("  path:            {}", path.display());
        println!("  created:         {created_at}");
        println!("  schema revision: {schema}");
        println!("  targets:         {targets}");
        println!("  requests:        {requests}");
        println!("  findings:        {findings}");
    }
    Ok(())
}

fn count(conn: &rusqlite::Connection, table: &str) -> Result<i64> {
    // `table` is never user input: every call site passes a literal.
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
        .map_err(|e| HexoraError::Storage(e.to_string()))
}

fn rusqlite_params<'a>(name: &'a str, now: &'a str) -> [&'a dyn rusqlite::ToSql; 3] {
    // A fixed project id: a project file holds exactly one project row.
    [&"prj_default" as &dyn rusqlite::ToSql, &name, &now]
}

fn now_rfc3339() -> String {
    // Kept dependency-free at M0; the engine uses `chrono` where formatting matters.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("@{now}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_a_project_that_info_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        init(&path, Some("Acme"), true).unwrap();
        assert!(path.join("project.db").exists());
        info(&path, true).unwrap();
    }

    #[test]
    fn init_refuses_to_overwrite_an_existing_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engagement");
        init(&path, Some("Acme"), true).unwrap();
        let err = init(&path, Some("Acme"), true).unwrap_err();
        assert_eq!(err.code(), "invalid_input", "an engagement's evidence is never overwritten");
    }

    #[test]
    fn init_defaults_the_name_to_the_directory_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme-q1");
        init(&path, None, true).unwrap();

        let project = crate::open_project(&path).unwrap();
        let name: String = project
            .metadata()
            .connection()
            .unwrap()
            .query_row("SELECT name FROM project", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "acme-q1");
    }

    #[test]
    fn info_on_a_missing_project_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let err = info(&dir.path().join("nope"), true).unwrap_err();
        assert_eq!(err.code(), "not_found");
    }
}
