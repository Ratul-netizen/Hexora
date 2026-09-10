//! Project-level settings: for now, the scope.
//!
//! Scope is the control that decides whether an automated subsystem may send anything
//! at all (`core/engine/src/guard.rs`), so it has to outlive the command that set it.
//! Up to M12 it was accepted at the API boundary and never written down, which meant
//! every CLI invocation started from an empty scope and no automated component could
//! run twice in a row without being told again what it was allowed to touch.
//!
//! The scope lives in the single `project` row as JSON. It is small, it is read once
//! per command, and keeping it in one column means a project file remains a complete,
//! portable record of an engagement: the traffic, the identities, the findings, and
//! the authorization it was all collected under.

use hexora_types::scope::Scope;
use rusqlite::params;

use crate::error::{Result, StorageError};
use crate::MetadataDb;

/// The fixed id of the single project row.
///
/// A project database holds exactly one project, as `hexora project init` writes it.
const PROJECT_ID: &str = "prj_default";

/// Reads and writes the project's settings.
#[derive(Debug, Clone)]
pub struct Settings {
    db: MetadataDb,
}

impl Settings {
    /// Opens the settings over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// The project's scope.
    ///
    /// An empty scope for a project that has no `project` row at all — an in-memory
    /// database, or one a test built directly — rather than an error: "nothing is in
    /// scope" is the correct and safe reading of "nobody has said anything is".
    pub fn scope(&self) -> Result<Scope> {
        let conn = self.db.connection()?;
        let json: Option<String> = conn
            .query_row("SELECT scope_json FROM project LIMIT 1", [], |row| {
                row.get(0)
            })
            .ok();

        match json {
            None => Ok(Scope::new()),
            Some(json) => serde_json::from_str(&json).map_err(|e| StorageError::Decode {
                entity: "Scope",
                reason: e.to_string(),
            }),
        }
    }

    /// Replaces the project's scope.
    ///
    /// Widening scope is the most consequential setting in a project — it is the
    /// difference between a tool that refuses to touch a host and one that will — so
    /// callers are expected to show the user what changed. Nothing here does it for
    /// them.
    pub fn set_scope(&self, scope: &Scope) -> Result<()> {
        let json = serde_json::to_string(scope).map_err(|e| StorageError::Decode {
            entity: "Scope",
            reason: e.to_string(),
        })?;

        let conn = self.db.connection()?;
        let updated = conn.execute(
            "UPDATE project SET scope_json = ?1, updated_at = ?2",
            params![json, crate::traffic::now()],
        )?;

        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "project row",
                id: PROJECT_ID.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hexora_types::scope::{PathMatch, ScopeRule};

    use super::*;

    fn project() -> Settings {
        let db = MetadataDb::in_memory().unwrap();
        db.connection()
            .unwrap()
            .execute(
                "INSERT INTO project (id, name, created_at, updated_at)
                 VALUES (?1, 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                params![PROJECT_ID],
            )
            .unwrap();
        Settings::new(db)
    }

    #[test]
    fn a_new_project_is_in_scope_for_nothing() {
        assert_eq!(project().scope().unwrap(), Scope::new());
    }

    #[test]
    fn a_database_with_no_project_row_reports_an_empty_scope() {
        let settings = Settings::new(MetadataDb::in_memory().unwrap());
        assert_eq!(settings.scope().unwrap(), Scope::new());
    }

    #[test]
    fn a_scope_survives_a_round_trip_with_its_rules_intact() {
        let settings = project();
        let scope = Scope::new()
            .include(ScopeRule {
                host: "*.example.com".into(),
                ports: vec![443],
                scheme: Default::default(),
                path: PathMatch::Prefix {
                    value: "/api".into(),
                },
            })
            .exclude(ScopeRule::host("admin.example.com"));

        settings.set_scope(&scope).unwrap();
        assert_eq!(settings.scope().unwrap(), scope);
    }

    #[test]
    fn a_stored_scope_still_decides_the_same_way_after_reloading() {
        let settings = project();
        settings
            .set_scope(&Scope::new().include(ScopeRule::host("example.com")))
            .unwrap();

        let scope = settings.scope().unwrap();
        let service = hexora_types::http::HttpService::new("example.com", 443, true);
        let other = hexora_types::http::HttpService::new("elsewhere.com", 443, true);
        assert!(scope.contains(&service, "/anything"));
        assert!(!scope.contains(&other, "/anything"));
    }

    #[test]
    fn setting_a_scope_on_a_project_that_does_not_exist_is_an_error() {
        let settings = Settings::new(MetadataDb::in_memory().unwrap());
        let error = settings.set_scope(&Scope::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");
    }
}
