//! Project-level settings: the scope, the headers every request must carry, and the
//! terms the engagement is conducted under.
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

use hexora_types::http::Header;
use hexora_types::programme::Programme;
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

    /// Headers to put on every request Hexora sends.
    ///
    /// A bug bounty programme routinely requires researchers to identify their traffic
    /// — `X-HackerOne-Research: <username>` is the common shape, and Wolt's programme
    /// says testing without it "can result in the forfeiture of the eligible bounty".
    ///
    /// An identity's `extra_headers` cannot express that: it covers authenticated
    /// replays and nothing else, while the requirement covers the scanner's probes, the
    /// intruder's payloads and every anonymous control too. So it lives on the project,
    /// where every send can see it.
    ///
    /// Empty for a project that has no `project` row, which is the correct reading of
    /// "nobody has asked for any".
    pub fn attached_headers(&self) -> Result<Vec<Header>> {
        let conn = self.db.connection()?;
        let json: Option<String> = conn
            .query_row(
                "SELECT attached_headers_json FROM project LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        match json {
            None => Ok(Vec::new()),
            Some(json) => serde_json::from_str(&json).map_err(|e| StorageError::Decode {
                entity: "attached headers",
                reason: e.to_string(),
            }),
        }
    }

    /// Replaces the headers put on every request.
    ///
    /// Consequential in the opposite direction from scope: a *missing* header here does
    /// not make traffic unsafe, it makes it unattributable, and a programme that cannot
    /// tell a researcher's requests from an attacker's is entitled to treat them the
    /// same way. Callers show the user what changed.
    pub fn set_attached_headers(&self, headers: &[Header]) -> Result<()> {
        let json = serde_json::to_string(headers).map_err(|e| StorageError::Decode {
            entity: "attached headers",
            reason: e.to_string(),
        })?;
        let conn = self.db.connection()?;
        let updated = conn.execute(
            "UPDATE project SET attached_headers_json = ?1",
            params![json],
        )?;
        // A project database with no project row silently matched nothing, and the
        // caller went on to print "Attached". A tool that reports a programme header as
        // set when it is not is the exact failure that forfeits a report, so this says
        // so instead.
        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "project row",
                id: PROJECT_ID.to_string(),
            });
        }
        Ok(())
    }

    /// The terms this engagement is conducted under.
    ///
    /// Scope says which systems may be touched; this says which kinds of finding the
    /// programme will accept. A bug bounty programme routinely puts most of what a
    /// passive scanner produces out of scope as a *class* — missing headers, cookie
    /// flags, CORS without proven impact — and a run that files forty of those is a run
    /// whose output gets skipped.
    ///
    /// Empty for a project that has none, which excludes nothing: the correct reading
    /// of "nobody has said otherwise" is that everything found is worth reporting.
    pub fn programme(&self) -> Result<Programme> {
        let conn = self.db.connection()?;
        let json: Option<String> = conn
            .query_row("SELECT programme_json FROM project LIMIT 1", [], |row| {
                row.get(0)
            })
            .ok();

        match json {
            None => Ok(Programme::none()),
            Some(json) => serde_json::from_str(&json).map_err(|e| StorageError::Decode {
                entity: "programme",
                reason: e.to_string(),
            }),
        }
    }

    /// Replaces the engagement's terms.
    ///
    /// Unlike scope, this is not a safety control: an exclusion can only ever reduce
    /// what is reported or sent, so a wrong one cannot make Hexora touch something it
    /// otherwise would not. It is still printed back to the user, because a silence
    /// nobody remembers asking for is worse than a noisy report.
    pub fn set_programme(&self, programme: &Programme) -> Result<()> {
        let json = serde_json::to_string(programme).map_err(|e| StorageError::Decode {
            entity: "programme",
            reason: e.to_string(),
        })?;
        let conn = self.db.connection()?;
        let updated = conn.execute("UPDATE project SET programme_json = ?1", params![json])?;
        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "project row",
                id: PROJECT_ID.to_string(),
            });
        }
        Ok(())
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
    fn attached_headers_survive_a_round_trip() {
        let settings = project();
        assert!(settings.attached_headers().unwrap().is_empty());

        let headers = vec![
            Header::new("X-HackerOne-Research", "wahid_ratul"),
            Header::new("X-Trace", "a:b"),
        ];
        settings.set_attached_headers(&headers).unwrap();

        let back = settings.attached_headers().unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "X-HackerOne-Research");
        assert_eq!(back[0].value_lossy(), "wahid_ratul");
        assert_eq!(back[1].value_lossy(), "a:b");
    }

    #[test]
    fn a_project_without_attached_headers_reads_as_none_rather_than_failing() {
        // "Nobody has asked for any" is the correct reading, and it must not be an
        // error: every send path asks this question, and a failure here would stop a
        // test run that had nothing wrong with it.
        let settings = Settings::new(MetadataDb::in_memory().unwrap());
        assert!(settings.attached_headers().unwrap().is_empty());
    }

    #[test]
    fn a_programme_survives_a_round_trip() {
        let settings = project();
        assert!(settings.programme().unwrap().is_empty());

        let mut programme = Programme {
            name: Some("Wolt".into()),
            policy_url: Some("https://hackerone.com/wolt".into()),
            exclusions: Vec::new(),
        };
        programme.exclude(hexora_types::programme::Exclusion::new(
            "headers.security",
            "out of scope: missing security headers",
        ));
        settings.set_programme(&programme).unwrap();

        assert_eq!(settings.programme().unwrap(), programme);
    }

    #[test]
    fn a_project_without_a_programme_excludes_nothing_rather_than_failing() {
        // Every scan asks this question. A failure here would stop a run that had
        // nothing wrong with it, and an error that read as "excluded" would silently
        // suppress findings.
        let settings = Settings::new(MetadataDb::in_memory().unwrap());
        let programme = settings.programme().unwrap();
        assert!(programme.is_empty());
        assert!(programme.excluded("headers.security").is_none());
    }

    #[test]
    fn setting_them_on_a_project_that_does_not_exist_is_an_error() {
        // It used to succeed and store nothing, and `hexora header add` printed
        // "Attached" over the top of it. A header a programme requires, reported as set
        // and never sent, is how a report gets rejected.
        let settings = Settings::new(MetadataDb::in_memory().unwrap());

        let error = settings
            .set_attached_headers(&[Header::new("X-HackerOne-Research", "r")])
            .unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");

        let error = settings.set_programme(&Programme::none()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");
    }

    #[test]
    fn setting_a_scope_on_a_project_that_does_not_exist_is_an_error() {
        let settings = Settings::new(MetadataDb::in_memory().unwrap());
        let error = settings.set_scope(&Scope::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error}");
    }
}
