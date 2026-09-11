//! Recording that a check ran.
//!
//! The store that exists to make silence mean something. A check that finds nothing
//! writes nothing, so "the check ran and the application was clean" and "the check
//! never ran" look identical in a findings list — and a retest that cannot tell them
//! apart will read the second as the first, which is the most expensive mistake this
//! tool could make.
//!
//! A run therefore records what executed, at which version, over how much traffic,
//! and what each detector produced — including, and especially, zero.
//!
//! This is not a scheduler. A passive run is one pass over stored traffic with a
//! start and an end. Queues, concurrency and retries belong to the active scheduler,
//! where the requirements will be real.

use hexora_types::ids::ScanRunId;
use hexora_types::verify::DetectorMode;
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StorageError};
use crate::MetadataDb;

/// What one detector did during one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorRun {
    /// Which check.
    pub detector: String,
    /// Which version of it.
    pub version: String,
    /// Whether it sends.
    pub mode: DetectorMode,
    /// Facts it stated.
    pub observations: u32,
    /// Suspicions it raised, which stop here until something verifies them.
    pub hypotheses: u32,
    /// Of the observations, how many were worth reporting.
    pub reportable: u32,
    /// Why this programme does not accept what it found, if it does not.
    ///
    /// The detector still ran, and its observations are still listed. What it did not
    /// do is produce a finding. A run record that omitted this would leave a reader
    /// unable to tell "nobody looked" from "it was looked at and this programme does
    /// not take them" — see `hexora_types::programme`.
    pub excluded: Option<String>,
}

/// One pass of the scanner over a project's traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRun {
    /// Stable identifier.
    pub id: ScanRunId,
    /// What the operator asked to be looked at.
    pub selection: String,
    /// When it started.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// When it finished, or `None` if it did not.
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// How it ended.
    pub status: RunStatus,
    /// Exchanges examined.
    pub exchanges_read: u64,
    /// Exchanges deliberately not examined — out of scope, or past the limit.
    pub exchanges_skipped: u64,
    /// How many requests the run put on somebody's system.
    ///
    /// Zero for a passive pass, and a real number for an active one: it is the
    /// question a client asks afterwards, and an engagement report should not have to
    /// guess at it.
    pub requests_sent: u64,
    /// Why the run ended before working through its queue, if it did.
    ///
    /// `None` means it finished. Anything else means the run is *unfinished*, and a
    /// reader must not take its silence for a clean result.
    pub stopped_because: Option<String>,
    /// The Hexora build that ran it.
    pub tool_version: String,
    /// What each detector did.
    pub detectors: Vec<DetectorRun>,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    /// Still going, or stopped without finishing.
    Running,
    /// Read everything it set out to.
    Completed,
    /// Stopped on an error. Its counts are what it had managed.
    Failed,
}

impl RunStatus {
    /// The word stored in the database.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parses the stored form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Reads and writes a project's scan runs.
#[derive(Debug, Clone)]
pub struct ScanStore {
    db: MetadataDb,
}

impl ScanStore {
    /// Opens the store over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// Writes a completed run and what each detector did.
    ///
    /// Written at the end rather than opened at the start and updated: a passive run
    /// is fast and local, and a half-written row that says a detector ran when it did
    /// not is worse than no row at all.
    pub fn record(&self, run: &ScanRun) -> Result<()> {
        let mut conn = self.db.connection()?;
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO scan_runs (
                 id, selection, started_at, completed_at, status,
                 exchanges_read, exchanges_skipped, tool_version,
                 requests_sent, stopped_because)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run.id.to_string(),
                run.selection,
                run.started_at.to_rfc3339(),
                run.completed_at.map(|at| at.to_rfc3339()),
                run.status.as_str(),
                run.exchanges_read as i64,
                run.exchanges_skipped as i64,
                run.tool_version,
                run.requests_sent as i64,
                run.stopped_because,
            ],
        )?;

        for detector in &run.detectors {
            tx.execute(
                "INSERT INTO scan_run_detectors (
                     run_id, detector_id, detector_version, mode,
                     observations, hypotheses, reportable, excluded_reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    run.id.to_string(),
                    detector.detector,
                    detector.version,
                    detector.mode.as_str(),
                    detector.observations as i64,
                    detector.hypotheses as i64,
                    detector.reportable as i64,
                    detector.excluded,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Every run, newest first.
    ///
    /// Not paginated: a run is a deliberate act, a handful per engagement.
    pub fn list(&self) -> Result<Vec<ScanRun>> {
        // One connection for the whole read, and the detector rows are fetched
        // through it. Asking the pool for a second while holding the first
        // deadlocks an in-memory project, whose pool is capped at one connection so
        // that every caller sees the same database.
        let conn = self.db.connection()?;
        let decoded: Vec<Result<ScanRun>> = {
            let mut statement = conn.prepare(
                "SELECT id, selection, started_at, completed_at, status,
                        exchanges_read, exchanges_skipped, tool_version,
                        requests_sent, stopped_because
                 FROM scan_runs ORDER BY started_at DESC, id DESC",
            )?;
            let rows = statement.query_map([], decode_run)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut runs = decoded.into_iter().collect::<Result<Vec<ScanRun>>>()?;

        for run in &mut runs {
            run.detectors = detectors_on(&conn, run.id)?;
        }
        Ok(runs)
    }

    /// The most recent run, if any.
    pub fn latest(&self) -> Result<Option<ScanRun>> {
        Ok(self.list()?.into_iter().next())
    }

    /// One run.
    pub fn get(&self, id: ScanRunId) -> Result<ScanRun> {
        let conn = self.db.connection()?;
        let row = conn
            .query_row(
                "SELECT id, selection, started_at, completed_at, status,
                        exchanges_read, exchanges_skipped, tool_version,
                        requests_sent, stopped_because
                 FROM scan_runs WHERE id = ?1",
                params![id.to_string()],
                decode_run,
            )
            .optional()?;

        let mut run = row.ok_or_else(|| StorageError::NotFound {
            entity: "scan run",
            id: id.to_string(),
        })??;
        run.detectors = detectors_on(&conn, id)?;
        Ok(run)
    }

    /// Whether a detector has ever run against this project, and at which versions.
    ///
    /// The question a retest asks: was this check even pointed at the application?
    pub fn versions_of(&self, detector: &str) -> Result<Vec<String>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT DISTINCT detector_version FROM scan_run_detectors
             WHERE detector_id = ?1 ORDER BY detector_version",
        )?;
        let rows = statement.query_map(params![detector], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// How many runs the project holds.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 = conn.query_row("SELECT count(*) FROM scan_runs", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// What each detector did in a run.
    pub fn detectors_of(&self, run: ScanRunId) -> Result<Vec<DetectorRun>> {
        let conn = self.db.connection()?;
        detectors_on(&conn, run)
    }
}

/// Reads the detector rows on a connection the caller already holds.
fn detectors_on(conn: &rusqlite::Connection, run: ScanRunId) -> Result<Vec<DetectorRun>> {
    {
        let mut statement = conn.prepare(
            "SELECT detector_id, detector_version, mode, observations, hypotheses,
                    reportable, excluded_reason
             FROM scan_run_detectors WHERE run_id = ?1 ORDER BY detector_id",
        )?;
        let rows = statement.query_map(params![run.to_string()], |row| {
            let mode: String = row.get(2)?;
            Ok(DetectorRun {
                detector: row.get(0)?,
                version: row.get(1)?,
                mode: if mode == "active" {
                    DetectorMode::Active
                } else {
                    DetectorMode::Passive
                },
                observations: row.get::<_, i64>(3)? as u32,
                hypotheses: row.get::<_, i64>(4)? as u32,
                reportable: row.get::<_, i64>(5)? as u32,
                excluded: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn decode_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ScanRun>> {
    let id: String = row.get(0)?;
    let selection: String = row.get(1)?;
    let started_at: String = row.get(2)?;
    let completed_at: Option<String> = row.get(3)?;
    let status: String = row.get(4)?;
    let read: i64 = row.get(5)?;
    let skipped: i64 = row.get(6)?;
    let tool_version: String = row.get(7)?;
    let requests_sent: i64 = row.get(8)?;
    let stopped_because: Option<String> = row.get(9)?;

    Ok((|| {
        Ok(ScanRun {
            id: id.parse().map_err(|e| StorageError::Decode {
                entity: "ScanRunId",
                reason: format!("{e}"),
            })?,
            selection,
            started_at: parse_time(&started_at)?,
            completed_at: completed_at.as_deref().map(parse_time).transpose()?,
            status: RunStatus::parse(&status).ok_or_else(|| StorageError::Decode {
                entity: "ScanRun.status",
                reason: format!("{status:?}"),
            })?,
            exchanges_read: read as u64,
            exchanges_skipped: skipped as u64,
            requests_sent: requests_sent as u64,
            stopped_because,
            tool_version,
            detectors: Vec::new(),
        })
    })())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|at| at.with_timezone(&chrono::Utc))
        .map_err(|e| StorageError::Decode {
            entity: "ScanRun timestamp",
            reason: format!("{e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Project;

    fn run(selection: &str, detectors: Vec<DetectorRun>) -> ScanRun {
        let now = chrono::Utc::now();
        ScanRun {
            id: ScanRunId::new(),
            selection: selection.into(),
            started_at: now,
            completed_at: Some(now),
            status: RunStatus::Completed,
            exchanges_read: 184,
            exchanges_skipped: 3,
            requests_sent: 0,
            stopped_because: None,
            tool_version: "0.1.0".into(),
            detectors,
        }
    }

    fn detector(id: &str, observations: u32, hypotheses: u32) -> DetectorRun {
        DetectorRun {
            detector: id.into(),
            version: "1.0.0".into(),
            mode: DetectorMode::Passive,
            observations,
            hypotheses,
            reportable: observations,
            excluded: None,
        }
    }

    #[test]
    fn a_detector_that_found_nothing_is_recorded_as_having_run() {
        // The row this whole table exists for. Without it, "clean" and "never
        // pointed at the application" are the same picture.
        let project = Project::in_memory().unwrap();
        let store = project.scans();
        let recorded = run("all hosts", vec![detector("headers.security", 0, 0)]);
        store.record(&recorded).unwrap();

        let read = store.get(recorded.id).unwrap();
        assert_eq!(read.detectors.len(), 1);
        assert_eq!(read.detectors[0].detector, "headers.security");
        assert_eq!(read.detectors[0].observations, 0);
        assert_eq!(read.status, RunStatus::Completed);
        assert_eq!(read.exchanges_read, 184);
    }

    #[test]
    fn runs_list_newest_first_with_their_detectors() {
        let project = Project::in_memory().unwrap();
        let store = project.scans();

        let first = run("all", vec![detector("headers.security", 2, 0)]);
        store.record(&first).unwrap();
        let mut second = run(
            "host=api.example.com",
            vec![detector("cors.configuration", 0, 1)],
        );
        second.started_at = first.started_at + chrono::Duration::seconds(10);
        store.record(&second).unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, second.id);
        assert_eq!(listed[0].selection, "host=api.example.com");
        assert_eq!(listed[0].detectors[0].hypotheses, 1);
        assert_eq!(store.latest().unwrap().unwrap().id, second.id);
    }

    #[test]
    fn the_versions_a_check_has_run_at_are_readable() {
        let project = Project::in_memory().unwrap();
        let store = project.scans();

        store
            .record(&run("a", vec![detector("headers.security", 1, 0)]))
            .unwrap();
        let mut newer = detector("headers.security", 1, 0);
        newer.version = "2.0.0".into();
        store.record(&run("b", vec![newer])).unwrap();

        assert_eq!(
            store.versions_of("headers.security").unwrap(),
            vec!["1.0.0".to_string(), "2.0.0".to_string()]
        );
        assert!(store.versions_of("nothing.here").unwrap().is_empty());
    }

    #[test]
    fn a_run_that_never_finished_does_not_read_as_one_that_did() {
        let project = Project::in_memory().unwrap();
        let store = project.scans();
        let mut stopped = run("all", vec![detector("headers.security", 0, 0)]);
        stopped.completed_at = None;
        stopped.status = RunStatus::Running;
        store.record(&stopped).unwrap();

        let read = store.get(stopped.id).unwrap();
        assert_eq!(read.status, RunStatus::Running);
        assert!(read.completed_at.is_none());
    }

    #[test]
    fn asking_for_a_run_that_is_not_there_says_so() {
        let project = Project::in_memory().unwrap();
        let error = project.scans().get(ScanRunId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error:?}");
    }
}
