//! Persisting identifier suggestions.
//!
//! A suggestion is not a finding and not a declaration; it is a queue item. What that
//! implies for storage is the whole of this module:
//!
//! * **It survives the session.** Traffic is captured on Monday and reviewed on
//!   Tuesday. Recomputing suggestions from current traffic each time would renumber
//!   them, change their scores and make ones somebody had already looked at vanish.
//! * **A review is never overwritten by analysis.** Re-running over a project
//!   refreshes the signals on suggestions nobody has looked at, and leaves accepted
//!   and rejected ones exactly as the human left them — the same rule the findings
//!   store follows, for the same reason.
//! * **There is no owner column.** Ownership lives in `object_declarations`. Two
//!   tables rather than one nullable column, so a heuristic cannot become an ownership
//!   assertion by way of a schema shortcut.

use hexora_types::candidate::{CandidateStatus, IdentifierCandidate, Signal};
use hexora_types::ids::{CandidateId, RequestId};
use rusqlite::{params, OptionalExtension};

use crate::error::{Result, StorageError};
use crate::MetadataDb;

/// What [`CandidateStore::record`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suggested {
    /// A value nobody had been offered before.
    Created(CandidateId),
    /// A suggestion that already existed; its signals were refreshed.
    Refreshed(CandidateId),
    /// A suggestion a human has already reviewed. Left exactly as they left it.
    Reviewed(CandidateId),
}

impl Suggested {
    /// The candidate's id, however it got there.
    pub fn id(&self) -> CandidateId {
        match self {
            Self::Created(id) | Self::Refreshed(id) | Self::Reviewed(id) => *id,
        }
    }

    /// Whether this run produced a suggestion the project had not seen.
    pub fn is_new(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Which suggestions to return.
#[derive(Debug, Clone, Default)]
pub struct CandidateFilter {
    /// Only suggestions in this state.
    pub status: Option<CandidateStatus>,
    /// Only suggestions scoring at least this much.
    pub min_score: Option<i32>,
}

/// Reads and writes identifier suggestions.
#[derive(Debug, Clone)]
pub struct CandidateStore {
    db: MetadataDb,
}

impl CandidateStore {
    /// Opens the store over a project's metadata database.
    pub fn new(db: MetadataDb) -> Self {
        Self { db }
    }

    /// Writes a suggestion, or refreshes the one already offering the same value in
    /// the same place.
    ///
    /// A suggestion a human has accepted or rejected is returned untouched. Analysis
    /// runs whenever a tester asks; their decisions do not.
    pub fn record(
        &self,
        candidate: &IdentifierCandidate,
        seen_in: &[RequestId],
    ) -> Result<Suggested> {
        let existing = self.find_matching(candidate)?;
        if let Some((id, status)) = existing {
            if status.is_reviewed() {
                // Still record where it was seen: the decision stands, but the
                // evidence behind it can keep growing.
                self.record_observations(id, seen_in)?;
                return Ok(Suggested::Reviewed(id));
            }
            self.write(candidate, id)?;
            self.record_observations(id, seen_in)?;
            return Ok(Suggested::Refreshed(id));
        }

        self.write(candidate, candidate.id)?;
        self.record_observations(candidate.id, seen_in)?;
        Ok(Suggested::Created(candidate.id))
    }

    fn write(&self, candidate: &IdentifierCandidate, id: CandidateId) -> Result<()> {
        let signals =
            serde_json::to_string(&candidate.signals).map_err(|e| StorageError::Decode {
                entity: "candidate signals",
                reason: e.to_string(),
            })?;
        let location =
            serde_json::to_string(&candidate.location).map_err(|e| StorageError::Decode {
                entity: "object location",
                reason: e.to_string(),
            })?;

        let conn = self.db.connection()?;
        conn.execute(
            "INSERT INTO identifier_candidates
                 (id, value, location_json, location_key, descriptor, source_request_id,
                  occurrences, signals_json, score, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT (value, location_key) DO UPDATE SET
                 descriptor = excluded.descriptor,
                 source_request_id = COALESCE(excluded.source_request_id, source_request_id),
                 occurrences = excluded.occurrences,
                 signals_json = excluded.signals_json,
                 score = excluded.score,
                 updated_at = excluded.updated_at",
            params![
                id.to_string(),
                candidate.value,
                location,
                candidate.location.key(),
                candidate.descriptor,
                candidate.source_request.map(|r| r.to_string()),
                candidate.occurrences,
                signals,
                candidate.score,
                candidate.status.as_str(),
                candidate.created_at.to_rfc3339(),
                candidate.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    fn find_matching(
        &self,
        candidate: &IdentifierCandidate,
    ) -> Result<Option<(CandidateId, CandidateStatus)>> {
        let conn = self.db.connection()?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT id, status FROM identifier_candidates
                 WHERE value = ?1 AND location_key = ?2",
                params![candidate.value, candidate.location.key()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match row {
            None => Ok(None),
            Some((id, status)) => Ok(Some((
                id.parse()?,
                CandidateStatus::parse(&status).unwrap_or_default(),
            ))),
        }
    }

    fn record_observations(&self, id: CandidateId, seen_in: &[RequestId]) -> Result<()> {
        if seen_in.is_empty() {
            return Ok(());
        }
        let mut conn = self.db.connection()?;
        let tx = conn.transaction()?;
        for request in seen_in {
            tx.execute(
                "INSERT OR IGNORE INTO identifier_candidate_observations
                     (candidate_id, request_id) VALUES (?1, ?2)",
                params![id.to_string(), request.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Suggestions, strongest first.
    ///
    /// Score order rather than time order: a review queue is worked from the top, and
    /// the top is what analysis had most reason to offer.
    pub fn list(&self, filter: &CandidateFilter) -> Result<Vec<IdentifierCandidate>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT c.id, c.value, c.location_json, c.descriptor, c.source_request_id,
                    c.occurrences, c.signals_json, c.score, c.status, c.created_at,
                    c.updated_at,
                    (SELECT count(*) FROM identifier_candidate_observations o
                      WHERE o.candidate_id = c.id) AS live
             FROM identifier_candidates c
             WHERE (?1 IS NULL OR c.status = ?1)
               AND (?2 IS NULL OR c.score >= ?2)
             ORDER BY c.score DESC, c.id ASC",
        )?;

        let rows = statement.query_map(
            params![filter.status.map(|s| s.as_str()), filter.min_score,],
            decode,
        )?;
        let mut candidates = Vec::new();
        for row in rows {
            candidates.push(row??);
        }
        Ok(candidates)
    }

    /// One suggestion by id.
    pub fn get(&self, id: CandidateId) -> Result<IdentifierCandidate> {
        let conn = self.db.connection()?;
        let row = conn
            .query_row(
                "SELECT c.id, c.value, c.location_json, c.descriptor, c.source_request_id,
                        c.occurrences, c.signals_json, c.score, c.status, c.created_at,
                        c.updated_at,
                        (SELECT count(*) FROM identifier_candidate_observations o
                          WHERE o.candidate_id = c.id) AS live
                 FROM identifier_candidates c WHERE c.id = ?1",
                params![id.to_string()],
                decode,
            )
            .optional()?;

        row.ok_or_else(|| StorageError::NotFound {
            entity: "identifier candidate",
            id: id.to_string(),
        })?
    }

    /// The exchanges a suggestion was drawn from and that the project still holds.
    pub fn observations(&self, id: CandidateId) -> Result<Vec<RequestId>> {
        let conn = self.db.connection()?;
        let mut statement = conn.prepare(
            "SELECT request_id FROM identifier_candidate_observations
             WHERE candidate_id = ?1 ORDER BY request_id ASC",
        )?;
        let rows = statement.query_map(params![id.to_string()], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?.parse()?);
        }
        Ok(ids)
    }

    /// Records a human's decision about a suggestion.
    pub fn set_status(&self, id: CandidateId, status: CandidateStatus) -> Result<()> {
        let conn = self.db.connection()?;
        let updated = conn.execute(
            "UPDATE identifier_candidates SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.to_string(), status.as_str(), crate::traffic::now()],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound {
                entity: "identifier candidate",
                id: id.to_string(),
            });
        }
        Ok(())
    }

    /// How many suggestions the project holds.
    pub fn count(&self) -> Result<u64> {
        let conn = self.db.connection()?;
        let count: i64 = conn.query_row("SELECT count(*) FROM identifier_candidates", [], |r| {
            r.get(0)
        })?;
        Ok(count as u64)
    }
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<IdentifierCandidate>> {
    let id: String = row.get(0)?;
    let value: String = row.get(1)?;
    let location: String = row.get(2)?;
    let descriptor: String = row.get(3)?;
    let source: Option<String> = row.get(4)?;
    let occurrences: i64 = row.get(5)?;
    let signals: String = row.get(6)?;
    let score: i64 = row.get(7)?;
    let status: String = row.get(8)?;
    let created: String = row.get(9)?;
    let updated: String = row.get(10)?;
    let live: i64 = row.get(11)?;

    Ok((|| {
        let signals: Vec<Signal> =
            serde_json::from_str(&signals).map_err(|e| StorageError::Decode {
                entity: "candidate signals",
                reason: e.to_string(),
            })?;
        Ok(IdentifierCandidate {
            id: id.parse()?,
            value,
            location: serde_json::from_str(&location).map_err(|e| StorageError::Decode {
                entity: "object location",
                reason: e.to_string(),
            })?,
            descriptor,
            source_request: source.map(|s| s.parse()).transpose()?,
            occurrences: occurrences.max(0) as u32,
            live_observations: live.max(0) as u32,
            signals,
            score: score as i32,
            status: CandidateStatus::parse(&status).unwrap_or_default(),
            created_at: parse_time(&created)?,
            updated_at: parse_time(&updated)?,
        })
    })())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| StorageError::Decode {
            entity: "identifier candidate",
            reason: format!("{value:?} is not an RFC 3339 timestamp: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use hexora_types::candidate::{SignalKind, Strength};
    use hexora_types::object::ObjectLocation;

    use super::*;
    use crate::Project;

    fn candidate(value: &str, index: usize) -> IdentifierCandidate {
        IdentifierCandidate::new(
            value,
            ObjectLocation::PathSegment { index },
            format!("path segment {index}"),
            vec![Signal {
                kind: SignalKind::VariesInPlace,
                weight: 12,
                detail: "seen with 3 different values".into(),
            }],
        )
    }

    #[test]
    fn a_suggestion_survives_a_round_trip_with_its_reasons() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());
        let offered = candidate("1000", 2);
        store.record(&offered, &[]).unwrap();

        let read = store.get(offered.id).unwrap();
        assert_eq!(read.value, "1000");
        assert_eq!(read.status, CandidateStatus::Proposed);
        assert_eq!(read.signals.len(), 1);
        assert_eq!(read.signals[0].kind, SignalKind::VariesInPlace);
        assert_eq!(read.score, 12);
        assert_eq!(read.strength(), Strength::Medium);
        assert_eq!(read.descriptor, "path segment 2");
    }

    #[test]
    fn re_analysing_refreshes_rather_than_duplicating() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());

        let first = store.record(&candidate("1000", 2), &[]).unwrap();
        assert!(first.is_new());

        let mut again = candidate("1000", 2);
        again.signals.push(Signal {
            kind: SignalKind::AppearsInResponse,
            weight: 5,
            detail: "came back in 8 responses".into(),
        });
        again.score = 17;

        let second = store.record(&again, &[]).unwrap();
        assert!(!second.is_new());
        assert_eq!(second.id(), first.id());
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.get(first.id()).unwrap().score, 17);
    }

    #[test]
    fn a_reviewed_decision_survives_re_analysis() {
        // The rule the findings store follows, for the same reason: a queue that
        // resurrects things somebody has already dismissed is one they stop working.
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());

        let offered = candidate("1000", 2);
        let recorded = store.record(&offered, &[]).unwrap();
        store
            .set_status(recorded.id(), CandidateStatus::Rejected)
            .unwrap();

        let again = store.record(&candidate("1000", 2), &[]).unwrap();
        assert!(matches!(again, Suggested::Reviewed(_)));
        assert_eq!(
            store.get(recorded.id()).unwrap().status,
            CandidateStatus::Rejected
        );
    }

    #[test]
    fn the_same_value_somewhere_else_is_a_different_suggestion() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());
        store.record(&candidate("1000", 2), &[]).unwrap();
        store.record(&candidate("1000", 4), &[]).unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn suggestions_come_back_strongest_first() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());

        let mut weak = candidate("2", 5);
        weak.score = 3;
        let mut strong = candidate("1000", 2);
        strong.score = 30;
        store.record(&weak, &[]).unwrap();
        store.record(&strong, &[]).unwrap();

        let listed = store.list(&CandidateFilter::default()).unwrap();
        assert_eq!(listed[0].value, "1000");
        assert_eq!(listed[1].value, "2");
    }

    #[test]
    fn listing_can_be_narrowed_to_what_has_not_been_reviewed() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());
        let first = store.record(&candidate("1000", 2), &[]).unwrap();
        store.record(&candidate("2000", 2), &[]).unwrap();
        store
            .set_status(first.id(), CandidateStatus::Accepted)
            .unwrap();

        let proposed = store
            .list(&CandidateFilter {
                status: Some(CandidateStatus::Proposed),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].value, "2000");
    }

    #[test]
    fn a_missing_candidate_is_reported_as_not_found() {
        let project = Project::in_memory().unwrap();
        let store = CandidateStore::new(project.metadata().clone());
        let error = store.get(CandidateId::new()).unwrap_err();
        assert!(matches!(error, StorageError::NotFound { .. }), "{error:?}");
    }
}
