-- M13.2: a record that a check ran.
--
-- M12.8 can already tell "this claim is gone" from "this claim changed". What it
-- cannot tell, and said so in `WhyGone::SourceSilent`, is *the check ran and found
-- nothing* from *the check never ran* — because a check that finds nothing writes
-- nothing, and silence looks identical either way.
--
-- These two tables are the difference. A run says which detectors executed, at which
-- versions, over which traffic, and what each produced. A later retest can then say
-- "headers.security ran at 1.0.0 over 184 exchanges and raised nothing" instead of
-- shrugging.
--
-- Not a scheduler. A passive run is one pass over stored traffic with a start and an
-- end; queues, concurrency and retries belong to M13.3, and inventing them here would
-- be inventing them blind.

CREATE TABLE scan_runs (
    id              TEXT PRIMARY KEY,
    -- What the run was pointed at, as the operator asked for it: a host filter, a
    -- detector filter, a limit. Stored so "nothing was found" can be read against
    -- what was actually looked at.
    selection       TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    -- NULL while a run is in flight, which is also what a crashed run looks like.
    -- Deliberately not defaulted to the start time: a run that never finished must
    -- not read as one that did.
    completed_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'completed', 'failed')),
    -- How much traffic was read, and how much was deliberately not.
    exchanges_read  INTEGER NOT NULL DEFAULT 0,
    exchanges_skipped INTEGER NOT NULL DEFAULT 0,
    -- The Hexora build. Same reasoning as `snapshots.tool_version`.
    tool_version    TEXT NOT NULL
);

CREATE INDEX idx_scan_runs_started_at ON scan_runs(started_at DESC);

-- One row per detector per run: the point of the whole table.
--
-- A detector with zero observations and zero hypotheses is the most valuable row
-- here, because it is the one that turns silence into a fact.
CREATE TABLE scan_run_detectors (
    run_id          TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    detector_id     TEXT NOT NULL,
    -- The version that ran. A claim that stopped appearing because the check was
    -- rewritten is not a claim that was fixed; this is how the two are told apart.
    detector_version TEXT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('passive', 'active')),
    observations    INTEGER NOT NULL DEFAULT 0,
    hypotheses      INTEGER NOT NULL DEFAULT 0,
    -- Of the observations, how many were worth reporting rather than being context.
    reportable      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, detector_id)
);
