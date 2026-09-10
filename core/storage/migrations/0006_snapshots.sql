-- M12.8: what the engagement looked like at a moment.
--
-- Everything else in this schema is *live*: findings are refreshed in place when a
-- test is re-run, candidates are re-scored, scope is edited. That is right for a
-- working project and useless for the question a retest asks — "what changed?" — which
-- needs a record of what was true then that a later run cannot rewrite.
--
-- So a snapshot is a copy, not a set of references. If it pointed at `findings.id` its
-- own past would change every time somebody re-ran a matrix, and a regression report
-- built on that would be worse than none.
--
-- There is deliberately no UPDATE path anywhere in `snapshots.rs`. A snapshot is
-- written once, read many times, and deleted whole. That is what makes the summary
-- columns safe: they are computed from `contents_json` at insert time and can never
-- drift from it, because nothing can change one without the other.

CREATE TABLE snapshots (
    id              TEXT PRIMARY KEY,
    -- What the tester called it: "before the fix", "day 3", "retest".
    label           TEXT NOT NULL,
    note            TEXT,
    taken_at        TEXT NOT NULL,
    -- The build that took it. A claim that stopped appearing after an upgrade and one
    -- that stopped appearing after a fix are different events, and a comparison that
    -- cannot tell them apart would report the first as the second.
    tool_version    TEXT NOT NULL,
    -- The project schema revision at the time, so a snapshot taken by an older build
    -- can be read back and understood rather than guessed at.
    schema_version  INTEGER NOT NULL,

    -- Summary, so listing snapshots never has to parse the contents below.
    exchanges           INTEGER NOT NULL DEFAULT 0,
    candidates          INTEGER NOT NULL DEFAULT 0,
    candidates_reviewed INTEGER NOT NULL DEFAULT 0,
    finding_count       INTEGER NOT NULL DEFAULT 0,
    identity_count      INTEGER NOT NULL DEFAULT 0,
    object_count        INTEGER NOT NULL DEFAULT 0,

    -- The serialized `snapshot::Contents`: scope, identities, declared objects and
    -- every claim as it stood.
    --
    -- Note what is *not* in here, and cannot be: an identity is recorded as its label
    -- and privilege level. `Credential` never reaches a snapshot, because a snapshot is
    -- the most copied, most exported and longest-lived artefact a project produces and
    -- session material has no business in one.
    --
    -- Note also what is not in here: traffic. Bodies are the largest thing in a project
    -- by orders of magnitude and a snapshot exists to be diffed, not restored. The
    -- exchange count above is what a comparison actually needs.
    contents_json   TEXT NOT NULL
);

CREATE INDEX idx_snapshots_taken_at ON snapshots(taken_at DESC);
