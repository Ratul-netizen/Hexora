-- M13.3: how much traffic a run put on somebody's system.
--
-- Every earlier run in this table read stored traffic and sent nothing, so "what did
-- this cost the target?" had one answer: nothing. An active run has to be able to
-- answer it with a number, because it is the question a client asks afterwards and
-- the one an engagement report should not have to guess at.
--
-- Defaulted to zero rather than NULL: every run recorded before this column existed
-- genuinely sent nothing, so zero is the true value rather than a stand-in for an
-- unknown one.
ALTER TABLE scan_runs ADD COLUMN requests_sent INTEGER NOT NULL DEFAULT 0;

-- Why a run ended before working through its queue, for the runs that did.
--
-- NULL means it finished. Anything else means the run is *unfinished*, and a retest
-- comparing two engagements must not read its silence as a clean result — the same
-- distinction `WhyGone` draws for a claim, drawn for a whole run.
ALTER TABLE scan_runs ADD COLUMN stopped_because TEXT
    CHECK (stopped_because IN ('cancelled', 'ceiling'));
