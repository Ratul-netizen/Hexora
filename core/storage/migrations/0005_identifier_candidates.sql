-- M12.7: values that might be object identifiers, and where they were seen.
--
-- Persisted rather than recomputed, because a tester captures traffic on Monday,
-- reviews suggestions on Tuesday and builds authorization tests on Friday. Analysis
-- that ran fresh each time would make a candidate somebody had already looked at
-- disappear, change score, or come back with a different id — and a review queue that
-- rewrites itself between visits is one nobody works through.
--
-- Note what is *not* here: an owner column. A candidate is a suggestion about which
-- bytes are an identifier. Whose identifier it is belongs to `object_declarations`,
-- and keeping the two tables apart is what stops a heuristic from becoming an
-- ownership assertion by way of a schema shortcut.

CREATE TABLE identifier_candidates (
    id              TEXT PRIMARY KEY,
    -- The value exactly as observed: never decoded, never normalized. `%31%30%30%30`
    -- and `1000` are different rows because an application may treat them
    -- differently, and which one it accepts is sometimes the finding.
    value           TEXT NOT NULL,
    -- Serialized `ObjectLocation`, and its stable key.
    location_json   TEXT NOT NULL,
    location_key    TEXT NOT NULL,
    -- A readable description of the place: "JSON field accountId", "path segment 2".
    descriptor      TEXT NOT NULL,
    -- One exchange it was seen in, for the tester to open. SET NULL rather than
    -- CASCADE: losing the traffic must not delete the reviewed decision, it must make
    -- the row say the traffic is gone.
    source_request_id TEXT REFERENCES requests(id) ON DELETE SET NULL,
    -- How many times it was observed when analysis last ran.
    occurrences     INTEGER NOT NULL DEFAULT 0,
    -- Serialized `Vec<Signal>`: why it was suggested, and what each reason counted
    -- for. Stored rather than recomputed so "why did Hexora suggest this?" has the
    -- same answer next week.
    signals_json    TEXT NOT NULL DEFAULT '[]',
    score           INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'proposed'
                        CHECK (status IN ('proposed', 'accepted', 'rejected', 'superseded')),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    -- The same value in the same place is one suggestion, however many times analysis
    -- runs over the same project.
    UNIQUE (value, location_key)
);

CREATE INDEX idx_identifier_candidates_status ON identifier_candidates(status);
CREATE INDEX idx_identifier_candidates_score ON identifier_candidates(score DESC);

-- Which exchanges a suggestion was drawn from.
--
-- Separate from the count on the candidate so the two can disagree, deliberately: the
-- count is what analysis saw, the rows are what the project can still show. When they
-- differ the interface says so, the same way a report prints a citation it can no
-- longer resolve rather than dropping it.
CREATE TABLE identifier_candidate_observations (
    candidate_id    TEXT NOT NULL REFERENCES identifier_candidates(id) ON DELETE CASCADE,
    request_id      TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    PRIMARY KEY (candidate_id, request_id)
);

CREATE INDEX idx_candidate_observations_request
    ON identifier_candidate_observations(request_id);
