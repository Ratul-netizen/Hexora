-- M12.5: declared object identifiers, and the requests constructed from them.
--
-- Two tables, and the split matters. A declaration is data a tester entered: "this
-- string is an invoice belonging to User A". A constructed attempt is a request that
-- was actually sent, and it exists as a row in `requests` like any other — this table
-- only records *why* it exists, so the substitution behind a finding can be read back
-- months later instead of being inferred from two paths that differ by one segment.

CREATE TABLE object_declarations (
    id                TEXT PRIMARY KEY,
    -- What kind of object, for the reader. Never used for matching.
    name              TEXT NOT NULL,
    -- The identifier exactly as it appears in a request.
    value             TEXT NOT NULL,
    owner_id          TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- The request the value was found in. Kept so a declaration can be traced back to
    -- the traffic that justified it; the declaration survives the traffic being
    -- pruned, because the claim it supports is about the value, not the exchange.
    source_request_id TEXT REFERENCES requests(id) ON DELETE SET NULL,
    -- Serialized `ObjectLocation`.
    location_json     TEXT NOT NULL,
    -- Stable key of that location, so "the same value in the same place" is one
    -- declaration however many times somebody declares it.
    location_key      TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    UNIQUE (owner_id, value, location_key)
);

CREATE INDEX idx_object_declarations_owner ON object_declarations(owner_id);
CREATE INDEX idx_object_declarations_value ON object_declarations(value);

-- Why a constructed request exists.
--
-- `request_id` is the generated request; `source_request_id` is what it was built
-- from. The generated row already carries `parent_id` and `identity_id`, so this adds
-- exactly the two facts those cannot express: which declaration was substituted in,
-- and what value it replaced.
CREATE TABLE constructed_attempts (
    request_id        TEXT PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
    source_request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    declaration_id    TEXT REFERENCES object_declarations(id) ON DELETE SET NULL,
    -- Who sent it. Redundant with requests.identity_id and kept anyway: a finding
    -- cites this table, and a join that silently returns NULL because the identity
    -- was deleted would leave a claim with no sender.
    sender_id         TEXT REFERENCES identities(id) ON DELETE SET NULL,
    location_json     TEXT NOT NULL,
    -- The value that was there, and the value that replaced it. Object identifiers,
    -- never credentials: the substitution never touches an authorization header.
    original_value    TEXT NOT NULL,
    replacement_value TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE INDEX idx_constructed_attempts_source ON constructed_attempts(source_request_id);
CREATE INDEX idx_constructed_attempts_declaration ON constructed_attempts(declaration_id);
