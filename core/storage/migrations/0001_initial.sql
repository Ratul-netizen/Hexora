-- Hexora project schema, revision 1 (SQLite backend).
--
-- Design notes:
--
-- * This database stores **metadata only**. HTTP bodies live in the content-addressed
--   blob store (see src/blob.rs) and are referenced here by `*_body_hash` plus
--   `*_body_size`. A project that captured 500 GB of responses still has a database
--   measured in hundreds of megabytes, which keeps it portable, backup-able and fast.
-- * IDs are UUIDv7 stored as TEXT. They sort chronologically, so `ORDER BY id` gives
--   capture order for free and no separate sequence column is needed.
-- * Header blocks are stored as raw BLOBs, not parsed JSON. Reconstructing a request
--   from parsed headers loses exactly the detail security testing needs: duplicate
--   fields, unusual casing, non-UTF-8 bytes.
-- * Timestamps are RFC 3339 in UTC.
-- * SQL here must stay portable enough to port to PostgreSQL for the team server; it
--   avoids SQLite-only syntax except where noted.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Project metadata
-- ---------------------------------------------------------------------------

CREATE TABLE project (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- Serialized `hexora_types::scope::Scope`.
    scope_json      TEXT NOT NULL DEFAULT '{"include":[],"exclude":[]}',
    settings_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Targets and attack surface
-- ---------------------------------------------------------------------------

CREATE TABLE targets (
    id              TEXT PRIMARY KEY,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    secure          INTEGER NOT NULL CHECK (secure IN (0, 1)),
    technologies    TEXT NOT NULL DEFAULT '[]',
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    UNIQUE (host, port, secure)
);

CREATE TABLE endpoints (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    -- Path with dynamic segments collapsed, e.g. /api/users/{id}. This is what keeps
    -- the target map readable when a crawl produced 40 000 concrete URLs.
    path_template   TEXT NOT NULL,
    request_count   INTEGER NOT NULL DEFAULT 0,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    UNIQUE (target_id, method, path_template)
);

CREATE INDEX idx_endpoints_target ON endpoints(target_id);

-- ---------------------------------------------------------------------------
-- Testing identities
-- ---------------------------------------------------------------------------

CREATE TABLE identities (
    id              TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    privilege       TEXT NOT NULL CHECK (privilege IN
                        ('anonymous', 'user', 'elevated', 'administrator')),
    -- Serialized `Credential`. Encrypted at rest when the project has a passphrase;
    -- see docs/threat-model.md.
    credential_json TEXT NOT NULL,
    extra_headers   TEXT NOT NULL DEFAULT '[]',
    owned_object_ids TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Traffic
-- ---------------------------------------------------------------------------

CREATE TABLE requests (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    endpoint_id     TEXT REFERENCES endpoints(id) ON DELETE SET NULL,
    -- Which subsystem produced this request.
    origin          TEXT NOT NULL CHECK (origin IN
                        ('proxy', 'repeater', 'scanner', 'fuzzer', 'workflow',
                         'extension', 'import', 'authz')),
    identity_id     TEXT REFERENCES identities(id) ON DELETE SET NULL,
    -- Repeater request branching: a variant points at the request it derives from.
    parent_id       TEXT REFERENCES requests(id) ON DELETE SET NULL,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    http_version    TEXT NOT NULL,
    -- Raw header block exactly as sent, CRLF-separated.
    headers_raw     BLOB NOT NULL,
    -- Body reference into the blob store. NULL means an empty body.
    body_hash       TEXT,
    body_size       INTEGER NOT NULL DEFAULT 0,
    sent_at         TEXT NOT NULL,
    notes           TEXT,
    tags            TEXT NOT NULL DEFAULT '[]',
    CHECK (body_size >= 0),
    CHECK ((body_hash IS NULL) = (body_size = 0))
);

CREATE INDEX idx_requests_target_time ON requests(target_id, sent_at);
CREATE INDEX idx_requests_endpoint ON requests(endpoint_id);
CREATE INDEX idx_requests_origin ON requests(origin);
CREATE INDEX idx_requests_parent ON requests(parent_id);
-- Blob garbage collection walks references by hash.
CREATE INDEX idx_requests_body_hash ON requests(body_hash);

CREATE TABLE responses (
    id              TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL UNIQUE REFERENCES requests(id) ON DELETE CASCADE,
    status          INTEGER NOT NULL,
    reason          TEXT,
    http_version    TEXT NOT NULL,
    headers_raw     BLOB NOT NULL,
    body_hash       TEXT,
    body_size       INTEGER NOT NULL DEFAULT 0,
    -- Whether a resource limit cut the body short. Evidence derived from a truncated
    -- body must disclose this, so it is stored rather than inferred.
    truncated       INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    -- Round-trip time in milliseconds; the basis for the scanner's timing analysis.
    duration_ms     INTEGER,
    received_at     TEXT NOT NULL,
    CHECK (body_size >= 0),
    CHECK ((body_hash IS NULL) = (body_size = 0))
);

CREATE INDEX idx_responses_status ON responses(status);
CREATE INDEX idx_responses_body_hash ON responses(body_hash);

CREATE TABLE websocket_messages (
    id              TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    direction       TEXT NOT NULL CHECK (direction IN ('client_to_server', 'server_to_client')),
    opcode          INTEGER NOT NULL,
    -- Small frames inline; larger ones go to the blob store like bodies do.
    payload         BLOB,
    payload_hash    TEXT,
    payload_size    INTEGER NOT NULL DEFAULT 0,
    sent_at         TEXT NOT NULL,
    CHECK (payload IS NULL OR payload_hash IS NULL)
);

CREATE INDEX idx_ws_request ON websocket_messages(request_id, sent_at);

-- Free-form tester notes, attachable to a target, endpoint or exchange.
CREATE TABLE notes (
    id              TEXT PRIMARY KEY,
    target_id       TEXT REFERENCES targets(id) ON DELETE CASCADE,
    request_id      TEXT REFERENCES requests(id) ON DELETE CASCADE,
    body            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_notes_target ON notes(target_id);

-- ---------------------------------------------------------------------------
-- Findings
-- ---------------------------------------------------------------------------

CREATE TABLE findings (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN
                        ('info', 'low', 'medium', 'high', 'critical')),
    confidence      TEXT NOT NULL CHECK (confidence IN
                        ('reported', 'tentative', 'firm', 'confirmed')),
    status          TEXT NOT NULL DEFAULT 'new' CHECK (status IN
                        ('new', 'triaged', 'confirmed', 'false_positive',
                         'duplicate', 'reported', 'fixed', 'accepted')),
    location_json   TEXT,
    description     TEXT NOT NULL,
    impact          TEXT NOT NULL,
    remediation     TEXT NOT NULL,
    reproduction    TEXT NOT NULL,
    cwe             TEXT,
    owasp           TEXT,
    cvss            TEXT,
    source_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_findings_severity ON findings(severity, confidence);
CREATE INDEX idx_findings_target ON findings(target_id);

-- Evidence is a separate table so a finding can cite many exchanges, and so deleting
-- traffic cannot leave a finding citing a request that no longer exists.
CREATE TABLE finding_evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    ordinal         INTEGER NOT NULL,
    -- Serialized `hexora_types::finding::Evidence`.
    evidence_json   TEXT NOT NULL,
    UNIQUE (finding_id, ordinal)
);

-- ---------------------------------------------------------------------------
-- Scanning, attacks, out-of-band
-- ---------------------------------------------------------------------------

CREATE TABLE scanner_jobs (
    id              TEXT PRIMARY KEY,
    target_id       TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('passive', 'active', 'verification')),
    state           TEXT NOT NULL CHECK (state IN
                        ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    requests_sent   INTEGER NOT NULL DEFAULT 0,
    findings_count  INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_scanner_jobs_state ON scanner_jobs(state);

CREATE TABLE attacks (
    id              TEXT PRIMARY KEY,
    base_request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    -- Serialized attack configuration: insertion points, payload sets, matchers.
    config_json     TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN
                        ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    total_requests  INTEGER,
    sent_requests   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE oob_interactions (
    id              TEXT PRIMARY KEY,
    -- The unique subdomain or token planted in the payload.
    correlation_id  TEXT NOT NULL,
    -- Set once the interaction is attributed to the request that caused it.
    request_id      TEXT REFERENCES requests(id) ON DELETE SET NULL,
    protocol        TEXT NOT NULL,
    source_ip       TEXT,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    received_at     TEXT NOT NULL
);

CREATE INDEX idx_oob_correlation ON oob_interactions(correlation_id);

-- ---------------------------------------------------------------------------
-- Workflows and extensions
-- ---------------------------------------------------------------------------

CREATE TABLE workflows (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- Node graph, exportable as JSON/YAML.
    definition_json TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE workflow_runs (
    id              TEXT PRIMARY KEY,
    workflow_id     TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN
                        ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    -- Per-node execution log, for debugging a workflow that misbehaved.
    trace_json      TEXT NOT NULL DEFAULT '[]',
    error           TEXT,
    started_at      TEXT,
    finished_at     TEXT
);

CREATE TABLE extensions (
    id              TEXT PRIMARY KEY,
    -- Reverse-DNS identifier from the manifest, e.g. com.example.paramscanner.
    manifest_id     TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    tier            TEXT NOT NULL CHECK (tier IN ('native', 'wasm', 'javascript', 'burp_compat')),
    enabled         INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- Permissions the user actually granted, which may be fewer than those requested.
    granted_permissions TEXT NOT NULL DEFAULT '[]',
    settings_json   TEXT NOT NULL DEFAULT '{}',
    installed_at    TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------

-- Records privileged actions: extension permission grants, AI tool approvals, scope
-- changes, credential access, bulk traffic deletion. Append-only by convention; a
-- tester needs to be able to answer "what did this tool do, and when".
CREATE TABLE audit_events (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    actor           TEXT NOT NULL,
    summary         TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    occurred_at     TEXT NOT NULL
);

CREATE INDEX idx_audit_time ON audit_events(occurred_at);
