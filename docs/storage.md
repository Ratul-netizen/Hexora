# Storage

## The problem

A pentest project is not a normal CRUD workload. One engagement can produce:

- millions of HTTP exchanges,
- response bodies averaging tens to hundreds of kilobytes,
- extreme repetition (the same 404 page, the same JS bundle, thousands of times),
- write-heavy bursts from the proxy while the UI reads history concurrently,
- and a lifetime measured in years, because the project *is* the evidence behind a
  report a client may query long after the engagement ended.

Five million exchanges at 100 KB is roughly 500 GB. A relational database that is also
the primary blob repository handles that badly: the page cache fills with body bytes,
maintenance operations become impractical, and backing up the project means copying
every byte of every response.

## The split

```text
metadata  →  MetadataDb (SQLite)    small, relational, queried constantly
bodies    →  BlobStore (files)      enormous, immutable, written once, read rarely
```

A message row stores a `body_hash` and `body_size`, not the bytes. A project that
captured 500 GB of responses still has a metadata database measured in hundreds of
megabytes — small enough to stay fast, portable and quick to back up.

## On-disk layout

A project is a **directory**, not a single file:

```text
engagement.hexora/
├── project.db      metadata (SQLite, WAL)
└── blobs/          content-addressed bodies
    └── ab/
        └── abcdef…
```

A directory rather than one file is what lets the metadata stay small while the body
store grows to whatever the engagement needs, and it means the blob directory can be
excluded from a quick backup or moved to a different volume.

## Content addressing

Blobs are keyed by the lowercase hex SHA-256 of their content.

**Deduplication.** Fuzzing 50 000 payloads against an endpoint returning the same 8 KB
error page stores that page once. In practice this is the difference between a project
that stays portable and one that does not.

**Immutability.** Identical hash means identical bytes, so writes are idempotent and no
locking is needed between the proxy writing traffic and the UI reading it.

**Integrity.** `get` verifies content against the hash it was filed under and returns
`BlobIntegrity` on mismatch rather than the altered bytes. These bytes are the evidence
behind findings in a client report; silently serving corrupted data would put a false
claim in front of a client.

**Sharding.** Files sit two hex characters deep (`ab/abcdef…`). A single directory
holding a million entries is slow to enumerate on every major filesystem; 256 buckets
keeps directories manageable at the scales this is built for.

**Atomic writes.** Content is written to a unique temporary name and renamed into
place, so a crash or a concurrent writer can never leave a half-written file visible
under a hash that promises complete content. A lost rename race is a success, not a
failure — the bytes are identical by construction.

**Garbage collection.** Blobs are shared, so deletion requires knowing nothing
references them any more. `idx_requests_body_hash` and `idx_responses_body_hash` exist
for that walk. The collector itself is not written yet; until it is, deleting traffic
leaves orphaned blobs, which wastes space but is not a correctness problem.

## SQLite configuration

Set on **every** connection, not once per database:

| Pragma | Value | Why |
| ------ | ----- | --- |
| `journal_mode` | `WAL` | Lets the proxy append traffic while the UI reads history |
| `foreign_keys` | `ON` | **Off by default in SQLite and per-connection.** The schema's cascade rules are load bearing; a connection without this silently orphans rows |
| `synchronous` | `NORMAL` | Correct under WAL; `FULL` costs throughput the proxy cannot spare |
| `busy_timeout` | `5000` | Absorbs contention between the capture and UI paths |
| `temp_store` | `MEMORY` | Keeps sorting off disk |

Do not assume SQLite defaults. `foreign_keys` in particular is the one people get
wrong, and its failure mode is silent.

## Schema conventions

- **IDs are UUIDv7 stored as TEXT.** Time-ordered, so `ORDER BY id` gives capture order
  for free and no sequence column is needed, while staying globally unique so projects
  from collaborating testers can be merged without renumbering.
- **Header blocks are raw BLOBs, not parsed JSON.** Reconstructing a request from
  parsed headers loses exactly what security testing needs: duplicate fields, unusual
  casing, non-UTF-8 bytes.
- **Timestamps are RFC 3339 UTC strings.**
- **`CHECK` constraints encode invariants the application must not violate** — the
  request `origin` vocabulary, finding severity and confidence values, and the rule
  that `body_hash IS NULL` exactly when `body_size = 0`, so metadata and blob store
  cannot disagree about whether a body exists.
- **SQL stays portable enough to move to PostgreSQL** for a future team server.

## Migrations

Rules, in order of importance:

1. **Forward only.** A released migration is never edited.
2. **Append to `MIGRATIONS`.** That is the only supported way to change the schema.
3. **Each migration is transactional**, together with its version bump, so an
   interrupted upgrade leaves a consistent earlier revision rather than a half-migrated
   database.
4. **A newer schema is refused, not downgraded.** Opening a project written by a newer
   Hexora returns `SchemaTooNew`. Applying old code to a newer schema silently corrupts
   engagement evidence, and that is not a recoverable mistake.

Version tracking uses SQLite's `user_version` pragma rather than a bespoke table, so
the version is readable even from a database whose tables failed to create.

Migrations are embedded with `include_str!`, so a single-file CLI can open a project
with no data directory alongside it.

## Blocking, not async

Everything here is synchronous, because SQLite is. The async engine calls it via
`tokio::task::spawn_blocking`. Making the blob half async while its sibling stays
blocking would add `.await` without removing the constraint.

## Backend seams

The domain model is backend-agnostic; `repository.rs` holds the interfaces.

| Role | Implemented | Shaped to allow |
| ---- | ----------- | --------------- |
| Metadata | SQLite | PostgreSQL (team server) |
| Bodies | Filesystem CAS | Object storage |
| Search | — | Tantivy |
| Analytics | — | DuckDB |

The right-hand column is **not implemented and not scheduled.** It is listed because
the interfaces were shaped to accommodate it. `TrafficSearch` is a separate trait from
`TrafficStore` for exactly this reason: relational `LIKE` is fine at small scale and
useless at millions of exchanges, and splitting the trait now means that swap will not
touch the engine.

Each of those choices should be re-decided against a benchmark on real project data,
not adopted because it appears in an architecture diagram.

## Pagination

Anything that grows with traffic volume is paginated, with a hard `Limit::MAX` of 1000
rows. Cursors are opaque, not offsets: traffic is being appended while the user
scrolls, and offset pagination would skip or duplicate rows.

## Status

Implemented and tested: connection management, pragmas, migrations, the blob store,
schema constraints.

Not implemented: SQLite implementations of the repository traits (M3), blob garbage
collection, credential encryption at rest, and everything in the right-hand column
above.
