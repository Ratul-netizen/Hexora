# Architecture

## Shape

```text
        Desktop (Tauri + React)          CLI (hexora)
                    │                          │
                    └────────────┬─────────────┘
                                 │
                         Hexora core (Rust)
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
   Transport                 Enforcement              Storage
   (HTTP/TLS/WS)          scope · permissions       metadata · blobs
```

One rule shapes everything else: **the core owns the application state.** The frontend
is a view. The CLI is a second view. Neither has its own scanner, its own proxy, or its
own idea of what a project contains — otherwise a result reproduced in CI could differ
from what a tester sees, and security-relevant logic would end up in the most easily
influenced part of the process.

## Crates

| Crate | Role | Status |
| ----- | ---- | ------ |
| `core/types` | Domain model: HTTP messages, IDs, scope, identities, findings, limits, secrets, errors | **Implemented** |
| `core/storage` | SQLite metadata database, migrations, content-addressed blob store, traffic, identities, findings, identifier candidates, engagement snapshots, project settings | **Implemented** |
| `core/engine` | Transport boundary, scope enforcement, extension permissions, AI tool gate | **Implemented** |
| `core/http` | HTTP/1.x parser and transport, TLS, chunked framing, content decoding, streaming bodies | **Implemented** |
| `core/proxy` | Intercepting proxy, CA, TLS interception, hooks, capture | **Implemented** |
| `core/repeater` | Load a stored request, edit it, send it as a chosen principal, diff the results | **Implemented** |
| `core/authz` | Authorization matrices: replay as several identities, compare structurally, produce evidence-gated findings. Constructs cross-identity requests from declared object identifiers (M12.5). Suggests values that might *be* identifiers, without deciding that they are (M12.7) | **Implemented** (M12.1, M12.5, M12.7) |
| `core/report` | Renders a project's findings into Markdown, self-contained HTML or JSON, resolving every citation against the stored traffic | **Implemented** (M12.3) |
| `apps/cli` | `hexora` headless CLI | **Implemented** |
| `apps/desktop` | Tauri shell | **Implemented** |
| `frontend` | React + TypeScript UI | **Implemented** |

The dependency graph is a DAG with `core/types` at the bottom and nothing depending on
the applications:

```text
types ← storage ← http ← proxy
  ↑        ↑        ↑       ↑
  └────  engine ────┴───────┤
           ↑                │
       repeater ← authz ────┤
           ↑                │
        report ─────────────┤
           ↑                │
        cli · desktop ──────┘
```

`core/report` depends on `core/storage` and `core/types` and on nothing else: a report
is a read of a finished project, so it has no reason to reach the network and no way
to. That is why `hexora report` can be trusted to change nothing.

The suggestion analyzer inside `core/authz` goes the other way: it takes no transport
*at all*. Its whole signature is stores in, suggestions out —

```rust
fn analyze(&TrafficStore, &ObjectStore, &CandidateStore) -> Result<Suggestions>
```

— so "reading the project cannot send a request" is not a rule anybody has to follow.
There is nothing in the function to send with.

`core/authz` deliberately owns no send path of its own: it drives `core/repeater`,
because loading a stored request, applying a credential, sending it and recording the
result is exactly what the repeater already does, and a second implementation would be
a second set of bugs. That holds for *constructed* requests too — a request Hexora
built rather than replayed goes out the same way, so security invariant 1 needs no
second enforcement point.

### Why so few crates

An earlier draft of this workspace had eleven core crates, nine of them empty. Empty
crates are not architecture — they are a promise the compiler cannot check. Crates are
split out of `core/engine` when the milestone that needs them lands and there is real
code to separate. `core/http`, `core/proxy`, `core/repeater`, `core/authz` and `core/report` were each
split out that way, when their contents existed; `core/scanner` is expected and does not
exist yet, because its contents do not.

Similarly, a trait earns its place when at least two components must agree on it, or
when it is the seam an invariant is enforced at. Speculative interfaces are worse than
none: they constrain the implementation before anything is known about it.

## Four names for a message, and why they are not interchangeable

Hexora keeps more than one representation of the same HTTP message, and confusing them
produces bugs that look like protocol findings. The vocabulary is fixed:

```text
REQUEST                              RESPONSE

structured HttpRequest               structured HttpResponse
   │ serialize                          ▲ parse
   ▼                                    │
raw bytes  ────── socket ──────►  TCP bytes
                                        │ remove framing:
                                        │ chunk headers, Content-Length,
                                        │ connection close
                                        ▼
                                  transfer-decoded bytes   (`encoded_body`)
                                        │ reverse Content-Encoding:
                                        │ gzip, deflate, br
                                        ▼
                                  content-decoded bytes    (`body`)
```

**Structured message** — [`HttpRequest`] / [`HttpResponse`]. A model: fields, an
ordered header list that tolerates duplicates and odd casing, a byte body. Serializing
one produces a well-formed request, which means CRLF line endings and framing headers
added where they were missing.

**Raw bytes** — what actually crossed the socket. For a request this is
[`RawRequest`], and it is not derived from the model: a raw request is sent exactly as
the tester wrote it, so it can be malformed in ways a model cannot represent.

**Transfer-decoded bytes** — the response body with HTTP *framing* removed and nothing
else. Chunk headers are gone; a `Content-Encoding: gzip` body is still gzip. Stored as
`responses.encoded_body_hash`, and reachable with `hexora history --body --wire`.

**Content-decoded bytes** — the application's bytes, after `Content-Encoding` has been
reversed. Stored as `responses.body_hash`, and what every comparison, search and
finding is computed against.

The middle two are the pair that gets conflated, and keeping them apart is not
pedantry: **request-smuggling research is about the framing, and content-encoding
research is about what sits inside it.** A single "wire body" would be useless for
both. The framing itself is not stored as bytes at all — it is recorded as `Quirk`s on
the exchange, because what matters about a chunk header is what was irregular about
it, not the bytes it occupied.

Two consequences worth stating:

* When no coding was reversed, `encoded_body` is **absent** rather than a copy. The
  decoded body already is the transfer-decoded form, and storing it twice would double
  the cost of every ordinary response to record a fact that is already true.
  `--wire` falls back to it.
* When a body hit a limit it is **not decoded at all**, and `content_encoding` records
  what was actually reversed rather than what the header announced. A row claiming a
  transformation nobody performed would be worse than one admitting it stopped.

## Where the invariants live

The security properties in [`security-invariants.md`](security-invariants.md) are
enforced at chokepoints, not in each caller:

```text
Scanner ─┐
Fuzzer  ─┤
Workflow─┼─→ ScopeGuard ─→ HttpTransport ─→ network
AI tool ─┤
Extension┘
```

Every subsystem that can send a request receives its transport already wrapped in a
`ScopeGuard`. If each subsystem checked scope itself, the invariant would hold until
someone added a sixth subsystem — and someone always does.

The same reasoning applies to `GrantSet` (no `add` method, so no code path can widen a
permission) and `ToolGate` (the AI proposes; it does not call).

## Three statements about a string, and why only one is machine-made

The authorization work turns on a distinction that is easy to collapse and expensive
to get wrong:

| | Says | Made by |
| - | ---- | ------- |
| `IdentifierCandidate` | "this value varies where an object id would" | analysis of captured traffic |
| `ObjectDeclaration` | "this value is an invoice" | a person |
| its `owner` | "…belonging to User A" | a person |

The lifecycle is one-directional and every arrow is a human pressing something:

```text
captured traffic → candidate → (accept) → still a candidate
                                   │  declare, with an owner
                                   ▼
                            ObjectDeclaration → constructed attempt → evidence → finding
```

Accepting a candidate records that it is an identifier and nothing else. Nothing
promotes a candidate to a declaration automatically, and `IdentifierCandidate` has no
field an owner could be written into. See invariant 10.

## Live stores and one that is not

Every store in `core/storage` is live except one. Findings are refreshed in place when
a test is re-run, candidates re-scored, scope edited — which is right for a working
project and useless for the question a retest asks.

```text
live      traffic · identities · objects · candidates · findings · settings
frozen    snapshots
```

A `Snapshot` therefore holds **copies**, not references. Pointing at `findings.id`
would let a re-run rewrite the project's own past, and a regression report built on
that would be worse than none. It copies the claims, their severity, confidence and
triage state, the scope, the identities (labels and privilege — never credentials) and
the declared objects. It does not copy traffic: bodies are the largest thing in a
project by orders of magnitude, and a snapshot exists to be diffed, not restored.

The comparison itself is a pure function in `core/types` — two records in, one answer
out — so it reads no project and can be re-run over exported snapshots years later with
the same result. `SnapshotStore` has no update method, which is what makes the summary
columns on the row safe: they are computed from the contents at insert time and nothing
exists that could change one without the other.

`Contents` is stored as one JSON document, so it carries `#[serde(default)]`: a
snapshot taken by an older build must stay readable when a later one adds a field, and
any field added there must default to *the cautious answer*, because that is what an
old snapshot will silently supply.

## Storage

Split by access pattern rather than kept in one store:

```text
metadata  →  SQLite       small, relational, queried constantly
bodies    →  blob store   enormous, immutable, written once, read rarely
```

An engagement can capture millions of exchanges and hundreds of gigabytes of bodies.
Keeping bodies out of the relational database is what keeps the project portable and
quick to back up. Bodies are content-addressed by SHA-256, which deduplicates the heavy
repetition a crawl or fuzzing run produces. Details in [`storage.md`](storage.md).

## Async and blocking

The engine is `async` (Tokio). Storage is synchronous, because SQLite is. The boundary
is explicit: the engine calls storage through `spawn_blocking`. Making half the storage
layer async would hide that constraint without removing it.

## Frontend boundary

React talks to the core over Tauri IPC, through a versioned command surface. The
frontend checks `rpc_contract_version` on startup and refuses to operate against an
engine it does not understand, rather than misinterpreting its messages — a security
tool that quietly displays the wrong request is worse than one that will not start.

## Process model, and what is deliberately not in-process

Two components are expected to run **outside** the core process:

- **The Burp/Montoya compatibility layer.** Running a JVM inside the core would drag
  the entire Java runtime into a Rust security tool's address space, and would give
  arbitrary Burp extensions direct memory access to credentials. It belongs in a
  separate process behind a restricted RPC interface. This is a multi-month subproject,
  independently versioned, with a public compatibility matrix rather than a claim of
  universal support. See `compatibility/burp-montoya/`.
- **The AI layer**, for the same isolation reasons.

Neither exists yet. They are named here so the boundaries stay clean while the core is
built, not to suggest work is underway.

## What is deliberately deferred

PostgreSQL, object storage, Tantivy search and DuckDB analytics are all plausible and
the interfaces were shaped so they can slot in. None is scheduled, and each should be
re-decided against a benchmark on real project data rather than adopted because it
appears in an architecture diagram.
