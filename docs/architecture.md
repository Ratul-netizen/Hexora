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
| `core/storage` | SQLite metadata database, migrations, content-addressed blob store, traffic, identities, project settings | **Implemented** (findings store still pending) |
| `core/engine` | Transport boundary, scope enforcement, extension permissions, AI tool gate | **Implemented** |
| `core/http` | HTTP/1.x parser and transport, TLS, chunked framing, content decoding, streaming bodies | **Implemented** |
| `core/proxy` | Intercepting proxy, CA, TLS interception, hooks, capture | **Implemented** |
| `core/repeater` | Load a stored request, edit it, send it as a chosen principal, diff the results | **Implemented** |
| `core/authz` | Authorization matrices: replay as several identities, compare structurally, produce evidence-gated findings | **Implemented** (M12.1) |
| `apps/cli` | `hexora` headless CLI | **Implemented** |
| `apps/desktop` | Tauri shell | **Implemented** (layout unreviewed) |
| `frontend` | React + TypeScript UI | **Implemented** (layout unreviewed) |

The dependency graph is a DAG with `core/types` at the bottom and nothing depending on
the applications:

```text
types ← storage ← http ← proxy
  ↑        ↑        ↑       ↑
  └────  engine ────┴───────┤
           ↑                │
       repeater ← authz ────┤
           ↑                │
        cli · desktop ──────┘
```

`core/authz` deliberately owns no send path of its own: it drives `core/repeater`,
because loading a stored request, applying a credential, sending it and recording the
result is exactly what the repeater already does, and a second implementation would be
a second set of bugs.

### Why so few crates

An earlier draft of this workspace had eleven core crates, nine of them empty. Empty
crates are not architecture — they are a promise the compiler cannot check. Crates are
split out of `core/engine` when the milestone that needs them lands and there is real
code to separate. `core/http`, `core/proxy`, `core/repeater` and `core/authz` were each
split out that way, when their contents existed; `core/scanner` is expected and does not
exist yet, because its contents do not.

Similarly, a trait earns its place when at least two components must agree on it, or
when it is the seam an invariant is enforced at. Speculative interfaces are worse than
none: they constrain the implementation before anything is known about it.

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
