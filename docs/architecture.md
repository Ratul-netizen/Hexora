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
| `core/verify` | The verification framework: detector and verifier traits, the one way to run an experiment, and the registry of what a build checks for | **Implemented** (M13.1) |
| `core/scan` | Passive checks over captured traffic, and the pass that runs them. Takes no transport | **Implemented** (M13.2) |
| `core/authz` | Authorization matrices: replay as several identities, compare structurally, produce evidence-gated findings. Constructs cross-identity requests from declared object identifiers (M12.5). Suggests values that might *be* identifiers, without deciding that they are (M12.7) | **Implemented** (M12.1, M12.5, M12.7) |
| `core/report` | Renders a project's findings into Markdown, self-contained HTML or JSON, resolving every citation against the stored traffic, and compiles a finding into a runnable reproduction | **Implemented** (M12.3, M12.9) |
| `core/types::structure` | Says *where* two response bodies differ, by JSON path, under a normalization policy the caller passes in and the report prints | **Implemented** (M12.10) |
| `core/active` | The queue: settles the hypotheses a passive pass could not, one host at a time, under a request ceiling, from a plan produced without sending | **Implemented** (M13.3, M13.4) |
| `core/fuzz` | One request, many values, and responses grouped by behaviour. Operator-driven: borrows the budget and the stop signal, concludes nothing | **Implemented** (M14.1) |
| `core/types::inject` | Where a value sits in a request and how to put a different one there — shared by constructed authorization tests and by input probing | **Implemented** (M13.4) |
| `core/types::echo` | Where a value came back and which of its characters survived, under the response's declared content type | **Implemented** (M13.4) |
| `core/types::redirect` | Where a `Location` header would send a browser, resolved rather than matched — and never followed | **Implemented** (M13.5) |
| `core/types::credential` | Breaking a session on purpose without ever writing one down: no `Display`, a redacting `Debug`, one named accessor | **Implemented** (M13.6) |
| `core/authz` primitives | `replay_once` and `judge` are public, so the scheduler runs the same matrix and the same confidence ladder as `hexora authz` rather than a second copy | **Implemented** (M13.7) |
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
       repeater ← verify ───┤
           ↑        ↑       │
           ├─── authz ──────┤
           │                │
         scan ──────────────┤
           ↑                │
        report ─────────────┤
           ↑                │
        cli · desktop ──────┘
```

`core/report` depends on `core/storage` and `core/types` and on nothing else: a report
is a read of a finished project, so it has no reason to reach the network and no way
to. That is why `hexora report` can be trusted to change nothing.

`core/verify` sits below `core/authz` rather than inside it, which is the whole point:
the framework must not depend on the first thing built on it, or the second thing will
have to bend to fit the first. The data types it works with — `Hypothesis`,
`Verification`, `Verified` — live in `core/types` instead, because `core/storage` has
to see `Verified` in order to refuse everything else.

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

Since M13.1 a verifier does not even receive a transport. It receives a `Lab`, whose
entire interface is *send this request as this principal*, and whose only
implementation is backed by the repeater — so a check has no way to reach the network
except through the guard, and no way to forget to record what it sent.

The same reasoning applies to `GrantSet` (no `add` method, so no code path can widen a
permission) and `ToolGate` (the AI proposes; it does not call).

## A suspicion and a claim are different types

The distinction every scanner after M13.1 is built on, and the reason it is a type
rather than a convention:

| | Says | Produced by | Can be stored |
| - | ---- | ----------- | ------------- |
| `Hypothesis` | "this looks suspicious" | a `Detector`, cheaply | **no** |
| `Verification` | what an experiment showed | a `Verifier`, through a `Lab` | — |
| `Verified` | "this is true, and here is the traffic" | `Verified::conclude` | yes |

`FindingStore` accepts only the third. There is no conversion from the first, so a
noisy check cannot become a noisy report by taking a shortcut — the call does not
compile. Confidence is derived from the verification rather than chosen by the
detector, so the ladder from *lead* to *confirmed* is written once, in
`core/types/src/verify.rs`, instead of once per check.

A detector's `examine` is synchronous and takes no `Lab`; a verifier's `verify` takes
one and nothing else that can send. The passive/active distinction is therefore
visible in the signature rather than in a comment.

M12.1 and M12.5 were rewritten onto this in the same change, so the framework has a
real user rather than a hypothetical one: `MatrixDetector` raises a hypothesis per
violating cell, `ReplayVerifier` runs the second experiment through a `Lab`, and the
findings come out the far end identical to what the hand-written path produced.

## A comparison that produces a sentence

`Fingerprint` answers "did the same kind of document come back?" and throws the
document away doing it. That is the right reduction for a score and the wrong one for
something a reader can check, so `Baseline` keeps the owner's bytes as well and
`hexora_types::structure` compares against them:

```text
fingerprint  →  "97% alike"                      a number nobody can verify
structure    →  "$.email was present for         a claim somebody can check
                 User A and absent for User B"
```

Normalization is the dangerous part, so it is a `Policy` the caller passes in rather
than a behaviour the engine has. Nothing is removed — a field set aside is still
listed with both values and the reason — and `Policy::describe()` travels with the
comparison into the CLI output, the matrix JSON, the evidence line and the window. See
invariant 14.

It buys the authorization engine a second route to `Support::Distinctive`: two
identities served *the same document*, with an unauthenticated request refused that
document, without a hand-declared object id. The anonymous control is the gate,
because two identities reading an identical *public* page looks exactly the same from
inside the comparison.

## The last mile: evidence that can be run

A claim in a report invites an argument. The two requests that produced it, in a form
a triager can paste into a terminal, end one — so `core/report` compiles a finding's
evidence into a reproduction:

```text
Finding
  └── Evidence::Comparison { baseline, variant, difference }
        │  read back from the project's traffic
        ▼
      Step 1  the control request, as User A
      Step 2  the same request, as User B     Expect: the difference
```

Nothing is composed. Every step names a `RequestId` the project holds, the bytes come
from that stored request, and a citation that cannot be resolved is printed as a gap
rather than guessed at. Credentials become placeholders named after the identity —
see invariant 13.

`curl` is offered only where curl can express the request. Four conditions rule it out
— a non-UTF-8 body, two `Content-Length` headers, a `Content-Length` that disagrees
with the body, and a bare-LF header block — and each is a thing a real finding is
sometimes about. The refusal carries the reason, and the raw form is always there.

## The queue, and what it promises

`hexora-scan` cannot send — `passive::scan` has no transport in its signature.
`hexora-active` is the crate where sending lives, and the split is the point:

```text
Plan::prepare(project, lab, checks, hypotheses, budget)  →  Plan     synchronous
run(plan, lab, checks, cancel)                           →  Outcome  the only sender
```

A dry run is the first function without the second. There is no flag on a sending path
that a future edit could stop honouring.

Within a run, **one host has one sequential queue**; the queues are futures driven
together on a single task by `buffer_unordered`, so the scheduler holds a `&dyn Lab`
across the whole run and stopping needs no cross-thread handshake. The request ceiling
is enforced by a `Metered` lab wrapped around the real one, so a check that loops is
stopped by the thing it was handed rather than by its own restraint.

`ActiveCheck` is object-safe where `Verifier` is not, and that is the whole reason it
exists separately: a verifier is written by a subsystem that knows its own case type,
and a scheduler holds a `Vec` of checks it knows nothing about. See invariant 15.

## Passive and active are a type, not a convention

`DetectorInfo::mode` says whether running a check puts traffic on the wire, and
`hexora detectors` prints it. That matters more than it sounds: it is the difference
between a check that is safe against production at 3pm and one that is not, and until
M13.2 it lived in people's heads.

It is also enforced by shape rather than by promise. `core/scan`'s entry point is:

```rust
pub fn scan(project: &Project, selection: &Selection) -> Result<Summary>
```

There is no transport to pass it. A passive check that wanted to send would have to
change that signature, which is a visible act rather than a quiet one — the same
technique `suggest::analyze` uses, and the reason both can be run on a client's
project without asking anybody first.

A passive check produces up to three things, and the scanner decides what becomes of
each. It does **not** choose its own verification: the pass applies
`Verification::Observed` to every observation, so the ceiling for anything passive is
a lead, uniformly and by construction. See invariant 12.

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
