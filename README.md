# Hexora

**The Modern Offensive Security Workbench**

Hexora is a web and API security testing platform for **authorized** penetration
testing, application security testing and security research. It is built as a fast
native core in Rust, with a desktop client (Tauri + React), a headless CLI that shares
the same engine, and an extension system with a real permission model.

> ⚠️ **For authorized security testing only.** Using Hexora against systems you do not
> own or have written permission to test is illegal in most jurisdictions.

---

## Status: M14.1 — one request, many values, and the row that does not match

Hexora intercepts traffic, stores it as evidence, replays it, and now tells you whether
an application actually checks *who* is asking:

```console
$ hexora authz ./engagement req_01a08c30bf9d… --as-identity "User A" --verify
GET https://api.example.com/accounts/acct-1000
Baseline: User A → 200

IDENTITY               PRIVILEGE      STATUS  OUTCOME       SIM    VERDICT
User B                 user           200     allowed       1.00   VIOLATION
Anonymous              anonymous      401     denied        0.00   ok

Compared with User A's response, field by field:

  User B: the same document at every one of its 7 field(s)
    2 field(s) set aside: 21 field name(s) treated as changing every request; credential values withheld
      $.csrf_token — value withheld: the field name says it is a credential
      $.served_at — `2026-09-11T11:00:01Z` for User A, `2026-09-11T11:00:04Z` for User B (the policy treats this field as changing every request)

1 candidate finding(s):

  [high/confirmed] Broken object-level authorization in GET /accounts/acct-1000
  … was replayed as User B (ordinary user), an identity that should not be able to
  reach User A's object, and the application served it anyway.

Recorded 1 finding(s) in the project.
```

The finding is in the project, not just the terminal — with the two request ids behind
it, so the claim can be re-opened and re-run months later:

```console
$ hexora findings ./engagement
ID                                     SEVERITY  CONFIDENCE STATUS   TITLE
fnd_01a08c5140…                        high      confirmed  new      Broken object-level authorization in GET /accounts/acct-1000
```

And it renders into a document somebody can be handed, with the request and the
response quoted under every claim, credentials redacted, and unverified leads kept in
their own section rather than dressed up as findings:

```console
$ hexora report ./engagement --format html --output acme.html
Wrote acme.html (10875 bytes): 1 established issue across 13 exchanges, plus 1 unverified lead.
1 unverified lead is listed separately. Re-run the test with --verify before presenting it as an issue.
```

All of that is in the desktop window too, on the same crates: declare scope and
identities, pick a captured request, replay it as everybody, read the matrix, open any
cell's exchange, work the findings list, follow a claim back to the traffic behind it,
triage, and preview the report before writing it.

Unimplemented paths return `NotImplemented` naming the milestone that will provide
them, rather than empty results, and `hexora --help` lists only commands that genuinely
work.

| Area | Status |
| ---- | ------ |
| Domain model (HTTP messages, scope, identities, findings, limits, secrets) | **IMPLEMENTED** |
| HTTP/1.x engine over TCP — wire-preserving parser, per-phase timeouts | **IMPLEMENTED** |
| TLS / HTTPS with certificate policy fit for testing | **IMPLEMENTED** |
| Chunked transfer decoding, gzip / deflate / brotli, streaming bodies | **IMPLEMENTED** |
| Both body forms kept: transfer-decoded and content-decoded (`history --body --wire`) | **IMPLEMENTED** |
| Raw request mode — bytes sent exactly as written (`repeat --raw`) | **IMPLEMENTED** |
| Intercepting proxy, TLS interception, request/response hooks | **IMPLEMENTED** |
| Interception CA, trust installation, `hexora setup` | **IMPLEMENTED** |
| Project storage: SQLite metadata + content-addressed blob store, migrations | **IMPLEMENTED** |
| Traffic history, Repeater with diffing and branch trees | **IMPLEMENTED** |
| Identities, project scope, authorization matrix (`hexora authz`) | **IMPLEMENTED** |
| Declared object identifiers and constructed cross-identity attempts (`hexora object`, `authz --construct`) | **IMPLEMENTED** |
| Findings persisted with their evidence, triage (`hexora findings`) | **IMPLEMENTED** |
| Suggested identifiers with the reasoning behind each one, never an ownership claim (`hexora identifiers`) | **IMPLEMENTED** |
| Engagement snapshots and retest comparison, which report why a claim is gone and never that it is fixed (`hexora snapshot`) | **IMPLEMENTED** |
| Verification framework: a detector raises a hypothesis, only a verifier's result can be stored, and the compiler enforces it (`hexora detectors`) | **IMPLEMENTED** |
| Passive scanner: six checks over captured traffic, sending nothing, every result a lead (`hexora scan passive`) | **IMPLEMENTED** |
| Proof-of-concept compilation: a finding becomes runnable steps, credentials replaced by placeholders (`hexora poc`) | **IMPLEMENTED** |
| Structural response comparison: which JSON field differed, at which path, under a normalization policy the report states | **IMPLEMENTED** |
| Active scheduler: one queue per host, a request ceiling, a plan you see before anything is sent (`hexora scan active`) | **IMPLEMENTED** |
| Reflected-input verification: which characters survived, and whether they landed in markup, script or data | **IMPLEMENTED** |
| Redirect verification: the `Location` header resolved the way a browser resolves it, and never followed | **IMPLEMENTED** |
| Authentication enforcement: whether an endpoint needs a session, and whether it verifies the one it is given | **IMPLEMENTED** |
| Cross-identity access, scheduled: every authenticated endpoint replayed as every other identity, owner inferred from the captured credential | **IMPLEMENTED** |
| Intruder: one request, a payload list, and responses grouped by behaviour so the outlier is one short row (`hexora fuzz`) | **IMPLEMENTED** |
| Scope enforcement at the transport boundary | **IMPLEMENTED** |
| Extension permission model · AI tool-permission gate | **IMPLEMENTED** |
| Desktop UI: project, CA, proxy, history, repeater, scope, identities, identifier suggestions, the authorization matrix, findings, the report and snapshots | **IMPLEMENTED** |
| Reports: Markdown / HTML / JSON, every claim citing its exchange (`hexora report`) | **IMPLEMENTED** |
| Attack chains | **PLANNED (rest of M12)** |
| Connection reuse | **DEFERRED (M1.4)** |
| Active scanner, Fuzzer, Workflows, OAST, AI, Burp compatibility | **PLANNED** |

Full detail: [`docs/roadmap.md`](docs/roadmap.md).

---

## What Hexora is trying to be

Not a Burp clone. The bet is on four things that existing tools do not do well:

- **Evidence-driven findings.** A heuristic match is a *lead*, not a vulnerability.
  Nothing is promoted above "reported" without evidence pointing at re-runnable
  traffic, and neither passive checks nor the AI layer can self-certify a finding.
- **Authorization testing as a first-class feature.** Replaying the same request as
  several identities and comparing the results is the highest-value manual work in most
  engagements, and it is almost entirely mechanical.
- **Automation that produces a report.** Workflows and attack chains that keep their
  evidence, so the write-up is close to automatic.
- **A permission model that means something.** Extensions and AI tools get exactly what
  was granted, enforced at a chokepoint rather than per-caller.

Burp compatibility is intended, but as an [independently versioned
subproject](docs/roadmap.md#notes-on-the-harder-items) with a public compatibility
matrix — not as a claim that every extension works.

---

## Architecture in one diagram

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

The core owns all application state; the frontend and CLI are views over it. Security
properties are enforced at chokepoints — every subsystem that can send a request gets
its transport already wrapped in a scope guard, so the check happens once rather than
in each of six callers.

See [`docs/architecture.md`](docs/architecture.md).

---

## Building

Requires Rust 1.88+ (the toolchain is pinned in `rust-toolchain.toml`), Node 20+, pnpm 9+.

```bash
# Core crates and CLI
cargo test --workspace --exclude hexora-desktop
cargo run -p hexora-cli -- --help
cargo run -p hexora-cli -- send http://example.com/

# Frontend
pnpm -C frontend install
pnpm -C frontend build
```

The desktop shell additionally needs [Tauri's system
dependencies](https://tauri.app/start/prerequisites/), and on Windows the MSVC C++
build tools.

**On Windows, build from PowerShell rather than Git Bash.** Git for Windows ships a
coreutils `link.exe` that shadows MSVC's linker and produces an error that looks
nothing like a toolchain problem. Full instructions:
[`docs/development.md`](docs/development.md).

---

## Documentation

| Document | Contents |
| -------- | -------- |
| [`docs/architecture.md`](docs/architecture.md) | Crate layout, boundaries, process model |
| [`docs/security-invariants.md`](docs/security-invariants.md) | The eight rules the codebase does not break, and where each is enforced |
| [`docs/threat-model.md`](docs/threat-model.md) | Hostile targets, extensions, local attackers — and the limits |
| [`docs/storage.md`](docs/storage.md) | Why bodies are not in the database |
| [`docs/development.md`](docs/development.md) | Building, testing, conventions |
| [`docs/roadmap.md`](docs/roadmap.md) | What exists and what does not |
| [`docs/feature-parity.md`](docs/feature-parity.md) | Burp / Caido / ZAP parity matrix and competitive position |
| [`docs/dependencies.md`](docs/dependencies.md) | Dependency, audit and secret-scanning policy |

**Read the threat model before trusting Hexora with a client's credentials.** It states
plainly what is not protected — notably that project data is not encrypted at rest and
that native and Burp-compatible extensions are not sandboxed.

---

## Contributing

Read [`docs/security-invariants.md`](docs/security-invariants.md) first. Most of those
rules exist because the natural way to write the code violates them.

---

## License

AGPL-3.0-or-later. Hexora is an independent implementation and contains no proprietary
code, assets or trademarks from other security products.
