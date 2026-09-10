# Roadmap

**Target: feature parity with Burp Suite Professional and Caido, on Windows and Linux.**

Web and API testing only. Network/infrastructure testing is deliberately out of scope
until web parity is reached — see [Deferred scope](#deferred-scope).

Status labels: **DONE** · **IN PROGRESS** · **PLANNED**

Nothing is described in the present tense before it works. A feature claimed here that
does not exist is a bug in this file.

Parity detail per feature: [`feature-parity.md`](feature-parity.md).

---

## Sequencing principle

The order below is deliberately **not** Burp's feature list sorted by prominence. Two
observations drive it:

1. **Caido has no active scanner and is still winning users from Burp.** A great
   manual toolkit is what earns adoption; the scanner is what earns enterprise
   renewals. Manual and automation come first.
2. **The scanner is the least differentiating thing we could build early.** Its value
   comes from years of accumulated checks. Our differentiators — evidence-gated
   findings, authorization testing, workflows — are cheaper to build and harder to
   copy.

So: **usable proxy → manual toolkit → automation → scanner → extensibility.**

A secondary rule: each milestone must leave Hexora *more usable than before*. No
milestone exists purely as scaffolding for a later one.

---

## Phase 0 — Foundation · DONE

**M0 — Architecture foundation** · DONE

Domain model, storage (SQLite metadata + content-addressed blob store), migrations,
scope enforcement at the transport boundary, extension permission model, AI tool gate,
CLI shell, Tauri shell, CI, threat model, security invariants.

157 tests passing. See [`architecture.md`](architecture.md).

---

## Phase 1 — A usable proxy

The goal of this phase is a tool a pentester would actually open.

**M1 — HTTP engine** · IN PROGRESS

Split into small steps, because a single "HTTP engine" milestone is undebuggable:

| | Scope | Status |
| --- | --- | --- |
| M1.1 | HTTP/1.1 over TCP: request writer, response head parser, `Content-Length` bodies, real `HttpTransport` | **DONE** |
| M1.2 | TLS via rustls — SNI, ALPN, verification, client certificates | **DONE** |
| M1.3 | Streaming bodies with **incremental** limit enforcement | **DONE** |
| M1.4 | Connection pooling, keep-alive, per-host caps | PLANNED · **next** |
| M1.5 | Chunked decoding, gzip/deflate/brotli, decompression-bomb protection | **DONE** (taken early — most real sites are chunked) |
| M1.6 | Redirects — opt-in, **scope-checked at every hop** | PLANNED |
| M1.7 | Hostile-server test suite, `cargo-fuzz` targets for the parser | PLANNED |
| M1.8 | Benchmarks and hardening | PLANNED |

### What M1.1 delivered

`hexora send <url>` issues a real request over a real socket and prints the exchange.
The engine lives in `core/http`:

- A **wire-preserving parser** that is permissive but loud. It accepts input a strict
  parser would reject — bare LF terminators, whitespace before the colon, obsolete line
  folding, duplicate `Content-Length` — and records each as a `Quirk` rather than
  silently normalizing it. Five of those quirks are flagged as request-smuggling
  signals. This is the reason the parser is hand-written rather than `httparse`: a good
  client parser hides exactly what a security tool needs to see.
- Framing per RFC 9112 §6.3, including the cases that matter — `HEAD`, 1xx, 204 and 304
  carry no body whatever the headers claim, and `Transfer-Encoding` beats
  `Content-Length` while being reported as the CL.TE primitive it is.
- Refusal where there is no defensible answer: two *different* `Content-Length` values
  produce an error rather than a guess, because guessing corrupts every measurement
  built on the body.
- Per-phase timeouts, so a tester can tell an unreachable host from one that accepted
  the connection and went silent.
- Limits enforced **while bytes arrive**. A server that never sends a blank line is cut
  off at the header cap rather than after exhausting memory.

Bodies delimited by `Content-Length` or connection close. Chunked responses and HTTPS
return `NotImplemented` naming the milestone that will handle them, rather than
returning a wrong body.

**M2 — Proxy** · IN PROGRESS

| | Scope | Status |
| --- | --- | --- |
| M2.1 | Interception certificate authority | **DONE** |
| M2.2 | Plain HTTP proxy, absolute-form requests | **DONE** |
| M2.3 | `CONNECT` tunnelling and TLS interception | **DONE** |
| M2.4 | Intercept / forward / drop / modify hooks | **DONE** |
| M2.5 | Trust installation and first-run experience | **DONE** (Windows verified; macOS and Linux written but unrun) |

HTTP proxy, `CONNECT` tunnelling, per-install interception CA with generated leaf
certificates, intercept/forward/drop/modify, certificate export and browser trust
instructions for Windows and Linux, and one-command setup that installs the CA into
the user trust store and verifies it by asking the platform.

The CA is the security-critical part: per-installation, never shipped, easy to
regenerate and remove. See [`threat-model.md`](threat-model.md).

**M3 — Traffic history** · DONE

`TrafficStore` over SQLite and the content-addressed blob store, the proxy capture
pipeline, and paginated history browsing from the CLI. Both the wire and decoded forms
of every body are kept, along with framing quirks and TLS details.

Still open here: filtering beyond pagination, blob garbage collection, and threading
the encoded bytes out of the transport so `encoded_body` is populated rather than NULL.

**M4 — Repeater** · DONE

Load from history, raw editing through `$EDITOR`, resend, response comparison, and
**request branching** — variants retain their parent relationship, which neither
competitor offers. `requests.parent_id` has carried this since M0.

Nothing is auto-corrected: a `Content-Length` that disagrees with the body is reported
and sent as written, because correcting it is how a tool turns a smuggling test into a
test of itself.

Still open here: collections, and byte-exact raw sending for requests whose line
endings are deliberately non-conforming.

> **At M4 Hexora is a usable tool rather than a foundation.** Everything after this is
> making it a *better* tool than the alternatives.

**M5 — Desktop UI** · DONE

The Tauri window over the same crates the CLI drives: project management, certificate
authority and trust, proxy control, live traffic, exchange inspection, and the
repeater with response comparison.

State lives in Rust rather than in React, so the window and the CLI cannot disagree
about what a project contains. The visual result has not been reviewed on any
platform — see STATUS.md.

**M5.1 — Protocol and target breadth** · PLANNED

HTTP/2 (proxying, not just client), invisible proxying, upstream proxy chaining, mTLS,
site map / target tree.

HTTP/2 is table stakes for modern targets and is the single hardest item in this phase.

---

## Phase 2 — Manual toolkit parity

**M6 — Intruder / Fuzzer** · PLANNED

All four Burp attack types (Sniper, Battering Ram, Pitchfork, Cluster Bomb), payload
processing pipeline, concurrency and rate limiting, matchers and filters (status,
length, regex, JSONPath, similarity, timing), pause/resume, split result view.

No artificial throttling. Burp Community's throttled Intruder is a major reason people
look for alternatives.

**M7 — Editing and rules** · PLANNED

Match & Replace (parameter- and header-aware, following Caido's redesign rather than
Burp's regex-only model), Decoder, WebSocket interception and replay, request pipelines
for race-condition testing.

**M8 — Traffic query language** · PLANNED

A query language over captured traffic, in the spirit of HTTPQL. Burp's Bambdas require
writing Java lambdas; that is a worse answer for the same problem.

**M9 — Session handling** · PLANNED

Session handling rules, macros, cookie jars, auto-reauthentication, Sequencer.

Session handling is the single most painful thing to configure in Burp. Doing it well is
a genuine adoption lever.

---

## Phase 3 — Automation and the differentiators

**M10 — Workflow engine** · PLANNED

Node-based visual workflows, JS nodes, extractors, string interpolation, JSON/YAML
export.

**M11 — Headless and client/server** · PLANNED

Full CLI parity with the desktop client on the same engine, plus a server mode that can
run on a VPS with a thin local client — Caido's architecture, and better than Burp's
desktop-only model. CI/CD integration.

**M12 — Authorization testing and attack chains** · PARTIAL (M12.1–M12.5 IMPLEMENTED)

**This is the flagship feature.** Neither competitor does it properly, and it automates
the highest-value manual work in most engagements.

Done (M12.1–M12.5), in `core/authz`, `core/storage`, `core/report`, the `authz` /
`findings` / `report` / `object` commands and the desktop window:

- Multiple identities, persisted in the project with their privilege ordering and the
  object identifiers they own (`core/storage/src/identities.rs`).
- The same request replayed as each of them, recorded as the identity that sent it.
- Structural response comparison: JSON key shape with array indices collapsed, or a
  token set with volatile runs masked — not a byte comparison.
- An unauthenticated control, so a public resource produces one finding rather than one
  per identity.
- Evidence-gated candidate findings: Tentative on similarity, Firm on a declared
  identifier appearing where it should not, Confirmed only after `--verify` reproduces
  it.
- Project scope persisted and enforced, since a matrix is automated traffic.
- Findings written into the project with their evidence, refused by storage if they
  fail their own validation, keyed on what they claim so a re-run updates rather than
  duplicates — keeping triage decisions and letting confidence fall when the evidence
  no longer supports it.
- `hexora findings`: list worst-first, show one in full, triage, filter to what is
  actually actionable.
- Reports (`core/report`, `hexora report`): Markdown, self-contained HTML and JSON off
  one model. Every claim quotes the request and response behind it; a citation the
  project cannot resolve is printed as missing rather than as a dead id. Scope,
  identities and coverage sit above the findings so a clean run reads as a record of
  what was tested, not as a clean bill of health. Leads stay in their own section,
  triaged-away findings are counted rather than hidden, and credentials are redacted
  with the length of what was removed.
- A desktop workflow (M12.4): scope and identities in Setup, the matrix run from a
  captured request, the findings list with every claim's evidence one click from the
  exchange it rests on, and the report previewed before it is written. Twelve IPC
  commands, contract version 3, and an identity view with no field that could carry a
  credential.

- Constructed cross-identity attempts (M12.5): object identifiers and their owners
  are declared by a human (`hexora object add`), and a run substitutes one into the
  object slot of a captured request and sends it as each identity. A control send per
  identity is what makes "the response looks like the object document" mean anything;
  a 200 with nothing identifiable in it is a lead, not a finding. Every generated
  request records the substitution that produced it — security invariant 9.

Not done:

- **Suggesting which values are object identifiers.** Today every one is declared by
  hand. A suggestion system would help, and it has to stay a suggestion: the moment a
  guess about what a string means becomes an assumption, the evidence model is gone.
- **Attack chains** that retain evidence at every step.

---

## Phase 4 — Scanning

**M13 — Crawler and passive scanner** · PLANNED
**M14 — Active scanner and verification engine** · PLANNED
**M15 — Custom scan checks** · PLANNED (a check DSL, in the spirit of BChecks)
**M16 — OAST** · PLANNED — self-hostable, DNS/HTTP/HTTPS/SMTP, correlated to the
originating request. Self-hosting is a selling point over Burp Collaborator.

---

## Phase 5 — Extensibility

**M17 — TypeScript extension SDK** · PLANNED
**M18 — Browser integration** · PLANNED — drive the user's installed Chrome over CDP
rather than shipping Chromium; DOM XSS testing.
**M19 — Extension runtime, sandboxing (WASM) and store** · PLANNED

---

## Phase 6 — Later

**M20 — Burp Montoya compatibility** · PLANNED — separate subproject, out-of-process
JVM, independently versioned, public compatibility matrix. Deliberately last among
extension work.

**M21 — AI subsystem** · PLANNED — after the scanner and verification engine, never
before. An AI layer over an unreliable core produces confident nonsense. The tool gate
and evidence model already exist so that when it arrives it is constrained by
construction.

**M22 — Team collaboration** · PLANNED — shared projects, PostgreSQL backend, RBAC,
audit.

---

## Platform support

| Platform | Status | Notes |
| -------- | ------ | ----- |
| Windows | **Primary** | Requires MSVC build tools; see [`development.md`](development.md) for the Git Bash linker trap |
| Linux | **Primary** | Tauri needs WebKitGTK; ship AppImage + `.deb` |
| macOS | Best-effort | Code stays portable and CI builds it, but notarization and signing are not set up. Promote to primary when there is an Apple Developer account |

Cross-platform items that need real work, none of them glamorous:

- **CA trust installation** differs per OS — Windows certificate store versus Linux NSS
  databases. This is fiddly and is a first-run experience problem, so it belongs in M2
  rather than being left until packaging.
- **Antivirus false positives.** An intercepting proxy with its own CA looks exactly
  like malware to a heuristic scanner. Budget time for vendor allowlisting.
- **Code signing.** Windows SmartScreen will flag unsigned builds. Unsigned security
  tools do not get adopted.

---

## Deferred scope

Recorded so it is not silently forgotten, and not silently started.

**Network and infrastructure testing.** Revisit only after Phase 3. If it happens, the
decisions already taken are: assessment only (no exploitation), orchestrate proven
tools rather than writing a scanner, and a separate privileged helper process so the UI
never runs elevated. `Scope` would need a network dimension — CIDR ranges, port ranges,
protocols — before any of it, because invariant 1 is meaningless to a port scanner
otherwise.

**Not building at all:** exploitation frameworks, C2, payload generation, our own CVE
database, a bundled Chromium, a bundled Nmap (its licence forbids it — see
[`feature-parity.md`](feature-parity.md)).

---

## Honest sizing

Burp is roughly twenty years of work by a substantial team. Caido has been in
development for years and still lacks an active scanner. This roadmap is not a
quarterly plan.

What is realistic:

- **Phase 1 (M1–M5)** gets a genuinely usable interception proxy and repeater. This is
  the milestone that matters most; everything else is incremental from a working tool.
- **Phase 2** is what makes people consider switching.
- **Phase 3** is what makes them switch.
- **Phase 4 onwards** is a multi-year arc, and the scanner in particular is never
  "finished" — its value accrues with every check added.

The plan is deliberately ordered so that stopping after any phase still leaves
something worth using.
