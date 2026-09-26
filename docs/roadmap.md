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

## The order, frozen at M12.6

Everything below still moves, but the *next several milestones* are fixed, and the
reason is worth stating once because it decides what gets built and what does not:

> **Hexora does not win by having more scanners. It wins by making every automated
> result explainable, reproducible and safe.**

A scanner that finds one more bug class than a competitor is a feature. A scanner whose
every claim can be re-run by the person reading the report is a different product. The
evidence model, the findings store, the report and the constructed-attempt machinery
built through M12 exist to make the second one possible, and the scanner is built on
top of them rather than beside them.

```text
M12.7  Identifier suggestions        candidates a human confirms, never assertions  ✔
M12.8  Engagement snapshots          what changed since the last assessment  ✔
M13.1  Verification framework        detector ≠ finding, enforced by the type system  ✔
M13.2  Passive scanner               observations over captured traffic, no new requests  ✔
M13.3  Active scheduler              asks before it sends, and one host at a time  ✔
M13.4  Reflected-input verification  context-aware, not "the string came back"  ✔
M13.5  Redirect verification         a controlled destination, never blindly followed  ✔
M13.6  Auth/session verification     the identity model, applied differentially  ✔
M13.7  IDOR/BOLA automation          M12.5 as a scanner primitive  ✔
M14.1  The intruder                  one request, many values, grouped by behaviour  ✔
M14.2  Attached headers              what a programme requires on every request  ✔
M14.3  Programme profile             which finding classes the programme accepts  ✔
```

Then, in this order and keeping their existing numbers: the extension platform (M17,
M19), Burp compatibility (M20), and the other protocols (M5.1 — HTTP/2, WebSockets,
HTTP/3). The numbers are not renumbered to match the order, because `CHANGELOG.md`,
`STATUS.md` and several `NotImplemented` messages in the code name milestones by
number, and silently reusing one would make a year of history ambiguous.

**Not before the above, however tempting:** HTTP/2 or HTTP/3 fuzzing, WebSocket
fuzzing, large payload generators, autonomous AI exploitation, hundreds of
vulnerability signatures, or Burp extension compatibility. Each of them multiplies the
surface area that has to be trustworthy before any of it is.

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

Invisible proxying, upstream proxy chaining, mTLS and a site map / target tree live here
alongside HTTP/2. HTTP/2 is table stakes for modern targets and is the single hardest
item in this phase, so it is broken out below.

### HTTP/2

The seams are already in place: `HttpVersion::Http2` and `HttpVersion::is_text_framed`
exist, ALPN is configurable on both the client and the interception seam, the
`HttpTransport` trait is per-request (one request maps to one h2 stream), and
`intercept.rs` *asserts* that `h2` must not be advertised until the engine can parse it —
so turning it on is a deliberate act, not an accident.

**The tension that shapes the whole design.** Hexora's identity is wire preservation:
send deliberately-malformed messages, keep casing, duplicates and bad framing exactly as
written. HTTP/2 fights this — it is binary, HPACK-compressed, lowercases every header
name, and a *conforming* library will not let a caller emit a protocol violation. But
protocol violations are the point of a security tool (HPACK bombs, CONTINUATION floods,
pseudo-header abuse, h2→h1 downgrade smuggling). So h2 needs **two paths**: a conforming
one (wrapping the `h2` crate — MIT, mature, already tokio + rustls compatible) to reach
h2-only targets at all, and a **frame-level** one (a thin custom codec) for the
adversarial sends. The milestones stage the conforming path first, because it unblocks
real targets quickly, and defer the frame codec, which is the deepest and depends on
everything else being solid — the same "HTTP/2 fuzzing not before parity" rule this
roadmap already states.

| Step | What it gives us | Depends on |
| ---- | ---------------- | ---------- |
| **M5.1a** — h2 client transport, conforming | ALPN negotiates `h2`; `HttpTransport::send` speaks HTTP/2 to an origin via the `h2` crate; one request → one stream → one `Exchange`. h2 facts recorded (negotiated protocol, stream id, pseudo-headers). Header-casing preservation is **explicitly dropped for h2 and that fact recorded** — a protocol truth, and a server that treats casing as significant is itself a finding. `send_raw` stays `NotImplemented` for h2. The repeater, authorization matrix and scanner reach h2-only endpoints for free, because they go through the trait the scope guard wraps. | existing TLS/ALPN |
| **M5.1b** — client connection management & multiplexing | Per-host h2 connection, concurrent streams, flow control, SETTINGS / GOAWAY, and **limits enforced per-stream and per-connection** — the HPACK / CONTINUATION analogue of the decompression-bomb guard, refused while arriving rather than after. | M5.1a; dovetails with M1.4 (pooling) |
| **M5.1c** — proxy accepts h2 from the browser | Remove the "do not advertise h2" guard; interception offers `h2`; the proxy becomes an **h2 server to the browser**, demultiplexes concurrent streams to exchanges, and forwards each over the origin's negotiated protocol. The capture and storage model is made concurrency-safe with stream association. **This is the table-stakes deliverable — "HTTP/2 proxy" as the market means it.** | M5.1b |
| **M5.1d** — faithful h2↔h1 translation & the downgrade surface | When an origin speaks only h1, translate — and **record the translation as an explicit, testable event**. h2→h1 downgrade is a real request-smuggling class, treated as a bug-finding surface rather than plumbing to hide. | M5.1c |
| **M5.1e** — frame-level h2 (`send_raw` + repeater editor) | A low-level frame codec for **non-conforming** h2: HPACK edge cases, pseudo-header ordering, CONTINUATION, stream-state abuse. The security differentiator, and the reason not to wrap the `h2` crate and stop. The repeater gains an h2 view. Last, because it is deepest and rests on a–c being solid. | M5.1c |
| **M5.1f** — storage / report / UI polish, hostile-peer suite, fuzz | `--wire` returns the reconstruction with its caveat, history carries stream association, reports name the h2 facts, and `cargo-fuzz` targets cover the frame codec and the HPACK decoder (mirroring M1.7 for HTTP/1.x). Hardening pass. | M5.1a–e |

**Sequencing.** a→b→c is the shortest path to the headline "HTTP/2 proxy" line, and
M5.1a is already useful on its own — it reaches h2-only APIs that are otherwise
unreachable. d–f make it trustworthy and adversarial. Rough effort: a and b are medium
each, **c is the largest single piece** (a dual-role proxy plus capture concurrency), d
and e are medium-large, f is medium.

**Risks to lock first.** The `h2`-crate-vs-hand-roll decision (recommended: the crate for
conforming, hand-roll only the M5.1e frame codec); capture concurrency, which the current
roughly-sequential observer assumes away and which M5.1c must address head-on rather than
patch later; and surfacing the casing/preservation caveat in the UI and reports at M5.1a,
so h2 never silently breaks the tool's core promise.

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
Burp's regex-only model), WebSocket interception and replay, and request pipelines for
race-condition testing.

The **Decoder** was taken early and ships now: a local transform bench (base64, URL, HTML
entities, hex, JWT claims decode) in the desktop window, chainable and sending nothing —
built in rather than left to an online decoder, because the values a tester decodes are
live session tokens.

### WebSocket

Some scaffolding is already in place: `WsMessageId` exists, and the `websocket_messages`
table has stood in the schema since the first migration — a frame is a row anchored to the
Upgrade request, with a direction, an opcode and a payload kept inline or in the blob store
like a body. Two things must change to fill it: the proxy currently *strips* `Upgrade` (it
is in the hop-by-hop set) and closes a tunnel after one exchange, and traffic stops being
request→response the moment a `101 Switching Protocols` turns the connection into a
long-lived, bidirectional stream of frames.

**The tension is the one HTTP/2 had.** A conforming WebSocket library normalises and
validates; a security tool must send the frame a conforming stack refuses — bad masking, a
reserved bit set, an invalid opcode, a length that lies, a fragmented control frame, a ping
flood. So two paths again: a **conforming relay** for capture and interception, and a
**hand-rolled frame codec** for the adversarial half. RFC 6455 framing is far simpler than
HPACK, so hand-rolling is tractable — and fuzzing that parser on hostile masking and length
bytes is essential, exactly like the HPACK fuzz that caught a panic in M5.1f.

| Step | What it gives us | Depends on |
| ---- | ---------------- | ---------- |
| **WS.a** — pass the upgrade through, capture the session | The proxy detects `Upgrade: websocket`, stops stripping it, completes the `101` to both sides, then relays the bidirectional stream while parsing frames into `websocket_messages` — direction, opcode, payload, and the **observed** masking, because an unmasked client frame or a masked server frame is itself a finding. The Upgrade request and response are captured as an ordinary exchange. This is the headline "WebSocket interception". | proxy tunnel (M2.3), the existing WS table |
| **WS.b** — the message timeline | History lists WebSocket sessions; opening one shows an ordered, both-directions timeline, and `hexora ws` does the same from the CLI. The storage read side for frames, the write side having landed in WS.a. | WS.a |
| **WS.c** — intercept and edit in flight | Per-message forward / replace / drop, in either direction — the WebSocket analogue of the HTTP interceptor hooks, on the same seam. This is "intercept" in the sense of modifying live traffic. | WS.a |
| **WS.d** — compose and send into a live session | Hold the session open and inject a composed or replayed message on demand, through the scope guard and captured like any frame — the WebSocket analogue of the repeater. | WS.a |
| **WS.e** — frame-level / adversarial WebSocket | A hand-rolled codec that emits exactly what the tester wrote: bad masking, RSV bits, invalid opcodes, a lying length, a fragmented control frame. Plus `permessage-deflate` (RFC 7692) — decompressed to be intelligible, both forms kept, bounded against a decompression bomb. The WebSocket analogue of raw h1 and frame-level h2. | WS.d |
| **WS.f** — hardening, WS-over-h2, polish | `cargo-fuzz` and proptest over the frame parser (masking, length, fragmentation on hostile bytes — the panic surface), close-code recording, WebSocket sessions in reports, and RFC 8441 WebSocket-over-HTTP/2 (Extended CONNECT) if in scope or explicitly deferred. | WS.a–e |

**Decisions to lock first.** In WS.a, strip `permessage-deflate` from the client's handshake
offer so every frame is uncompressed and readable — a documented, pragmatic first move —
and defer real deflate to WS.e; otherwise capture shows compressed noise. The proxy's
one-request-then-shutdown tunnel must switch to a frame relay after the `101` and hold the
connection, with the M5.1c h2 stream loop the nearest precedent; both directions relay
concurrently, and the capture write path is already concurrency-safe. And masking is
recorded as evidence rather than silently normalised, the same discipline as the h2 casing
caveat.

**Sequencing.** a→b makes WebSocket traffic observable; c adds live modification; d→e are
the manual-testing power; f hardens. **WS.a is the largest single piece** — the proxy
connection-model change plus the frame parser and capture — with the rest medium to
medium-large, mirroring the HTTP/2 cadence.

**RFC 8441 (WebSocket over HTTP/2, Extended CONNECT) is deferred**, not built in WS.f. It is
rare in the wild, it interacts with the h2 stream machinery rather than the h1 tunnel every
other WS step uses, and no target seen so far needs it; the frame codec and capture model
built here carry straight over when a target does.

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

**M12 — Authorization testing and attack chains** · PARTIAL (M12.1–M12.6 IMPLEMENTED)

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

M12.6 closed the two pieces of wire-level debt that a scanner would otherwise be built
on top of: response bodies are kept in both their transfer-decoded and content-decoded
forms, and requests can be sent byte for byte through
`RequestSource::{Structured, Raw}` rather than always being serialized from the message
model. Raw mode is HTTP/1.x requests only; HTTP/2 and HTTP/3 want wire models of their
own.

**M12.7 — Identifier suggestions** · DONE

Every object identifier is declared by hand today, so constructed testing is exactly as
broad as what somebody typed. Hexora can do better than that without pretending to know
more than it does: it can *point at* the values in captured traffic that look like
identifiers, and let a human say yes.

```text
/api/accounts/1000/invoices/20001      ?user_id=1000      {"accountId":1000}
                  │                          │                     │
                  └──────────────┬───────────┴─────────────────────┘
                                 ▼
                    "1000 appears in 17 requests, in three
                     places. Possible object identifier."
                                 │
                          [Confirm] [Ignore]
                                 │
                                 ▼
                        ObjectDeclaration (M12.5)
```

The rule that makes this safe is the same one that made M12.5 defensible: **a candidate
never becomes an ownership assertion on its own.** A suggestion carries where the value
was seen and how often; ownership is still something a person asserts, because the tool
cannot know whose account `1000` is and a guess dressed as a fact would poison every
finding downstream. Nothing is sent as a result of a suggestion.

Built as described, with three decisions worth recording:

- **Suggestions persist.** An engagement is captured on Monday and worked on Friday.
  Re-analysis refreshes a proposed candidate and leaves a decided one alone.
- **The score is explainable.** Each candidate carries the signed signals behind it
  rather than a bare confidence, so a tester can answer "why did Hexora suggest this?"
  — and, when it is wrong, see *which* reason was wrong.
- **`IdentifierCandidate` has no owner field**, and neither does its table. Security
  invariant 10 records this, with the tests that hold it.

**M12.10 — Structural differential analysis** · DONE

M12.1 could say two responses were 97% alike. This says *which field* — the difference
between a number a developer can dispute and a line they can go and look at.

```text
before:  User B received a response 97% alike the one served to User A
after:   $.email — `alice@example.com` for User A, absent for User B
```

Four layers, and the third is the one that matters:

1. **Representation.** Bodies are flattened to one node per JSON path, containers
   included, so `{}` and `{"a":null}` agree at the root and differ at `$.a`.
2. **Deterministic paths, with the indices kept.** `$.items[3].price`, not
   `$.items[].price` — a tester told an invoice differs wants to know which one. The
   cost is honest: an array whose order changed shows as many differences, because as
   far as the comparison can tell, it did change.
3. **Classification.** `Appeared`, `Disappeared`, `Changed`, `TypeChanged`. A number
   becoming a string is a change of *shape*, kept apart from a value moving.
4. **An explicit normalization policy.** Not automatic scrubbing of anything that
   *looks* dynamic — that would recreate the exact problem Hexora exists not to have.
   A field set aside is still listed with both values and the reason, the policy
   prints itself into the report, and `Policy::strict()` sets nothing aside at all.
   `id`, `uuid` and `key` are never in the dynamic list, with a test saying so.

Credential-named fields report that they differed and withhold what they were.
Duplicate JSON keys are flagged rather than collapsed by the parser in silence.

It also gives the authorization engine a second route to a firm claim: two identities
served *the same document*, with an unauthenticated request refused it, no longer
needs a hand-declared object id. The anonymous control is the gate, and `NotTried`
does not clear it.

Deliberately not built: JSON Schema validation. Nothing here knows what an application
*should* return; it compares two documents that were actually served. A schema layer
can arrive when a check needs one.

**M12.9 — Proof-of-concept compilation** · DONE

The last mile. A finding already knows the exchanges behind it; this turns them into
something a triager can run.

```text
Finding evidence          →  Steps
Evidence::Comparison         1. the control request, as User A
  baseline, variant          2. the same request, as User B
  difference                    Expect: User B received acct-1000
```

Built from stored evidence and nothing else: a step that cites an exchange the project
has lost says so rather than inventing a request. Credentials become placeholders
named after the identity, the same one in every step, so a reader supplies two values
and runs the whole thing — and can see that the two steps were sent as different
people, which is the finding.

`curl` where curl can express the request, and a stated reason where it cannot. A
command that quietly recomputed a deliberately wrong `Content-Length` would undo
`RequestSource::Raw` at the last step.

Reproductions reach the report for established findings only. A runnable block on an
unverified claim is the thing most likely to be forwarded without the sentence that
qualified it.

Deliberately not built: a reproduction that *runs itself*. Hexora can already re-run a
request — that is the repeater — and a button that replays an exploit against a client
system on a reader's behalf is a different feature with a different threat model.

**M12.8 — Engagement snapshots** · DONE

An engagement is not one moment. A consultant tests, the client fixes, the consultant
re-tests — and the question that matters on the second visit is *what changed*.

```text
snapshot = scope + identities + configuration + traffic + declared objects
         + findings + detector versions + when
```

With two of those, Hexora can answer "this finding existed in the previous assessment
and is now fixed", "this one is new", and "this one is unchanged". The findings store
already keys a claim on what it claims and keeps triage across re-runs, which is half
of it; the other half is being able to say which run a claim belonged to.

Detector versions are in the list deliberately. A finding that disappeared because the
application was fixed and one that disappeared because a check was changed are not the
same event, and a regression report that cannot tell them apart is worse than none.

Built as described, with four decisions worth recording:

- **A snapshot copies rather than references.** The findings store updates a claim in
  place on a re-run, so a snapshot that pointed at rows would rewrite its own past.
- **It never says *fixed*.** Every disappearance carries a reason, and only one of the
  three is about the application at all. Security invariant 11.
- **A claim nobody re-tested is reported as such.** Found by running an actual retest:
  the application was repaired, the matrix re-ran and raised nothing, and the old claim
  sat there looking like a current result — because a run that produces no claim never
  writes to the claim it did not produce.
- **Detector versions are the tool version, honestly labelled.** Hexora has no registry
  of which checks ran until M13.1, so "ran and found nothing" and "never ran" are
  reported as one inconclusive answer rather than guessed apart.

---

## Phase 4 — Scanning

The scanner is the thing buyers compare on and the thing most likely to waste a
tester's day. It is built as a verification framework with detectors plugged into it,
not as a pile of checks, and the ordering below is the frozen one.

**M13.1 — Verification framework** · DONE

The universal shape, before a single detector exists:

```text
request → preconditions → test generator → candidate → send → observation
        → differential comparison → hypothesis → verification → finding
```

Two traits and one rule. A `Detector` says *"this looks suspicious"* and produces a
[`Hypothesis`](../core/types/src/finding.rs). A `Verifier` performs a controlled
experiment and says whether the behaviour reproduces. **Only a verifier's output may
reach the findings store**, which is security invariant 6 made structural: the type a
detector produces cannot be persisted as a finding, so a noisy check cannot become a
noisy report by taking a shortcut.

Every generated request goes through the same `ScopeGuard` as everything else. That is
an architectural invariant, not a scanner setting.

Built as described, with four decisions worth recording:

- **The rule is the signature.** `FindingStore` takes a `Verified`, which only a
  `Verification` produces. A detector that tries to store a hypothesis does not get an
  error; it does not compile.
- **Confidence is derived, not chosen.** A fifth rung, `Observed`, was added for
  passive checks — a missing header is a fact with no experiment to run, and its
  honest ceiling is a lead.
- **A verifier gets a `Lab`, not a transport.** One method: send this as this
  principal. Scope, attribution and storage are the lab's business, so a check cannot
  forget any of them.
- **M12.1 and M12.5 were rewritten onto it in the same change**, so the framework has
  a real user rather than a hypothetical one, and the live behaviour is unchanged.

Deliberately not built: the object-safe registry and the scheduler. `Detector` and
`Verifier` carry associated types, which is honest about today — nothing yet
dispatches over a heterogeneous set — and the queue belongs to M13.3, where the
requirements are real.

**M13.2 — Passive scanner** · DONE

Observations over traffic that has already been captured. No new requests, which makes
it safe to run on any engagement and easy to benchmark.

| Detector | Risk | Value |
| --- | --- | --- |
| Missing security headers | Low | High |
| Cookie security attributes | Low | High |
| CORS configuration | Low/Medium | High |
| Information-disclosure headers | Low | High |
| TLS configuration observations | Low | High |
| Cache-control problems | Low/Medium | High |
| Mixed content | Low | Medium |
| Sensitive data in responses | Medium | High |
| Authentication and session observations | Medium | High |
| Technology fingerprinting | Low | Medium |

**Most of these are observations, not vulnerabilities, and are labelled as such.**
`Server: nginx/1.24.0` is a fact about the response; whether it matters depends on the
engagement. A scanner that files it as a finding teaches people to ignore the findings
list, which is the only thing a findings list must never become.

Built with six checks, covering six of the ten rows above:

```text
headers.security      security headers, applicability decided per header
cookies.security      Set-Cookie attributes, in the context of the cookie
cors.configuration    who may read responses, and with whose credentials
disclosure.headers    technology banners — informational, never filed
cache.sensitive       cache directives on authenticated responses
tls.observations      what the recorded handshake showed
```

Four decisions worth recording:

- **The pass takes no transport.** `scan(&Project, &Selection)` has nowhere to put
  one, so "passive" is a property of the signature. Security invariant 12.
- **Three products, one of which is a finding.** Informational observations are listed
  and never filed; reportable ones become leads; hypotheses stop until an experiment
  settles them. The result is deliberately boring: many observations, few hypotheses,
  fewer findings.
- **A check does not choose its own verification.** The pass applies
  `Verification::Observed` to every observation, so no passive check can promote
  itself above a lead.
- **Response bodies are not loaded.** No check here needs one; it keeps a large
  engagement out of RAM and keeps the check most likely to quote somebody's data out
  of the build.

The four rows not covered — mixed content, sensitive data in responses,
authentication/session observations, technology fingerprinting beyond banners — are
either body-reading (deliberately deferred with the accessor) or need an experiment.

**M13.3 — Active test scheduler** · DONE

One queue per host, a request ceiling, and every request through the guard. The
scheduler is what makes active testing safe to point at a production system, so it
landed before the detectors that use it.

```text
Plan::prepare(...)  →  Plan     synchronous; there is no await to send through
run(plan, ...)      →  Outcome  the only function in Hexora that sends
```

`--dry-run` is the first without the second. Not a flag on a sending path — a flag can
stop being honoured by an edit nobody reviewed carefully.

**One host is never sent two requests at once.** Each host has a sequential queue with
a pause between its requests; only different hosts run concurrently. A global
concurrency limit was the obvious design and the wrong promise: eight requests over
eight hosts is polite, eight at one host is a small denial of service, and what a
client cares about is what their server sees.

**A run that stopped early says so, before its results.** Invariant 15. A truncated
queue reported as a finished one turns "unfinished" into "clean", which is the worst
thing a scanner can say.

The first check is `cors.reflection`, chosen because it closes a loop M13.2 left open
on purpose: an `Origin` that cannot be on anybody's allowlist separates a reflecting
server from an allowlisted one, and that request is exactly what a passive pass will
not make. A refutation is a first-class result here — "this host does not reflect
arbitrary origins" is what stops a suspicion following a tester around.

Building it found two defects nothing else would have. Scanner traffic was attributed
to `Origin::Repeater`, which the scope guard treats as human-initiated, so an
out-of-scope host would have been flagged rather than refused. And the passive pass
deduplicated hypotheses per host, so an application with a vulnerable endpoint beside
a safe one had only one of them tested — whichever came first.

Deliberately not built: retries, a resumable queue, and any form of scheduled or
background running. A queue nobody is watching is how a tool ends up sending traffic
after everyone has gone home.

**M13.4 — Reflected-input verification** · DONE

A marker goes in, and the *context* it comes back in decides what it means. Reporting
because a string came back is how scanners earn their reputation, so this reports
neither less nor more than what happened:

```text
{"q": "hxa…<>…"}            application/json   data. Ruled out.
<div>hxa…&lt;&gt;…</div>    text/html          escaped. Ruled out.
<div>hxa…<>"'…</div>        text/html          `<` in HTML text. Filed.
```

One value answers both questions — a prefix token, the probe characters, a suffix
token — so the sandwich says where the value landed *and* what survived the trip. Both
tokens are alphanumeric, so nothing encodes them, and they are generated per run so a
page containing a string this build compiled in is never mistaken for a reflection.

The content type is a parameter rather than a guess: the same bytes are inert as
`application/json` and are markup as `text/html`, and the caller has that header.

**It does not say "cross-site scripting."** It says which character came back
unencoded, what it landed inside, and — in the finding itself — that whether this is
exploitable depends on a CSP, a template that may re-encode, and a page somebody has
to look at. A test asserts the title names no vulnerability class.

Deliberately not built: body inputs, which want a body model rather than a byte
offset; path segments, because `hexora identifiers` tells a route from a value with
evidence and guessing here would undo it; and any attempt to render the page to see
what a browser would do, which is a different tool.

**M13.5 — Redirect verification** · DONE

A controlled destination, and the `Location` header inspected rather than followed.

Following it would mean sending a request to a host **the target chose**, which is the
one way an automated tool gets talked into traffic nobody authorized. The scope guard
would refuse it; relying on a backstop instead of not doing the thing is how a
backstop eventually gets a hole in it. Invariant 16.

The destination is a host, not a substring. All of these contain the probe and only
the first three send a browser anywhere:

```text
https://elsewhere/                    taken
//elsewhere/                          taken — invisible to a filter matching `http`
https://app.example.com@elsewhere/    taken — the host is after the `@`
/redirect?to=https://elsewhere        carried, not obeyed
https://app.example.com.elsewhere/    a fourth host, not a subdomain of either
```

A carried value is refuted with the reason, because a tester told three times that a
search parameter is an open redirect stops reading. Backslashes are normalised the way
a browser normalises them, so `/\elsewhere` is protocol-relative rather than a path.

Two forms are tried, and the second is the point: an application that refuses
`https://elsewhere` and accepts `//elsewhere` is reported as a filter that does not
cover a form browsers treat identically — a better finding than one that accepts both,
because it says somebody tried.

Probe destinations are `.invalid` (RFC 2606). They never resolve, and nobody can
register one, so a redirect reported last year cannot be turned into a live one by
somebody buying the domain named in the report.

Deliberately not built: header-driven redirects, which have a different shape and want
their own check; and any attempt to follow a destination to see what is there.

**M13.6 — Authentication enforcement** · DONE

Two failures a cross-identity matrix cannot see, because every identity in one holds a
*valid* credential — an endpoint that accepts any token looks exactly like one that
checks properly.

```text
replayed as captured       →  200   the baseline: this session still works
sent with no credential    →  200   the endpoint needs no session
sent with a broken one     →  200   it has a session and does not check it
```

The third is the sharp one. The probe is the captured token with one character of its
**JWT signature** changed and its header and payload byte-identical, so an application
that accepts it is not verifying signatures — a different sentence from "authentication
is missing".

The baseline is replayed rather than read back. Without it an expired session makes
every probe come back 401 and the run would report *authentication is enforced* having
established nothing: M12.8's lesson, applied one endpoint at a time.

Three outcomes, not two. Same status with *different* content is its own answer and
reaches a report as a lead, because that is what a sign-in page answered 200 looks
like — and also what a partly populated view of the real resource looks like. The
structural comparison names the fields so a reader can tell which.

Credentials are broken without ever being written down (invariant 17), and nothing
that might change data is replayed (invariant 18) — the second enforced by the
scheduler after the reflection check was caught queueing `POST /transfer`.

**Scope.** This milestone's roadmap line named two things. What shipped is the
anonymous and broken-credential half. The multi-identity differential — the same
request as User A, User B and Anonymous — is M12.1, which does it on demand today, and
scheduling it across an engagement is M13.7. Recorded so nobody reads
`auth.enforcement` as covering cross-identity access.

Deliberately not built: session fixation, rotation and expiry, which need a login flow
rather than one captured request.

**M13.7 — Cross-identity access, scheduled** · DONE

M12.1's matrix across an engagement's traffic rather than one request a tester names.

Whose session was captured is the question everything rests on, and proxy traffic does
not answer it — a browser announces no identity id. So each declared credential is
applied to a copy of the request's own headers and compared byte for byte: an exact
answer or none at all. An endpoint whose credential matches nothing declared is reported
as untested with that reason.

One implementation, two front doors. The check calls `hexora_authz::replay_once` and
`analysis::judge`, made public rather than reimplemented — M13.1 built them to take a
`Lab` precisely so this seam could open. A scheduled run that classified responses
differently from `hexora authz` would be two sets of verdicts for one question.

Against the IDOR demo it reached **Firm with no declared object identifiers**, through
M12.10's same-document path behind a refused anonymous control. That is the payoff of
three earlier milestones landing at once: the structural comparison establishes *the
same document*, the anonymous control establishes *not a public page*, and neither
needed a human to declare anything.

Two false positives were removed on the way. `GET /profile` — the textbook
correctly-scoped endpoint — was reported as a violation on every run without
declarations; `every_value_differs()`, which M12.10 built and nothing used, clears it on
evidence. And breaking a credential can land on another valid one, which reads exactly
like a session nobody verified; the project knows what it declared, so that is now
checked rather than risked.

**Scope.** The roadmap named the constructed chain — identifier → ownership →
substitution → constructed request. What shipped is the **replay** half, which needs no
declarations and works on every engagement. Scheduling M12.5's constructed attempts is a
smaller increment now that the replay machinery is schedulable, and is recorded in
STATUS.md as a decision rather than an omission.

Deliberately not built: inferring ownership. Invariant 10 still holds — a suggestion is
not an object and an object is not an ownership claim.

**M13.8 — Crawler and coverage** · IN PROGRESS (CR.a–CR.e DONE; CR.f fuzzing DONE, JS-rendered deferred to M18)

The scanner is only as good as what was captured, and today that is exactly what a tester
proxied — the single largest gap against Burp. A crawler discovers endpoints on its own and
feeds them into the same project the scanner reads, so "clean scan" stops meaning "nobody
looked here".

**A crawler sends traffic — that is the tension.** Everything else in Phase 4 either observes
captured traffic (passive) or sends only what an experiment needs behind a plan you approve
(active). A crawler generates requests nobody typed, so it is not exempt from the discipline
that keeps this a tool a tester trusts: it produces requests through the **active scheduler**
(M13.3) — one host at a time, a request ceiling, a plan shown before anything is sent — and
every request passes the **scope guard**, so an out-of-scope link is recorded as *found*,
never fetched. The tester asks for the crawl by starting a bounded one and seeing its plan;
that is how "nothing is sent that a tester did not ask for" survives a crawler.

| Step | What it gives us | Depends on |
| ---- | ---------------- | ---------- |
| **CR.a** — the link extractor | Reads the URLs a captured response references — anchors, form actions, `script`/`img`/`link` sources, and URL-shaped strings — each resolved against the response's base the way M13.5 resolves a `Location`. Sends nothing; it operates over traffic already captured and *offers* endpoints, the way the identifier analyzer offers identifiers. | passive-scan model, M13.5 resolver |
| **CR.b** — the frontier and the fetch | A bounded, scope-checked crawl: a frontier seeded from captured traffic, fetched through the active scheduler, each response fed back to CR.a to discover more, until the frontier empties or the ceiling is hit. Out-of-scope links are recorded, not followed; depth and count are bounded. | CR.a, M13.3 scheduler |
| **CR.c** — what a crawler must never click | A crawler that follows every link logs itself out, deletes records, fires webhooks. So: **GET-only** auto-follow; a link that looks state-changing or destructive (`logout`, `delete`, `remove`…) is recorded, not followed; a **form is discovered, never auto-submitted** — submitting is a deliberate act, like the intruder; `robots.txt` and `nofollow` are respected by default and the default is overridable, loudly. | CR.b |
<!-- CR.c landed: GET-only auto-follow, forms discovered-never-submitted, destructive-link
avoidance (SkipReason::LooksDestructive), and a full robots.txt parser (RFC 9309) respected
by default and overridable via CrawlPolicy. `rel="nofollow"` is the one piece deferred: it
needs the extractor to associate a link's `rel` with its `href` at the tag level, which the
current attribute-scanning CR.a does not do — it folds into the tag-aware extractor work in
CR.f rather than being half-built here. -->

| **CR.d** — authenticated crawling | Crawl as a declared identity, reusing the session model (M15.1–15.2), so the crawler reaches behind the login; each fetched exchange records which identity saw it, so coverage is attributable and a crawl as User A versus User B is two maps — feeding the cross-identity work. | CR.b, M15 |
<!-- CR.d landed: `Crawler::crawling_as(identity)` authenticates every in-scope request
with the identity's credential (after the programme headers, so the credential wins), and
`hexora crawl --as <identity>` records each fetched page under that identity. The site map
already renders the `as: <identity>` column per path, so a crawl as User A and one as User B
are two attributable maps. Verified end to end: an authenticated crawl's pages show up in
`hexora sitemap` attributed to the identity. -->

| **CR.e** — the site map | The coverage answer, made visible: a host → path tree in the CLI and the window showing what was fetched, what is out of scope, what forms were found but not submitted, and which identity reached each. And the scanner now has more to scan, because the crawl fed the project — the "empty scan" gap closed. | CR.b |
<!-- CR.e landed (CLI): `hexora sitemap <project>` prints the host→path tree with methods,
statuses and the identity that reached each path, lists out-of-scope URLs seen, and with
--forms lists forms discovered-but-never-submitted (reusing CR.a over captured HTML). The
pure builder is `hexora_crawl::SiteMap::build(pages, scope)`, decoupled from storage so the
desktop window can reuse the same function. The window view itself is the remaining half,
deferred to the desktop surface. Note: adding Origin::Crawler required 'crawler' in the
requests.origin CHECK (migration 0001) — caught by the crawl→sitemap end-to-end run. -->

| **CR.f** — hardening and JS-rendered discovery | The HTML/URL extractor fuzzed on hostile bytes (the panic surface, like the HPACK and WebSocket parsers), a per-host budget the scheduler enforces, and the decision on **JS-rendered endpoints**: a static extractor misses SPA routes and XHR that only exist after JavaScript runs, so this **merges with browser integration (M18)** — driving a real browser over CDP, the approach ZAP's Client Spider adopted in 2026 — rather than being built twice. A static crawl reports honestly that a JS app needs the browser. | CR.a–e, M18 |
<!-- CR.f fuzzing landed: `hexora_crawl::fuzz_extract` drives the extractor over arbitrary
bytes (HTML/form/URL-string paths plus the hand-rolled resolver via a hostile base URL);
a proptest in core/crawl/src/lib.rs asserts panic-free + bounded (stressed at 20k cases),
and a `crawl_extract` cargo-fuzz target sits beside hpack_decode/ws_frame/ws_inflate. The
per-host budget is already enforced (CrawlBudget::max_per_host, CR.b). JS-rendered discovery
and rel="nofollow" (needs a tag-aware extractor) are the remainder, deferred to M18's browser
integration rather than hand-rolled here. -->


**Decisions to lock first.** The crawler is a *producer* for the scheduler, not a second sender
beside it, so it never opens its own connections — it enqueues requests the scheduler sends
under scope and the ceiling. Safety beats completeness: a smaller map is better than one that
logged the tester out or deleted a record, so GET-only and never-auto-submit are defaults,
not options a hurried run skips. And the static/JS split is stated, not hidden: a static
crawl says what it could not reach, and the browser-driven crawl (M18) is where a SPA's real
surface is found.

**Sequencing.** a→b is the crawl; c makes it safe to point at a real target; d reaches behind
a login; e is the visible payoff and the gap actually closing; f hardens and hands the JS
case to the browser. **CR.b is the largest piece** (the frontier plus the scheduler
integration); the rest are medium, and CR.f is deliberately not a place to hand-roll a
browser — it defers to M18.

**M15 — Session handling** · IN PROGRESS

```text
M15.1  Session adoption      a person logs in, Hexora notices  ✔
M15.2  Which cookie is you   attribution through a jar that changes  ✔
M15.4  Renewal sequence      a stored sequence with holes where secrets go
M15.3  What a credential says  expiry and subject, read from the token  ✔
M15.4  Runs outlive sessions  refresh before, stop when it dies  ✔
M15.6  In-session detection  replay a known-good request, compare structurally
```

**M15.5 — Custom scan checks** · PLANNED (a check DSL, in the spirit of BChecks)

**M16 — OAST** · PLANNED — self-hostable, DNS/HTTP/HTTPS/SMTP, correlated to the
originating request. Self-hosting is a selling point over Burp Collaborator.

**M14 — The workbench** · IN PROGRESS — what a tester reaches for between the
repeater and the scanner, and what an engagement is conducted under.

```text
M14.1  The intruder            one request, a payload list, responses grouped by behaviour  ✔
M14.2  Attached headers        what a programme requires on every request  ✔
M14.3  Programme profile       which finding classes the programme will accept  ✔
M14.4  Headers on your own traffic  the proxy identifies in-scope browsing  ✔
M14.5  Programmes in the window    the desktop UI knows a class was excluded
```

> **The number was reused, and the original M14 is gone.** M14 first read "Active
> scanner and verification engine", which was built as M13.1 and M13.4–M13.7; this
> file used to say the number would not be reused, and then it was. Recorded here
> rather than quietly corrected: `CHANGELOG.md` and the code name milestones by
> number, so "M14" means the workbench work and nothing else, and a reader of an old
> note deserves to know which of the two they are looking at.

---

## Phase 5 — Extensibility

**M17 — TypeScript extension SDK** · PLANNED
**M18 — Browser integration** · PLANNED — drive the user's installed Chrome over CDP
rather than shipping Chromium; DOM XSS testing.
**M19 — Extension runtime, sandboxing (WASM) and store** · PLANNED

---

## Phase 6 — Later

**M20 — Burp Montoya compatibility** · PLANNED — separate subproject, out-of-process
JVM, independently versioned. Deliberately last among extension work.

**No blanket compatibility claim, ever.** The deliverable is a matrix, published with
the layer and kept honest by a test suite:

```text
Montoya API surface        implemented / partial / unsupported / behaviourally incompatible
Extension compatibility    per extension, with what was actually run
```

Which licenses the sentence *"Hexora supports Burp extensions through a compatibility
layer, with tested compatibility documented per API"* — and not the shorter, more
appealing, unverifiable one. The ground rules are in
[`compatibility/burp-montoya/README.md`](../compatibility/burp-montoya/README.md).

**M21 — AI subsystem** · PLANNED — after the scanner and verification engine, never
before. An AI layer over an unreliable core produces confident nonsense. The tool gate
and evidence model already exist so that when it arrives it is constrained by
construction.

**M22 — Team collaboration** · PLANNED — shared projects, PostgreSQL backend, RBAC,
audit.

---

## Commercialization — the plumbing to sell it

The product is ahead of the business plumbing: there is a great deal to sell and no way to
charge for it. Nothing in the tree does licensing, entitlement or paid-tier gating today.
This track adds that, and the distribution a paid tool needs, without giving up the honesty
the rest of the codebase keeps.

**Two things are decided before any code.** The workspace is **AGPL-3.0**; selling closed
Pro features on top of it is an *open-core* arrangement that needs a **commercial dual
licence** and a **contributor licence agreement** in place before outside contributions
arrive — retrofitting a CLA is far harder than starting with one. And the free/paid split is
a product decision, not an engineering one: the shape below is a proposal, not a commitment.

**An entitlement is a capability grant, and the codebase already has that pattern.**
`core/engine/src/permission.rs` orders capabilities by implication and marks the dangerous
ones; the AI `ToolGate` classifies a call at one boundary. An entitlement gate is the same
shape — features ask "am I entitled to X?" at one chokepoint, the way automated traffic asks
the scope guard — and a denial is **explicit** ("Repeater collections need Pro"), never a
silent failure. Two principles are non-negotiable for *this* tool: licensing is
**offline-first** (pentesters work air-gapped; a launch that phones home is a non-starter),
so entitlements come from an **Ed25519-signed licence file verified against an embedded
public key**, not a server check; and an expired licence **never locks a tester's evidence**
— it degrades to a free read-and-report tier, it does not brick a live engagement.

| Step | What it gives us | Depends on |
| ---- | ---------------- | ---------- |
| **LIC.0** — the split and the licence (decision, not code) | The open-core boundary (which features are commercial), the AGPL + commercial dual licence, and a CLA in place before external contributions. A prerequisite, recorded so it is not skipped. | — |
| **LIC.a** — the entitlement model and gate | An `Entitlements` value (tier, expiry, feature set) read from an Ed25519-signed licence file with an embedded public key — offline, no phone-home. A gate mirroring the capability/scope-guard pattern: one chokepoint, explicit denials, and a missing or expired licence falling back to the free tier rather than failing. | permission.rs precedent |
| **LIC.b** — gating applied, and the free/pro split | The gate wired into real features under a defined split — core interception, repeater and reporting free; the active scanner, intruder at scale, SARIF/CI export and retest snapshots as paid, say — each gated feature naming its tier. `hexora license show|activate` and a desktop licence panel. | LIC.a |
| **LIC.c** — trials, activation, and grace | A time-limited trial, in-app licence entry, an offline activation flow, and expiry handling that is loud before and graceful after — degrading to read-and-report, never locking evidence mid-engagement. | LIC.b |
| **LIC.d** — signed, auto-updating installers | Authenticode-signed Windows installers, macOS notarization and Linux packages through the Tauri bundler; the Tauri updater with signature verification; and a release CI workflow — today CI only builds the CLI. Unsigned security tools do not get adopted (see Platform support). | Tauri bundle config |
| **LIC.e** — supply-chain and release integrity | `cargo-audit` and `cargo-deny` in CI, an SBOM, and signed checksums on release artifacts — the things enterprise procurement asks for. `cargo-audit` is already installed locally; this wires it into the pipeline. | LIC.d |

**The honesty this track must keep.** Client-side licensing deters casual sharing; it does
not stop a determined attacker who can patch a binary, and the docs say so plainly rather
than implying DRM the tool does not have. Hard, unbypassable enforcement lives server-side,
which is the **M22** team/server track — the natural sequel to this one. And the licence
signing key is the most sensitive thing this track introduces after the interception CA: its
storage and rotation get a runbook, not a line in a script.

<!-- Release-blocker resolved: the licence key is no longer a placeholder. `EMBEDDED_LICENSE_KEY`
is now set at build time from `HEXORA_LICENSE_PUBKEY` (64 hex), all-zeros (free tier) when
unset — so dev and tests cannot grant a tier, and a release embeds the real key. The issuer
tooling landed: `hexora license keygen` (Ed25519 keypair) and `hexora license sign` (mint a
signed licence). Shipping them is safe because signing needs the offline private key and the
build verifies against the separately-embedded public key. The one-time key ceremony is in
docs/licensing-keys.md. Proven end to end: keyed build + signed Pro licence unlocks a gated
feature; no licence stays free; a wrong-key licence is refused. Remaining: LIC.d (signed
installers, needs code-signing certs) and running the ceremony once before release. -->


**Sequencing.** LIC.0 is a decision to make now. a→b is the smallest path to actually
charging money (a gate and a split); c makes the paid experience humane; d and e make it
feel enterprise-grade and pass procurement. It is the shortest route from "a strong tool" to
"a tool with a price", and it does not need another protocol first.

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
