# Where we are

**Pick-up-anywhere note.** Read this first on a new machine or after a break; it is the
only file that needs to be current for you to resume. Updated at the end of every
milestone.

- **Last updated:** M13.7 (cross-identity access, scheduled)
- **Branch:** `main` · **Remote:** `github.com/Ratul-netizen/Hexora`
- **Toolchain:** Rust 1.98 pinned in `rust-toolchain.toml` · MSRV 1.88

---

## Done

| Milestone | What it gave us |
| --------- | --------------- |
| **M0** — Architecture foundation | Domain model, SQLite storage + content-addressed blob store, migrations, scope enforcement at the transport chokepoint, extension permission model, AI tool gate, CLI + Tauri shells, CI, threat model, security invariants |
| **M1.1** — HTTP/1.x over TCP | Wire-preserving parser (permissive but loud, records smuggling quirks), RFC 9112 §6.3 framing, per-phase timeouts, incremental limits, `hexora send` |
| **M1.2** — TLS | rustls with SNI/ALPN, platform trust store, per-transport verification opt-out, mTLS client certs, TLS observations recorded on the exchange |
| **M1.5** — Chunked + compression | Chunked decoding with desync quirks, trailers, gzip/deflate/brotli with bomb protection enforced while expanding |
| **M1.3** — Streaming bodies | Incremental chunked state machine, `BodyStream` owning the connection, `send_streaming()` returning at the response head |
| **M2.1** — Interception CA | Per-installation CA, per-host leaf minting, RFC 1123 host validation, easy removal |
| **M2.2** — HTTP proxy | Absolute-form forwarding, hop-by-hop stripping, capture via an observer, loopback by default |
| **M2.3** — TLS interception | `CONNECT` tunnelling, double handshake, selective interception with exempt and only-mode |
| **M2.4** — Interception hooks | Forward / replace / drop / respond on requests, forward / replace / drop on responses, with a queue that cannot wedge the browser |
| **M3** — Traffic storage | Proxied exchanges persist into a project: metadata in SQLite, bodies content-addressed and deduplicated, both the wire and decoded forms kept, TLS details and framing quirks recorded, keyset-paginated `hexora history` |
| **M4** — Repeater | Load a request from history, edit it in `$EDITOR`, resend it, diff the responses. Nothing is auto-corrected — a wrong `Content-Length` is reported and sent as written. Sends keep a link to what they derived from, so `--tree` answers "which edit caused this?" |
| **M2.5** — Trust and first run | `hexora setup` gets a machine ready in one command. The CA installs into the *user* trust store (no admin), is verified by asking the platform rather than trusting an exit code, and removes cleanly. Firefox is detected and called out because it ignores the system store |
| **M5** — Desktop UI | The Tauri window does the whole loop: open a project, install the CA, run the proxy, watch traffic arrive live, inspect an exchange, send it to the repeater, edit, resend, diff. Same crates as the CLI — there is no second engine |
| **M12.1** — Authorization testing | Replay one captured request as every identity and say what the differences prove. Structural comparison, an unauthenticated control that stops a public page becoming six findings, declared object ids that both convict and exonerate, confidence that has to be earned by reproduction. Identities and scope now persist in the project |
| **M12.2** — The findings store | A run's conclusions are written into the project, with their evidence. Storage refuses a claim that fails its own validation. Re-running updates the claim rather than duplicating it, keeps triage decisions, and lets confidence fall when the evidence no longer supports it. `hexora findings` lists, shows and triages |
| **M12.3** — The report | `hexora report` turns a project into a document: Markdown for a ticket, a self-contained HTML page for a client, JSON for whatever reads it next. Every claim quotes the request and the response behind it; a citation the project cannot resolve is printed as missing rather than as a dead id. Scope, identities and coverage come first, so a clean run reads as a record of what was tested rather than a clean bill of health. Leads stay in their own section, dismissed findings are counted rather than hidden, and credentials are redacted with the length of what was removed |
| **M12.4** — The desktop workflow | The window does the whole loop without a terminal: declare scope and identities, pick a captured request, replay it as everybody, read the matrix, open any cell's exchange, work the findings list, follow a citation back into history, triage, and render the report. Same commands, same crates, same engine as the CLI. The interface has now been *looked at* on Windows, which is how two layout defects and a wrong run instruction in the docs were found |
| **M12.5** — Constructed attempts | The matrix replays; this builds. Declare which identifiers are objects and who owns them, and a run substitutes one into the object slot of a captured request and sends it as each identity — the request nobody captured, which is the only way to ask "can User B reach *User A's* invoice?" from User B's own traffic. Nothing is guessed, a 200 is not a finding, every generated request records the substitution behind it, and the substitution touches nothing else in the message |
| **M12.6** — Wire-exact traffic | Response bodies are kept in both forms — the bytes that arrived and the bytes they decode to — so `--wire` returns the gzip stream and `--body` the JSON inside it. Requests can be sent byte for byte: `RequestSource::{Structured, Raw}`, a `--raw` flag and a mode switch in the window. Bare LF stays bare LF, casing and duplicates survive, a wrong `Content-Length` is sent wrong. Raw mode still goes through the same scope guard, and Hexora no longer claims byte-preservation it does not have |
| **M12.7** — Identifier suggestions | Hexora reads a project's own traffic and offers the values that behave like object identifiers. It stops there: a candidate has no owner field, accepting one declares nothing, and the analyzer takes no transport so it cannot send. A value is offered because it *varies where an identifier would* against a path that is holding still — not because it looks numeric — so `v2` is never suggested and `/status` against `/profile` suggests neither. Each suggestion carries the signed signals behind it rather than a confidence number, so "why did it suggest this?" has an answer you can disagree with. Suggestions persist across sessions; a decision survives re-analysis. `hexora identifiers` and an Identifiers tab in the window |
| **M12.8** — Engagement snapshots | A retest can finally answer *what changed*. `hexora snapshot take` records the project as it stood — claims, scope, identities, declared objects — as copies rather than references, so a later run cannot rewrite its own past. `snapshot diff` compares two moments, or one moment against the project as it stands, and it never says *fixed*: a claim that stopped appearing is reported as gone **with the reason**, and only one of the three reasons is about the application at all. A claim nothing re-tested between the two is listed as standing-but-untested rather than counted as unchanged, which is the failure a real retest run exposed. Credentials never reach a snapshot |
| **M13.1** — The verification framework | A detector's suspicion and a finding's claim are different types, and the compiler keeps them apart: `FindingStore` takes a `Verified`, which only a `Verification` produces, so a check that is merely suspicious cannot record a claim — the call does not compile. Confidence is derived from what the experiment showed rather than chosen by the detector, which puts the ladder from lead to confirmed in one place instead of one per check. A verifier receives a `Lab` — send this as this principal — not a transport, so scope and attribution cannot be forgotten. M12.1 and M12.5 were rewritten onto it in the same change, with identical live results. `hexora detectors` says what this build looks for and which of it sends |
| **M13.2** — The passive scanner | Six checks over traffic the project already holds, and nothing sent: `scan(&Project, &Selection)` has nowhere to put a transport, so "passive" is a property of the signature. Three products kept apart — an informational observation is listed and never filed, a reportable one becomes a *lead*, and a hypothesis stops until an experiment settles it. A check does not choose its own verification, so nothing passive can state itself above a lead. Five hundred endpoints missing one header is one finding citing three exchanges. A run records which detectors ran and at which versions, including the ones that saw nothing — which is the row that turns silence into a fact |
| **M12.9** — Proof of concept | A finding compiles into steps somebody can run, built from the exchanges it already cites and nothing else — a citation the project has lost is printed as a gap rather than guessed at. Credentials become placeholders named after the identity, the same one in every step, so a reader supplies two values and runs the whole thing. `curl` where curl can express the request, and a stated reason where it cannot: a command that recomputed a deliberately wrong `Content-Length` would undo raw mode at the last step. `hexora poc`, a **Run it** block in the report for established findings, and a panel in the window |
| **M12.10** — Structural difference | The comparison engine could say two responses were 97% alike; it can now say *which field*. Responses are flattened to JSON paths that keep their array indices — `$.items[3].price`, not `$.items[].price` — and each path is classified as appeared, disappeared, changed or type-changed. The normalisation that makes that survive a real application is an **explicit policy**, not a silent behaviour: a field set aside is still listed with both its values and the reason, the policy prints itself into the report, and `Policy::strict()` sets nothing aside at all. Credential-named fields report *that* they differed and never *what* they were. Duplicate JSON keys are flagged rather than collapsed by the parser in silence. Two identities served byte-for-byte the same document — behind an unauthenticated request that was refused — now state firmly, without needing a declared object id |
| **M13.3** — The active scheduler | The first thing in Hexora that sends traffic nobody typed, and the first that asks before doing it. `Plan::prepare` is synchronous and answers "what would this do?" — which hypotheses can be settled, which lost their traffic, which point outside scope, how many requests per host — so `--dry-run` is the sending function not being called rather than a flag it honours. One host is never sent two requests at once: each gets a sequential queue with a pause, and only different hosts run concurrently. The ceiling is enforced by the lab a check is handed, so a check that loops is stopped by what it was given. A run that stopped early says so before its results, in the CLI, the window and the run record. First active check: `cors.reflection`, which settles M13.2's CORS suspicion with an origin that cannot be on anybody's allowlist |
| **M13.4** — Reflected input | The check a scanner is most often wrong about, built to be right about it. A probe carries its own markers and the characters worth testing in one value, so one request answers both *did it come back* and *what survived*. Seven contexts are told apart — HTML text, quoted and unquoted attributes, comments, script strings, script source, style, JSON — under the response's **declared** content type rather than a guess, because `{"q":"<script>"}` is inert as JSON and is markup as HTML and the bytes are identical. Confirmed means a *second, different* marker landed the same way, not the same request twice. It never says "cross-site scripting": it says which character came back unencoded and where, then says what it would take to know more |
| **M13.5** — Redirect destination | The `Location` header is resolved the way a browser resolves it and **never followed** — following a destination the target chose is the one way an automated tool gets talked into traffic nobody authorized, and the scope guard is a backstop rather than a reason to try. The answer is a *host*, not a substring: `//elsewhere`, `/\elsewhere` and `https://trusted@elsewhere` are all taken and all invisible to a filter matching `http`, while `/redirect?to=https://elsewhere` is carried and is refuted **with the reason**. An application that refuses the absolute form and accepts the protocol-relative one is reported as what it is — a filter that does not cover a form browsers treat identically. Probe destinations are `.invalid`, so they never resolve and nobody can ever register them. New invariant 16 |
| **M13.6** — Authentication enforcement | Two failures a cross-identity matrix cannot see, because every identity in one holds a *valid* credential. Three requests per endpoint: replayed as captured (the baseline — without it an expired session makes everything look refused and the run would report *enforced* having tested nothing), then with no credential, then with the captured credential's **JWT signature** changed by one character and its header and payload byte-identical. An application that accepts the third is not verifying signatures, which is a different sentence from *authentication is missing*. The middle outcome — same status, different content — is its own answer and reaches a report as a lead, because that is what a sign-in page answered 200 looks like. Credentials are broken without ever being written down: no `Display`, a redacting `Debug`, one named accessor. New invariants 17 and 18 |
| **M13.7** — Cross-identity access, scheduled | M12.1's matrix across an engagement's traffic rather than one request a tester names. Whose session was captured is answered by **applying each declared credential and comparing byte for byte** — an exact answer or none at all, because proxy traffic announces no identity id and everything a cross-identity test concludes rests on getting it right. One implementation, two front doors: the check calls the same `replay_once` and `judge` that `hexora authz` does, so a scheduled verdict and an on-demand one cannot disagree. A budget too small for every identity sends **nothing** rather than testing a subset and reporting it as the whole. Against the IDOR demo it reached **Firm with no declared object ids**, through M12.10's same-document path behind a refused anonymous control |

## Next

**The spine now runs in both directions.** A passive check raises a suspicion it
cannot settle; the scheduler settles it, and a refutation is as much a result as a
finding. Against a demo application with one reflecting endpoint and one correctly
allowlisted one, three requests produced a High/Confirmed finding on the first and
ruled the second out by name.

**Two real defects fell out of building it**, both found by checking a live run rather
than by reading code. Scanner traffic was attributed to `Origin::Repeater`, which the
scope guard treats as human-initiated — so an out-of-scope host would have been
flagged rather than refused. And the passive pass deduplicated hypotheses per *host*,
so on an application with a vulnerable endpoint and a safe one next to it, the
scheduler tested whichever came first and the bug went unprobed.

**The evidence spine is now end to end.** Traffic becomes an observation, an
observation becomes a hypothesis, a hypothesis becomes a verification, a verification
becomes a finding — and a finding now becomes something a triager can run. Each arrow
is a thing somebody can check, which is the whole product.

**And the comparison at the centre of it now produces a sentence rather than a
number.** "97% alike" is a thing a developer can dispute and nobody can verify;
"`$.email` was present for User A and absent for User B" is a line they can go and
look at. M12.10 also gives the authorization engine a second way to reach a firm
claim: two identities served *the same document*, with an unauthenticated request
refused that document, no longer needs a hand-declared object id to be stated
firmly.

**Nothing in this build sends a request a tester did not ask for.** That sentence
survives M13.3 unchanged, and keeping it true is most of what the milestone is: a run
happens because somebody invoked one, the plan is shown before anything goes out, and
a non-interactive stdin answers *no*.

**The gate everything else is built behind is in place.** M13.1 makes the distinction
between *a check thought something* and *an experiment established something* a fact
about the types rather than a discipline somebody has to keep. Every scanner after
this inherits it for free, which is the only reason it was worth building before there
were any scanners to inherit it.

**A second visit is now answerable.** M12.8 gives the engagement a memory: what was
true then, frozen, so what is true now can be compared against it. The discipline is
the same one the rest of the tool runs on — Hexora will say a claim is *gone* and say
why, and it will not say *fixed*, because a test that produced nothing has established
nothing about an application.

**Every object identifier no longer has to be typed by somebody.** M12.5 could build
the request nobody captured, but only from identifiers a human had already declared,
which made constructed testing exactly as broad as somebody's patience. M12.7 lets
Hexora point at the candidates — and go no further, because the distance between
*IdentifierCandidate*, *ObjectDefinition* and *ownership* is the distance between a
tool whose findings can be trusted and one whose findings rest on a guess.

**The request layer no longer changes anything it was not asked to.** A response is
kept as it arrived *and* as it decodes; a request can be sent exactly as written. That
matters most for what comes next: a scanner generating traffic on top of a layer that
quietly rewrote bytes would produce findings about requests nobody made.

**The order is frozen** as of M12.6, and the reason is worth repeating here because it
decides what gets built: *Hexora does not win by having more scanners — it wins by
making every automated result explainable, reproducible and safe.* Full detail in
[`docs/roadmap.md`](docs/roadmap.md).

```text
M13.4  Reflected-input verification  context-aware, not "the string came back"
M13.5  Redirect verification         a controlled destination, never blindly followed
M13.6  Auth/session verification     the identity model, applied differentially
M13.7  IDOR/BOLA automation          M12.5 as a scanner primitive
```

The one immediately next, in more detail:

- **M14 — the manual-testing pillar.** Intercept editor, Repeater tabs, match/replace,
  scope organisation, search and filter, manual findings as first-class. The scanner
  work of M13 is built on evidence a person gathers; the interface for gathering it by
  hand has had one milestone (M12.4) to the scanner's eight. *Manual testing is not a
  legacy mode beneath automation — it is the source of experiments, evidence and
  eventually automation.*

Still open in M12: **attack chains** that retain evidence at every step.

**Not before those, however tempting:** HTTP/2 or HTTP/3 fuzzing, WebSocket fuzzing,
large payload generators, autonomous AI exploitation, hundreds of vulnerability
signatures, or Burp extension compatibility. Each multiplies the surface area that has
to be trustworthy before any of it is.

**What the active scheduler has and has not been run against.** One local demo
application with a deliberately reflecting endpoint and a correctly allowlisted one,
over plain HTTP on loopback. The pacing and ceiling are unit-tested against a
recording lab with real timing, and the whole thing has never been pointed at a large
application, a rate-limited one, or one behind a CDN that answers differently to an
unfamiliar `Origin`.

**What the scheduled cross-identity check does not cover.** *Constructed* requests —
substituting a declared object identifier that belongs to somebody else. M12.5 does
that on demand and the roadmap named it as part of M13.7; what shipped is the **replay**
half, which needs no declarations and therefore works on every engagement. The
constructed half needs `hexora object add` to have been used, and scheduling it is a
smaller increment now that the replay machinery is schedulable. Recorded as a decision
rather than an omission.

Also not covered: an endpoint whose captured credential matches no declared identity is
reported as untested rather than guessed at, so an engagement whose identities were
added after the traffic was captured gets nothing from this check until the traffic is
re-captured.

**What authentication enforcement covers, and what it does not.** M13.6's roadmap
line named two things: *"the same request as User A, User B and Anonymous, compared
differentially"*. What shipped is the **anonymous and broken-credential half** — is a
session required, and is it checked — which is the part nothing else in Hexora could
do. The **multi-identity half** is M12.1, which already does it on demand for one
request a tester names, and scheduling it across an engagement is M13.7, where it sits
with the constructed-request work. That split is a decision rather than an omission,
and it is recorded here so nobody reads `auth.enforcement` as covering cross-identity
access.

Also not covered: anything but `GET`, `HEAD` and `OPTIONS` — see invariant 18 — and
session *fixation*, *rotation* and *expiry*, which need a login flow rather than one
captured request.

**What redirect verification does not cover.** Header-driven redirects —
`X-Forwarded-Host` poisoning is the usual one — are **not** tested. They have a
different shape: the interesting response is often a 200 whose absolute links have
moved rather than a `Location` at all, and claiming to cover them by putting a
destination in `Accept` would be worse than saying they are not covered. Only query
parameters of endpoints that actually redirected in captured traffic are probed, so a
redirect that happens only for certain values is missed too.

**What reflected-input verification does not cover.** Request bodies. An input in a
JSON or form body is not enumerated, because [`ObjectLocation::Body`] addresses a byte
offset — the right handle for replacing a value somebody already found, and the wrong
one for listing fields nobody has. That wants a body model, and it is a gap rather than
a decision. Path segments are also deliberately left out: a segment is as often a route
as a value, and `hexora identifiers` is the thing that tells those apart with evidence.

**Stopping is wired, and one half of it is unverified.** The window's Stop button was
clicked mid-run against a deliberately slowed target: 6 of a planned 48 requests went
out, and the result reported itself as unfinished above its findings. The CLI's Ctrl-C
path is written and compiles, but **it has not been confirmed with a real console
signal** — this environment cannot deliver one to a background Windows process, and
`kill -INT` from MSYS kills the process instead of raising the handler. Somebody
should press Ctrl-C during a real run before that path is trusted.

**Two honesty notes carried forward:**

The macOS and Linux trust paths in `core/proxy/src/trust.rs` are written, unit-tested
and type-checked, but have never been *run* on those platforms. Only Windows is
verified end to end.

The authorization work — replay, construction and the report — has been exercised end
to end against a local application with a deliberate IDOR *and* a correctly built
version of the same endpoint, from the CLI and from the window. The broken one produced
a High finding naming the exact substitution; the correct one produced nothing at all.
None of it has been run against a large real application, where response noise is worse
than any fixture.

**What raw mode does and does not cover.** HTTP/1.x request bytes, and nothing else:
there is no raw frame injection for HTTP/2 or HTTP/3, and no raw WebSocket frames.
Those want wire models of their own rather than a byte buffer with a different name.
Raw mode also does not bypass scope, and cannot: the destination is the service the
request is addressed to, the path is read out of the request line, and a request whose
line cannot be read is refused.

**What constructed testing does not prove.** Ownership is the tester's assertion, not
something Hexora establishes: `hexora object add` records a claim. A constructed
attempt that cannot tie what came back to the declared owner produces a lead, never a
finding — and Hexora does not suggest which values are identifiers, so the coverage is
exactly as broad as what somebody has declared. Do not read "no findings" from a
construction run as "no IDOR".

**The window has been inspected** on Windows, every tab, with a real project open. It
has not been seen on macOS or Linux, at a small window size, or on a high-density
display, and the HTML report is still shown as text rather than rendered.

M1.4 (connection pooling) stays deferred: the fuzzer needs it, the proxy does not, and
a pool that mis-frames one response corrupts the next.

Full plan: [`docs/roadmap.md`](docs/roadmap.md).

## Open decisions

| Question | Status | Blocks |
| -------- | ------ | ------ |
| **First customer**: solo pentesters / small consultancies / bug bounty hunters | **Unanswered** | Nothing until M4. Decides whether M12 (authorization testing → reports) or M13 (scanner) comes first. Recommendation: consultancies — the gap between Caido Team and Burp's $13,600 Enterprise tier, and the evidence architecture already fits |
| Write positioning analysis into `docs/positioning.md`? | Unanswered | Nothing |

---

## Getting a machine ready

```bash
# 1. Rust
winget install --id Rustlang.Rustup -e          # Windows
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # macOS/Linux

# 2. Windows only: MSVC C++ build tools, INCLUDING the Windows SDK
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override \
  "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# 3. Frontend
corepack enable && pnpm -C frontend install
```

### Two Windows traps that cost hours

1. **Do not build from Git Bash.** Git for Windows ships a coreutils `link.exe` at
   `/usr/bin/link.exe` that shadows MSVC's linker. The error looks nothing like a
   toolchain problem — it says `link: extra operand` and suggests installing build
   tools you may already have. Build from **PowerShell** or a Developer Command
   Prompt, or `call vcvars64.bat` first.
2. **`--includeRecommended` matters.** Installing the VCTools workload without it can
   omit the Windows SDK, and you get `LNK1181: cannot open input file 'kernel32.lib'`.

Both are written up in [`docs/development.md`](docs/development.md).

## The gate — run this before every commit

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
pnpm -C frontend typecheck && pnpm -C frontend build
```

All six must pass. `cargo audit` currently reports **0 vulnerabilities** and 8
warnings — 7 unmaintained crates and one unsoundness in `glib`, all transitive through
Tauri and recorded in [`docs/dependencies.md`](docs/dependencies.md).

## Try it

```bash
# Everything at once, on a machine you control.
cargo run -p hexora-cli -- setup ./engagement

cargo run -p hexora-cli -- send http://example.com/
cargo run -p hexora-cli -- send https://example.com/ --insecure   # self-signed targets
cargo run -p hexora-cli -- project init ./scratch/demo

# The CA, a step at a time.
cargo run -p hexora-cli -- ca --status      # does this machine trust it?
cargo run -p hexora-cli -- ca --install     # asks first
cargo run -p hexora-cli -- ca --untrust     # remove from the store, keep the files
cargo run -p hexora-cli -- ca --delete      # untrust and remove everything
cargo run -p hexora-cli -- ca --export hexora-ca.crt
cargo run -p hexora-cli -- proxy --listen 127.0.0.1:8080
cargo run -p hexora-cli -- proxy --only target.example.com   # leave your own traffic alone

# Capture into a project, then read it back.
cargo run -p hexora-cli -- proxy --project ./scratch/demo
cargo run -p hexora-cli -- history ./scratch/demo
cargo run -p hexora-cli -- history ./scratch/demo --body req_01a08b… > response.bin
cargo run -p hexora-cli -- history ./scratch/demo --body req_01a08b… --wire > wire.gz

# The repeater: resend, edit, compare, and see what descended from what.
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --dry-run
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --edit
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --raw --edit   # bytes, untouched
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --tree
cargo run -p hexora-cli -- repeat ./scratch/demo req_A --diff req_B

# Authorization testing: is the application checking who is asking?
cargo run -p hexora-cli -- scope add ./scratch/demo api.example.com
export TOKEN_B=...                      # never on the command line: ps reads that
cargo run -p hexora-cli -- identity add ./scratch/demo "User B"     --kind bearer --from-env TOKEN_B --owns acct-2000
cargo run -p hexora-cli -- identity list ./scratch/demo
cargo run -p hexora-cli -- authz ./scratch/demo req_01a08b… --as-identity "User A"
cargo run -p hexora-cli -- authz ./scratch/demo req_01a08b… --as-identity "User A" --verify

# Ask the question a capture cannot: not "can this identity reach this URL?" but
# "can it reach *that* object?". Declaring sends nothing; --construct does.
cargo run -p hexora-cli -- object add ./scratch/demo acct-1000 --owner "User A" --name account --in-request req_01a08b…
cargo run -p hexora-cli -- object list ./scratch/demo
cargo run -p hexora-cli -- authz ./scratch/demo req_01a08b… --as-identity "User B" --construct --verify

# What a run concluded, and what to do about it.
cargo run -p hexora-cli -- findings ./scratch/demo
cargo run -p hexora-cli -- findings ./scratch/demo --actionable
cargo run -p hexora-cli -- findings ./scratch/demo --show fnd_01a08c…
cargo run -p hexora-cli -- findings ./scratch/demo     --triage fnd_01a08c… --status false-positive

# The write-up, with the traffic behind every claim quoted in place.
cargo run -p hexora-cli -- report ./scratch/demo
cargo run -p hexora-cli -- report ./scratch/demo --format html --output acme.html
cargo run -p hexora-cli -- report ./scratch/demo --actionable --severity high
cargo run -p hexora-cli -- report ./scratch/demo --format json

# The desktop window. Same engine, no terminal.
pnpm -C frontend dev            # leave running: a debug build loads the dev server
cargo run -p hexora-desktop     # in a second terminal
```

---

## Things worth remembering

Written down because they were learned the hard way and are easy to undo by accident.

- **The parser is hand-written on purpose.** `httparse` would be the obvious choice and
  is the wrong one: a client parser normalizes away exactly the ambiguity a security
  tool exists to find. See the module docs in `core/http/src/parse.rs`.
- **`Secret<T>` has no `Serialize` impl.** That is not an oversight — it makes leaking
  a credential through `serde_json::to_string` a *compile error*. Persistence opts in
  per field via `redact::exposed`.
- **Scope normalization decodes to a fixed point.** Decoding once left a real bypass:
  `/%2561dmin` → `/%61dmin` → `/admin`. Found by a property test, not by review.
- **Unimplemented paths return `NotImplemented` naming their milestone.** Never an
  empty result — a security tool that appears to have run and found nothing is worse
  than one that says it cannot run yet.
- **Tests that assert OS-specific error classifications will fail in CI.** Closing a
  socket with data queued gives `ECONNRESET` on Windows and a clean EOF on Linux.
- **Windows schannel rejects a locally generated CA passed as a file.** It checks
  revocation, and a local CA has no revocation list, so you get
  `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` even though the certificate is fine. Install
  it into the store with `certutil` instead; `curl --ssl-revoke-best-effort` works for
  a quick test.
- **Inside a CONNECT tunnel the client sends origin-form targets**, which carry no
  scheme. Forwarding one naively replays it upstream over plaintext and silently
  downgrades a connection the user believes is encrypted. The scheme comes from the
  CONNECT authority, and a test asserts the captured URL stays `https://`.
- **Interception records what the server said, never what the tester substituted.**
  A replaced or dropped response is still observed as it arrived. Recording a
  substitution as the server's own behaviour would put a fabricated response into the
  evidence behind a finding.
- **"Interception enabled" and "interception watched" are different states.** With no
  consumer attached nothing pauses, because a queue nobody reads would hang every
  request while looking like a crashed proxy.

## Documentation map

| File | For |
| ---- | --- |
| [`docs/roadmap.md`](docs/roadmap.md) | What exists, what is next, in what order and why |
| [`docs/feature-parity.md`](docs/feature-parity.md) | Burp / Caido / ZAP matrix and competitive position |
| [`docs/architecture.md`](docs/architecture.md) | Crate layout and where invariants are enforced |
| [`docs/security-invariants.md`](docs/security-invariants.md) | The rules the codebase does not break |
| [`docs/threat-model.md`](docs/threat-model.md) | Hostile targets, extensions, local attackers — and the limits |
| [`docs/storage.md`](docs/storage.md) | Why bodies are not in the database |
| [`docs/development.md`](docs/development.md) | Building, testing, conventions |
| [`docs/dependencies.md`](docs/dependencies.md) | Dependency, audit and secret-scanning policy |
- **An anonymous control is what makes a matrix trustworthy.** Without it, a public
  page produces one "violation" per identity, all of them true and all of them
  worthless. With it, the run says the only thing that is actually the case.
- **Declared object identifiers cut both ways.** They are what raises a similarity
  match to a disclosure — and what clears an endpoint that returns each caller their
  own record in an identical document shape. `GET /profile` scores 1.00 against the
  owner's response and is not a bug; only the ids inside can say so.
- **Scope is why `hexora authz` needs a project that has one.** Authorization replays
  are automated traffic, and the guard refuses automated traffic to undeclared hosts.
  The run asks once, before sending, so a misconfigured scope is one sentence rather
  than one failure per identity.
- **A findings list that un-dismisses things is a list nobody reads.** Re-running a
  test refreshes the claim and leaves the triage decision alone, on purpose. The
  inverse rule is just as deliberate: confidence follows the evidence *currently*
  attached, so a re-run without `--verify` takes a `Confirmed` finding back down to
  what the stored comparison actually supports.
- **"Identical" is an answer, not an empty result.** `hexora repeat --diff` used to
  print nothing for two matching responses. For an authorization comparison that case
  is the finding, and printing nothing reads as a broken command.
- **A report that lists nothing must not read as "nothing is wrong".** An empty
  findings section is a statement about what was tested, and the coverage, scope and
  identities are printed above it so a reader can see the limits of the claim.
- **The HTML report escapes everything and loads nothing.** It quotes bodies from the
  application that was just attacked, and some findings exist *because* that
  application reflects input — an unescaped report would deliver the payload it
  documents, on the client's machine. For the same reason there is no script, no
  external stylesheet and no font from a CDN: a document that phoned home on open
  would leak when and where it was read.
- **A citation that resolves to nothing is worse than no citation.** It leaves the
  reader believing the claim was checkable. A cited exchange the project no longer
  holds is printed as missing, with the reason, and counted in the report's caveats.
- **A redacted header prints the length of what was removed.** Otherwise a reader
  cannot tell a credential that was hidden from one that was never sent, and the
  request in front of them will not reproduce either way.
- **A bare `input` selector catches checkboxes too.** `.toolbar input { width: 320px }`
  stretched the findings filter's checkbox to a third of the screen and left the box
  marooned from its own label. It was in the stylesheet for one milestone before
  anybody opened the window.
- **A debug Tauri build loads `devUrl`, not `frontendDist`.** The documented command
  (`pnpm build && cargo run -p hexora-desktop`) opened a window reading
  `ERR_CONNECTION_REFUSED` — which looks like a broken application rather than a
  missing dev server. Written up in `docs/development.md`.
- **Credential kinds go to the frontend; credential values never do.** `IdentityView`
  has no field that could carry one, so a token cannot reach a devtools console, a
  screenshot or a crash report by accident. The typed IPC edge is where that is
  enforced, and there is a test asserting it.
- **The object slot belongs to the request, not to the sender.** Resolving it per
  identity meant the anonymous control — which owns nothing — fell back to a location
  recorded on a *different* endpoint and substituted into the literal path word
  `accounts`. One request, at a URL nobody chose, answering nothing. It is resolved
  once from the request now, and a location recorded elsewhere is never reused.
- **A control response is what makes a similarity score mean anything.** "The reply
  looks like the object document" is empty without the document that identity gets for
  its *own* object, so every sender sends one unmodified request first. The first
  version of the test fixture returned the same error page to everybody, which scored
  1.00 against itself and turned an error page into a violation.
- **Include the target in its own candidate list.** Excluding it looked tidy and made
  "this request already asks for that object" — where the honest answer is *the matrix
  covers this* — come out as "there is nowhere to put it".
- **"Wire body" is two different things, and both matter.** Framing (chunk headers,
  Content-Length) and content coding (gzip) are separate steps, and a single name for
  the bytes between them would be useless for smuggling research and for
  content-encoding research alike. The stored pair is *transfer-decoded* and
  *content-decoded*, and `docs/architecture.md` defines both.
- **A structured view must not invent what the bytes did not carry.**
  `HttpRequest::get` adds a `Host` header from the service, so the history pane showed
  a `Host` on a raw request deliberately sent without one. A view of evidence that
  adds a field is worse than one that omits it.
- **The panel had been claiming byte preservation it did not have.** The repeater's
  own description said "what is typed is what is sent" while structured editing
  re-serialized the message. The fix was as much the sentence as the code.
