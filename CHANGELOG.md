# Changelog

All notable changes to Hexora are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

### Added — M0, architecture foundation

**Domain model** (`core/types`)
- Raw-preserving HTTP message model: ordered duplicate-tolerant headers, original
  casing, byte bodies, framing-ambiguity detection for smuggling work.
- Type-distinct UUIDv7 identifiers.
- Scope model with deny-wins semantics, path normalization (percent-decoding and
  dot-segment removal), IPv4/IPv6 literal handling and subdomain wildcards.
- Testing identities with privilege ordering for authorization testing.
- Evidence-driven finding model; findings cannot claim confidence they have not earned.
- Resource limits, including two-sided decompression-bomb protection.
- `Secret<T>` wrapper: no `Display`, redacted `Debug`, explicit `.expose()`.

**Storage** (`core/storage`)
- Metadata/body split: SQLite for metadata, content-addressed blob store for bodies.
- Filesystem blob store with SHA-256 addressing, deduplication, atomic writes,
  two-level sharding and integrity verification on read.
- Transactional forward-only migrations; a newer schema is refused, not downgraded.
- Backend-agnostic repository interfaces with mandatory cursor pagination.

**Engine** (`core/engine`)
- Single transport boundary through which all requests pass.
- `ScopeGuard`: automated subsystems cannot send out-of-scope traffic; human-driven
  requests are flagged rather than blocked.
- Extension permission model that can only be narrowed after grant.
- AI tool-permission gate; credential access forbidden outright.

**Applications**
- `hexora` CLI: `project init`, `project info`, `version`.
- Tauri + React desktop shell reporting engine status and checking IPC contract version.

**Project**
- CI: fmt, clippy (deny warnings), test, frontend typecheck and build, desktop check,
  dependency audit.
- Documentation: architecture, threat model, storage, security invariants, development
  guide, roadmap.
- AGPL-3.0-or-later.

### Fixed — M0 compiler and security gate

First run of the code against an actual compiler. Six defects that static review missed:

- `hexora-storage`: pooled connection could not coerce to `&Connection` through `?` (E0308).
- `hexora-cli`: a helper returned an array of references to its own parameters (E0515);
  replaced with `rusqlite::params!` at the call site.
- `clippy::if_same_then_else` in path normalization; two branches merged.
- `clippy::manual_range_contains` in a storage test.
- Tauri `#[tauri::command]` in the crate root collided with its own generated
  re-export (E0255); the IPC surface moved to `commands.rs`, which is better structure
  anyway — the command list is the desktop client's whole attack surface.
- Missing `icons/icon.ico`, required by `tauri-build` on Windows. Icons are now
  generated reproducibly by `scripts/generate_icons.py`.

Also: a false-positive test. `no_temporary_files_are_left_behind` matched `.tmp`
anywhere in the path, and `tempfile::tempdir()` names its directory `.tmpXXXXXX`, so
every blob looked like a leftover. Now matches file names only.

### Security

- **`Secret<T>` no longer implements `Serialize`.** It was `#[serde(transparent)]`, so
  `serde_json::to_string` on an `Identity` emitted the credential in cleartext — a leak
  through exports and IPC that a redacting `Debug` did nothing to prevent. Deriving
  `Serialize` over a secret is now a compile error. Persistence must opt in per field
  through the new `redact::exposed` adapter. `Credential` and `Identity` are
  consequently not `Serialize`.
- Removed a Base64 Basic Authentication literal from a test. It was RFC 7617's own
  worked example (`aladdin:opensesame`) and therefore not a live credential, but it is
  indistinguishable from one to a scanner or a reviewer skimming a diff. The test now
  decodes the header and asserts against obviously-fake fixtures.
- Added a `gitleaks` CI job scanning full history. There was no secret scanning before.
- CI toolchain pinned to 1.98 in every job. Previously CI installed `stable` and cargo
  then silently auto-installed a different compiler from `rust-toolchain.toml`.
- MSRV corrected from 1.85 to 1.88 — the floor imposed by Tauri's dependency graph.

### Added — M1.1, HTTP/1.x over TCP

**Hexora now sends real requests.**

- New crate `core/http`: a wire-preserving HTTP/1.x parser and a TCP transport.
- The parser is deliberately permissive but loud — it accepts what a strict parser
  rejects and records every deviation as a `Quirk`, five of which are request-smuggling
  signals (bare LF, obs-fold, space before colon, duplicate `Content-Length`, CL beside
  TE). Written by hand rather than using `httparse` precisely because a good client
  parser normalizes away what a security tool exists to find.
- Framing per RFC 9112 §6.3. Conflicting `Content-Length` values are refused rather
  than guessed.
- Per-phase timeouts and incrementally-enforced limits.
- `hexora send <url>` — like `curl`, except nothing you wrote is rewritten on the way
  out: header order, casing and duplicates are all preserved, and a deliberately
  ambiguous request stays ambiguous.

Sensitive response headers are redacted in `hexora send` output unless
`--show-secrets` is passed, and out-of-scope targets are flagged rather than blocked,
since a typed URL is a human decision.

### Added — M1.2, TLS

- rustls with SNI, ALPN and mTLS client certificates; roots from the **platform**
  trust store, so a corporate inspecting proxy's CA is honoured automatically.
- Certificate verification is per-transport, recorded on the exchange and logged every
  time it is relaxed — not a global "ignore TLS errors" switch.
- TLS observations (deprecated protocol versions, expired or self-signed leaves)
  surfaced as observations, never as findings.
- `TlsInfo`, `CertificateSummary` and `Verification` live in `hexora-types`: domain
  vocabulary that storage and the UI both need, kept free of `rustls` so the record
  outlives the implementation.

### Added — M1.5, chunked transfer and content decoding

- Chunked decoding that treats the chunk-size line as the desync surface it is:
  extensions, whitespace, signs, `0x` prefixes, leading zeros, missing terminators and
  data after the final chunk are each recorded as a `Quirk`, and six of them are
  flagged as smuggling signals.
- Trailer fields are captured and merged into the header list.
- gzip, deflate (zlib-wrapped or raw) and brotli, with `Limits::check_decompression`
  finally carrying real traffic — enforced in 64 KB steps while output expands, so a
  bomb is stopped mid-expansion rather than after.
- An unrecognised `Content-Encoding` is an error, not a silent pass-through: returning
  still-encoded bytes as a body would make every downstream match wrong.

### Fixed

- **Scope normalization decoded only once**, leaving a real bypass:
  `/%2541dmin` → `/%41dmin` → `/admin`. Any gateway that decodes and forwards to a
  back-end that decodes again would route past an exclusion. Decoding now runs to a
  fixed point. Found by the `normalization_is_idempotent` property test.

### Added — M1.3, streaming bodies

- Incremental chunked state machine, so a response is decoded as it arrives rather than
  after it is complete.
- `BodyStream` borrows the connection, letting the proxy relay a body it never buffers.
- `send_streaming()` returns at the response head, which is what makes interception on
  large downloads possible at all.

### Added — M2, the intercepting proxy

- **M2.1** Per-installation certificate authority: generated on first use, never
  shipped, RFC 1123 host validation before minting, and one command to remove it.
- **M2.2** HTTP proxy: absolute-form forwarding, hop-by-hop header stripping, capture
  through an `ExchangeObserver`, bound to loopback unless told otherwise.
- **M2.3** TLS interception: `CONNECT` tunnelling, the double handshake, and selective
  interception — `--exempt` for pinned applications, `--only` to decrypt one target and
  leave the tester's own browsing alone.
- **M2.4** Interception hooks: forward, replace, drop or answer a request without
  contacting the server; forward, replace or drop a response. The queue tracks whether
  a consumer is attached, so an interceptor nobody is watching cannot wedge a browser.

### Added — M3, traffic storage

- `TrafficStore`: the first real implementation over the metadata database and blob
  store built in M0. One transaction per exchange, because a request recorded without
  its response is evidence with a hole in it.
- Bodies are content-addressed and deduplicated — ten identical 404s cost one blob.
- **Both body forms are kept.** Schema revision 2 adds `encoded_body_hash`,
  `encoded_body_size` and `content_encoding`, so a finding about a compression side
  channel or a gzip parser differential remains examinable. As a separate migration:
  a released migration is never edited.
- Framing quirks and TLS handshake details are stored per exchange, so smuggling
  signals can be searched for rather than noticed as they scroll past.
- `ProjectCapture` connects the proxy to the store. Writes go to a blocking pool and a
  failure logs rather than propagating: a full disk must not break a browsing session.
  Out-of-scope traffic is captured by default — the proxy has to see a host before a
  tester can decide it is in scope.
- `hexora proxy --project DIR` records; `hexora history DIR` reads back, newest first,
  with keyset pagination that stays stable while capture continues appending.
- `hexora history DIR --body ID` writes one response body to stdout unmodified,
  `--wire` asks for the form that arrived.

### Fixed

- `hexora project info` printed `@1789041608` where a timestamp belonged; it is now
  RFC 3339, matching what the traffic store writes.

### Added — M4, the repeater

- **`hexora repeat`**: load a request from history, optionally open it in `$EDITOR`,
  send it, and see what changed. The editing loop is the shell's, not a bespoke one —
  a tester already has an editor they are fast in.
- **Nothing is auto-corrected.** A `Content-Length` that disagrees with the body is
  sent as written; a missing `Host` stays missing; duplicate `Transfer-Encoding`
  headers survive. Every inconsistency is *reported* instead, with smuggling signals
  listed first. Correcting these is how a tool turns a smuggling test into a test of
  itself.
- Editing `Host` does not redirect the TCP connection — that is a virtual-host routing
  test, and following it could send the request somewhere never in scope. An
  absolute-form request line does redirect it, because there the text is stating a
  destination.
- **Request branching.** Every send records what it derived from, so `--tree` shows a
  request and its variants, and "which edit caused the 403?" is a query rather than a
  memory. `requests.parent_id` has carried this since M0.
- **Response comparison.** Status, headers, body length, first differing byte offset
  and round-trip time. `is_interesting()` filters the noise a tester does not care
  about: a `Date` that moved on or a rotated session cookie is listed but not flagged.
- A byte-identical response that arrived seconds later **is** flagged — that is the
  entire signal in a time-based blind injection, and a diff that called it "identical"
  would hide the finding.
- `hexora repeat --diff` compares two stored exchanges without sending anything, and
  `--dry-run` prints exactly what would leave the machine.
- Storage grew `TrafficStore::request`, `response_head` and `children`, so a stored
  exchange can be reconstituted and resent. Header casing, order and duplicates
  survive the round trip through the database.

### Fixed

- **The proxy forwarded `Proxy-Connection` to origin servers.** It is a de-facto
  hop-by-hop header addressed to the proxy itself, so an origin was seeing a field the
  client never intended it to see — directly at odds with the claim that a target
  receives what the tester meant to send. Found by reading what a real target actually
  received during an M4 smoke test, not by reading the code.

### Added — M2.5, trust installation and first run

- **`hexora setup`**: one command creates a project, generates the CA, installs it and
  says what is left to do. Every step is also available on its own, and the output
  names the command for each.
- **`hexora ca --install`** installs into the *user* trust store on every platform that
  has one — the Windows user Root store, the macOS login keychain, the per-user NSS
  database on Linux. No administrator rights, and the blast radius is one account.
- **`--status`** asks the platform whether the certificate is trusted instead of
  assuming a zero exit code meant success. `unknown` is a distinct answer from
  `not trusted`, because reporting the wrong one sends a tester to reinstall a CA that
  is already there.
- **`--untrust`** removes it from the store and leaves the files; `--delete` now
  untrusts *before* deleting. The other order leaves a still-trusted certificate whose
  files are gone — the worst state to leave a root CA in.
- Installing always asks first, and a non-interactive stdin answers no. `--yes` is how
  to agree deliberately; silence is not consent for a root certificate.
- Firefox is detected and reported, because it ships its own store and ignores the
  system one — the single most common first-run confusion.
- The CA now exposes SHA-256 and SHA-1 fingerprints. SHA-256 is the identity and is
  what every trust decision is made on; SHA-1 exists only because the Windows store
  indexes by thumbprint and `certutil` accepts no other lookup key.

### Fixed

- **A reloaded CA served a certificate nobody had trusted.** `load` rebuilt the CA by
  re-signing it from parsed parameters, which mints a fresh serial number, so the DER
  differed from the file on disk. That DER is what the proxy puts in the TLS chain as
  the root and what identifies the CA to a trust store — meaning after the first
  restart, browsers were being shown a root certificate that was never installed. The
  certificate is now decoded from the stored PEM. Found by a test asserting that a
  fingerprint survives a reload.
- **Trust-store lookups were classified from the wrong line of output.** `certutil`
  opens with a banner naming the store and puts the real error two lines below, so the
  "certificate is absent" markers were never seen and every Windows check reported
  `unknown` forever. Classification now searches the whole output of both streams.

### Added — M5, the desktop UI

- The Tauri window does the whole loop: open a project, install the certificate
  authority, start and stop the proxy, watch traffic arrive live, inspect an exchange,
  send it to the repeater, edit it, resend it and see the diff.
- **The same crates as the CLI.** There is no second engine, no second proxy and no
  UI-only code path — anything the window can do is scriptable and reproducible.
- Application state lives in Rust (`state::AppState`), not in React. A frontend store
  that believed something different about a project than the engine did would
  eventually render a request that was never sent.
- Captured exchanges are pushed to the window as they happen, as summaries rather than
  whole exchanges: shipping bodies through IPC for traffic nobody has clicked on would
  stall the window during a crawl.
- Bodies are prepared for display rather than handed over raw (`preview::BodyPreview`).
  Anything containing a NUL or not valid UTF-8 is shown as a hex dump, never as lossy
  text — characters that were never on the wire have no business on screen in a
  security tool. Large bodies are truncated and say so.
- Framing quirks are surfaced in the history table rather than buried in a detail pane,
  because a smuggling signal is worth noticing while scrolling.
- Installing the CA from the window states the consequences at the moment of the
  decision and requires a second confirmation.
- `hexora_proxy::Fanout` replaces the CLI's private observer fan-out and is now shared.
  An observer that panics no longer stops the ones after it: a UI event channel that
  has gone away must not take down the capture producing the evidence.

### Fixed

- **CI failed on Linux** after M2.5: `CommandError::tool_missing` was dead code there,
  because the Linux trust-status path never called it. It now distinguishes a missing
  `certutil` — which on Debian and Ubuntu ships in `libnss3-tools` and is often simply
  absent — from a certificate that is genuinely untrusted, which is the behaviour the
  other platforms already had. `docs/development.md` now describes how to check
  `cfg`-gated code locally instead of discovering it in CI.

### Added — M12.1, authorization testing

- **`hexora authz`**: take one captured request and replay it as every identity in the
  project, then say what the differences prove. The highest-value manual work in most
  engagements, and the part testers most often run out of time for.
- **The baseline is replayed, never reused.** The captured response may be weeks old
  and its session long expired; comparing against it would report differences that
  belong to time rather than to authorization.
- **An unauthenticated control is added by default.** If an anonymous request receives
  the same resource then "User B can read it" proves nothing about User B — the
  resource is public. The peer verdicts are demoted to inconclusive and the run reports
  the one thing that is true, instead of six findings about a public page.
- **Responses are compared structurally, not byte for byte.** JSON bodies reduce to
  their key shape with array indices collapsed; other bodies to a token set with
  digits, hashes and opaque ids masked. Two invoices for two customers are the same
  *resource*; a rotating CSRF token is not a different page.
- **Declared object identifiers decide the ambiguous cases both ways.** An id belonging
  to the owner, found in somebody else's response, raises a finding to Firm — it is a
  fact about the bytes, not a score. The mirror image exonerates: a response carrying
  the *caller's own* ids is the application scoping a lookup to the session, and
  `GET /profile` stops being reported as a violation despite scoring 1.00 similarity.
- **Confidence is earned.** A similarity match is Tentative; a declared identifier makes
  it Firm; only `--verify`, which replays each violation a second time, produces
  Confirmed. Nothing is emitted at Critical — blast radius is a tester's judgement.
- **Every replay is recorded as the identity that sent it**, with `origin = authz` and
  a parent pointing at the request it derived from, so a finding cites two request ids
  somebody else can open months later.
- **`hexora identity`**: add, list and remove the principals a project tests as.
  Credentials are read from an environment variable or a file, never from an argument —
  `ps` and shell history both capture those — and are never printed back.
- **`hexora scope`**: the project scope is now persisted (`project.scope_json`) and read
  by every command. It had been accepted at the API boundary and thrown away, which
  meant no automated subsystem could run twice in a row. An authorization matrix is
  automated traffic, so it refuses to start against a host nobody declared, once,
  before it sends anything.
- **History says who a request was sent as.** The `requests.identity_id` column has
  been in the schema since M0 and nothing wrote it; authorization replays now do, and
  both `hexora history` and the desktop table show the label beside the row. A replay
  the project cannot attribute is not evidence.
- The engine RPC contract goes to version 2: `HistoryRow` gained the identity field.

- A state-changing method is refused without `--yes`, naming how many times the request
  would be sent. Hexora will still replay `DELETE` if told to — a tool that quietly
  declined to test destructive endpoints would be hiding the worst authorization bugs
  there are.

### Added — M12.2, the findings store

- **Findings are written into the project.** `hexora authz` files what it finds; the
  `findings` and `finding_evidence` tables have been in the schema since M0 with
  nothing writing to them. A conclusion that lives only in a terminal cannot be cited
  six months later, which is the entire point of keeping a project file.
- **Storage enforces invariant 6.** `FindingStore::save` refuses anything
  `Finding::validate` rejects, so a claim above `Reported` with no evidence cannot
  reach a report by taking the storage route around the verification engine. A detector
  with a bug gets an error, not a row.
- **Re-running a test updates the claim instead of duplicating it.** Findings are keyed
  on what they claim — target, title and location — not on a generated id. Two
  consequences are deliberate: triage survives, so a finding marked `false_positive`
  stays marked; and confidence follows the evidence currently attached in *both*
  directions, so a re-run without `--verify` brings a `Confirmed` finding back down to
  what the stored comparison actually supports.
- **`hexora findings`** lists them worst first — severity, then how firmly established,
  which is the order they get worked through rather than the order they were found.
  `--show` prints one in full with its evidence, `--triage … --status` records a human
  judgement, and `--actionable` hides what is still only a lead. Listing is keyset-paged
  on the same ordering, so a page boundary never repeats or skips a row.
- **`hexora authz --no-save`** reports without writing, for a run somebody wants to look
  at before committing to.
- Findings name the target the base request was actually sent to (`TrafficStore::target_of`),
  rather than a fresh id that would point at a target the project has never heard of.

### Fixed

- **`hexora repeat --diff` printed nothing when the two responses matched.** It reads
  as a command that failed, and "identical" is the whole answer for an authorization
  comparison — two principals served byte-for-byte the same response *is* the finding.
  The headline is now always printed. M12's reproduction steps tell a reader to run
  exactly this command, which is how it surfaced.
- **The finding store deadlocked on a single-connection pool.** Reading a finding held
  a pooled connection while asking for a second one to load its evidence, which is a
  deadlock rather than a slow query on every in-memory project. Evidence now loads on
  the caller's connection.

### Added — M12.3, the report

- **`hexora report`** turns a project into a document somebody can be handed: Markdown
  for a ticket or a repository, a self-contained HTML page for a client, JSON for
  whatever consumes it next. All three render the same model, so the page and the file
  cannot claim different things.
- **Every claim carries its exchange.** Evidence is resolved against the project's
  traffic and the request and response are quoted in full — not an id the reader would
  have to go and look up. A citation the project can no longer resolve is printed as
  *missing*, with the reason, because a reference that silently resolves to nothing
  leaves a reader believing the claim was checkable.
- **A report says what was tested, not only what was found.** Scope, identities,
  exchange and target counts sit above the findings, and a clean run says so in those
  terms rather than implying a clean bill of health.
- **Leads never mix with established issues.** Anything below `Firm` goes in its own
  section after the findings, labelled unverified. `--actionable` drops them entirely,
  and the count still appears under "what this report leaves out" — as do findings
  triaged as false positives or duplicates. Each of those is a human decision a
  reviewer is entitled to ask about, so it is counted rather than hidden.
- **Credentials do not travel.** Sensitive headers are redacted by default and the
  report says so, printing the length of what was removed so a redacted header cannot
  be mistaken for an absent one. `--show-secrets` opts out and warns that the file is
  now a secret rather than a deliverable.
- **The HTML page escapes everything and loads nothing.** A report quotes bodies from
  the application that was being attacked; some findings exist precisely because that
  application reflects input. No script, no external stylesheet, no font from a CDN —
  a document that phoned home on open would leak when and where it was read.
- **The Markdown fence outgrows the body it quotes.** A response containing three
  backticks would otherwise close the block early and lay out the rest of the document.
- A render changes nothing: no traffic is sent, no triage state is touched, and running
  it twice on an unchanged project produces the same bytes, so a draft and a retest can
  be diffed.

### Changed

- `hexora report` was exercised end to end against a local application with a
  deliberate IDOR: proxy capture → `hexora authz --verify` → `hexora findings` →
  Markdown and HTML. The document names the leaked account id, quotes both sides of the
  comparison, keeps the public endpoint as a separate unverified lead, and carries no
  credential.

### Added — M12.4, the desktop workflow

- **The window does the whole loop.** Six tabs — Setup, History, Repeater,
  Authorization, Findings, Report — over the same crates the CLI calls. Until now
  three of the four things the engine does best were reachable only from a terminal,
  which made the desktop client look like a proxy with a repeater bolted on.
- **Scope and identities are declared in Setup.** An empty scope is why an
  authorization matrix refuses to run, so the card says that rather than leaving a
  run to fail. Adding a rule shows the whole scope back: widening it is a decision
  somebody may have to justify later.
- **The authorization matrix runs from the window.** Pick a request in History, press
  *Test authorization*, choose whose request it is, and every other identity is
  replayed against it. The anonymous control, verification, saving and the
  state-changing confirmation are all switches with their consequences written next to
  them. Clicking a cell opens that replay in History.
- **The findings list answers "why is this a finding?".** Worst first, leads visibly
  apart from established issues, and one finding opens in full: impact, remediation,
  reproduction, and every piece of evidence as a button that opens the exact exchange
  it rests on. Triage is one click and survives the test being re-run.
- **The report is previewed before it is written.** Format, severity floor, leads,
  credentials and title, then the document itself — byte-for-byte what lands on disk.
  Even the HTML is shown as text: rendering it would mean executing markup that came
  from the application under test.
- **Twelve IPC commands** (`scope_*`, `identities_list`, `identity_*`, `authz_run`,
  `findings_*`, `report_render`), the contract version bumped to 3 so an old interface
  and a new engine refuse each other rather than misreading messages.
- **`IdentityView` has no field that could carry a credential.** The frontend gets the
  *kind* — bearer, cookie, none — because a value that reaches a renderer process
  reaches a devtools console, a screenshot and a crash report. A test asserts it.
  Adding an identity prefers an environment variable read in-process; the typed-value
  route says at the point of entry that it crosses the IPC boundary.

### Fixed

- **The window has been looked at.** Every tab, on Windows, with a real project open —
  which is how these were found: a bare `.toolbar input { width: 320px }` was
  stretching the findings filter checkbox across a third of the screen, and a `select`
  in a card ran the full 1600px width of the window.
- **The documented way to run the desktop shell did not work.** A debug Tauri build
  loads `devUrl`, not `frontendDist`, so `pnpm build && cargo run -p hexora-desktop`
  opened a window showing `ERR_CONNECTION_REFUSED` — indistinguishable, to anyone
  trying Hexora for the first time, from a broken application. `STATUS.md` and
  `docs/development.md` now say to run the dev server alongside it, and why.

### Added — M12.5, constructed cross-identity attempts

A replay answers "can User B reach this URL?". It cannot answer "can User B reach
**User A's** invoice?" when the only captured traffic is User B asking for their own —
the request that would answer it has never existed. Hexora now builds it.

- **`hexora object add`** declares which identifiers are objects and who owns them
  (`core/types/src/object.rs`, `core/storage/src/objects.rs`). Given a request the
  value appears in, the location is *discovered* — path segment, query parameter,
  header or byte offset in the body — so nobody counts path segments by hand.
  Declaring sends nothing: it is data entry, and running the test is a separate act.
- **`hexora authz --construct`** substitutes a declared identifier into the object
  slot of a captured request and sends the result as each identity. `--max-attempts`
  bounds it; the default is 12 and the ceiling is 100.
- **Nothing is guessed.** Both facts that make this possible — which value is an
  object, and whose it is — are declared by a human. A value that merely looks like an
  identifier is not one, and a tool that guessed would send traffic at an endpoint on
  the strength of that guess and then reason about the answer as if it meant
  something.
- **A 200 is not a finding.** Each sender first sends the request unmodified, so there
  is a control: the document that identity gets when the application is working. A
  response is then a violation when it carries the owner's *other* identifiers (the
  caller never sent them), or quotes the substituted one inside a document shaped like
  the caller's own. A response carrying the caller's own data clears the endpoint. An
  error page quoting its input, a document of the right shape with nothing
  identifiable in it, and a bare 200 all produce a lead or nothing at all.
- **The substitution is recorded, not inferred.** `constructed_attempts` holds the
  source request, the declaration, the sender, the location, and both values. The
  generated request also carries `parent_id`, so `hexora repeat --tree` and the
  desktop history answer "where did this come from?" without knowing anything about
  declarations.
- **The substitution touches nothing else.** Path segments are encoded so an
  identifier containing `/` or `..` cannot walk somewhere else; query values are
  encoded so one cannot add a parameter; an existing `%XX` escape is preserved rather
  than double-encoded; the body is edited byte-for-byte with no JSON round trip, so
  duplicate keys and whitespace survive; `Content-Length` is left exactly as the
  tester had it. Credential headers are never an object location, in either direction.
- **Declared values are validated where they enter and where they are used.** Control
  characters are refused — a value carrying CRLF spliced into a header is request
  splitting inside a tool the tester trusts — as is anything over 512 bytes.
- **Matching is byte-exact.** No Unicode normalization and no decoding to a fixed
  point: two spellings of the same character are two different identifiers to an
  application, and which one it accepts may be the finding.
- **The desktop window** declares objects, runs constructed attempts, and shows each
  substitution next to what it returned. IPC contract 4.
- **Security invariant 9** — a generated request says where it came from, and changes
  only what it claims to.

Exercised end to end against a local application with a deliberate IDOR *and* a
correctly built version of the same endpoint: the first produced a High/Confirmed
finding naming the substitution, the second produced nothing at all.

### Added — M13.2, the passive scanner

The first scanner, built on M13.1 and deliberately boring: many observations, a few
hypotheses, fewer findings — and every finding a lead.

**It cannot send, and that is the signature.**

```rust
pub fn scan(project: &Project, selection: &Selection) -> Result<Summary>
```

No transport, no `Lab`, nothing in a `Project` that reaches a network. "The passive
scanner makes no requests" is a property of what the function was given rather than a
rule somebody keeps — which is also why the test for it asserts a full pass runs
rather than asserting a mock went uncalled. There is no mock, because there is no
parameter.

**Three products, and only one of them is a finding.**

```text
Observation (informational)   "Server: nginx/1.24.0"          listed, never filed
Observation (reportable)      "no HSTS on an HTTPS response"  → a lead
Hypothesis                    "the origin may be reflected"   → stops here
```

A check does **not** choose its own verification. The pass applies
`Verification::Observed` to every observation, whose ceiling is `Reported` — not
actionable, a lead. So no passive check can state anything more firmly than any other,
by construction rather than by policy.

Origin reflection is the worked example of the third row: one exchange showing
`Access-Control-Allow-Origin` equal to the request's `Origin` is equally consistent
with a server that reflects anything and one that allows exactly that origin. Telling
them apart needs a second request with a different `Origin`, which this pass does not
make — so it produces a hypothesis and no finding at all.

**Six checks**, grouped by the question they answer:

```text
headers.security      HSTS, CSP, framing, nosniff, Referrer-Policy, Permissions-Policy
cookies.security      Secure, HttpOnly, SameSite — in the context of the cookie
cors.configuration    who may read responses, and with whose credentials
disclosure.headers    Server, X-Powered-By, Via — informational, never filed
cache.sensitive       cache directives on authenticated responses
tls.observations      what the recorded handshake showed, without making a new one
```

Applicability is decided per condition rather than by listing header names: HSTS is
asked of HTTPS responses only, CSP and framing of HTML documents only, cache
directives of authenticated successful responses with content only. A JSON API
response therefore produces one observation where a naive check would produce five.

**Deduplication.** Five hundred endpoints missing one header is one finding citing
three exchanges, with the count. The fingerprint is detector, host and condition —
never a URL, and never a value.

**`hexora scan passive <project>`**, with `--detector`, `--host`, `--since`,
`--limit`, `--everything` and `--no-save`. It prints exchanges analysed, detectors
executed, observations, hypotheses and findings as separate counts, and prints a row
for every detector including the ones that saw nothing.

**`hexora detectors`** now lists mode (passive/active), version, and what each check
can produce. A **Scan** tab in the desktop window runs the pass and opens the exchange
behind any result.

**A scan run is recorded** (migration 7): which detectors ran, at which versions, over
how much traffic, and what each produced — including zero. That is the row M12.8's
`WhyGone::SourceSilent` was shrugging about, and `WhyGone::DetectorChanged` now exists
because of it: a claim that stopped appearing after a check was rewritten reads as
inconclusive rather than as a fix. Findings from a scanner carry the detector and
version on the row, and the report prints them.

**Out-of-scope traffic is not analysed by default.** The proxy records everything it
sees, so a project holds the tester's own browsing; the pass reads in-scope traffic,
counts what it skipped, and says so.

### Fixed

- **A session cookie could reach scanner output through a retained exchange.** Request
  credential headers were redacted; `Set-Cookie` response headers were not, and a
  performance change that began holding one exchange per grouped observation carried
  the value into everything downstream. `Set-Cookie` values are now replaced at
  assembly — name and attributes kept — so no check, observation, finding, report or
  IPC payload can carry one. Caught by the regression test written for exactly this,
  which is the reason it was written.
- **A CORS reflection check comparing header values as lossy text** could have matched
  two different byte strings that decode to the same replacement characters. The one
  comparison where the bytes are attacker-controlled now compares bytes.

### Added — M13.1, the verification framework

Everything after this is a scanner, and a scanner is only worth having if a detector's
suspicion and a finding's claim are different things that cannot be confused. They are
now different **types**, and the compiler enforces it.

```text
Detector  →  Hypothesis   ──✗──▶  FindingStore
                 │
             Verifier  (a controlled experiment, through a Lab)
                 ▼
            Verification  ──▶  Verified  ──✓──▶  FindingStore
```

**The rule is the signature.** `FindingStore::save` and `record` take a `Verified`,
and the only way to get one is `Verified::conclude`, which requires a `Verification`.
There is no `From<Hypothesis>`, no `into_finding`, no constructor that takes a bare
`Finding`. A check that is merely suspicious does not get an error when it tries to
record a claim — the call does not compile. Security invariant 6 moved from a runtime
check into the type system; `Finding::validate` stays wired up inside `conclude` as
the backstop for a verifier that returns support with nothing behind it.

**Confidence is derived, never chosen.** `Verification::confidence` is a total
function from what the experiment showed to what may be claimed:

```text
Reproduced                  the effect happened again        → Confirmed
Supported { Distinctive }   hard to explain another way      → Firm
Supported { Consistent }    consistent, other causes too     → Tentative
Observed                    nothing to experiment on         → Reported (a lead)
Refuted / Inconclusive      —                                → no finding at all
```

`Observed` is the rung a passive check climbs: a missing `Strict-Transport-Security`
header is a fact, not a hypothesis, and there is no second send that would establish
it more firmly. Its ceiling is `Reported`, which is not actionable — it reaches a
report as a lead, never as a claimed vulnerability.

**A verifier gets a `Lab`, not a transport.** One method — *send this request as this
principal* — backed by the repeater, so scope enforcement, attribution and storage as
evidence are the lab's business and a check cannot forget any of them. A detector's
`examine` is synchronous and receives no lab at all, which puts the passive/active
distinction in the signature instead of a comment.

**M12.1 and M12.5 were rewritten onto it**, so the framework has a real user rather
than a hypothetical one:

- `MatrixDetector` raises a hypothesis per violating cell; `ConstructionDetector` does
  the same for constructed attempts.
- `ReplayVerifier` runs the second experiment — what `--verify` always did — through a
  `Lab`, and returns a `Verification` rather than setting a bool.
- `AuthzTester::assess` is run-detect-verify in one call. `Cell::reproduced: bool`
  became `Cell::verification: Option<Verification>`, because "it did not reproduce"
  and "nothing re-examined it" were the same missing tag in the matrix and are not the
  same fact.
- An out-of-scope or unrunnable second experiment is `Inconclusive`, not a failure and
  not a quiet pass.

**`hexora detectors`** lists what this build checks for, each check's version, and
**whether it sends** — the difference between something safe to run against production
at 3pm and something that is not. The registry is assembled from the crates the binary
links rather than discovered; there is no plugin mechanism and the docs say so.

### Changed

- **A violation that does not reproduce is now capped at a lead.** It used to keep
  whatever confidence the first result earned, with a note attached; a `Firm` claim
  could therefore rest on two experiments that disagreed. Two experiments that
  disagree cannot be "hard to explain any other way", so the claim comes out
  `Tentative` and the note says it was seen once and not again. The information is
  kept; the certainty is not.
- `ScopeRule` now implements `Display`, and `Cell` carries a verification rather than
  a bool. The desktop matrix shows which it was.

### Added — M12.8, engagement snapshots

A consultant tests in March, the client fixes through April, the consultant comes back
in May — and the only question in May is *what changed*. Every store in a project is
live: findings are refreshed in place when a test is re-run, candidates re-scored,
scope edited. Without a record of what was true in March there is nothing to compare
against.

**A snapshot copies rather than references.** Pointing at `findings.id` would let a
re-run rewrite the project's own past. It records the claims as they stood, their
severity, confidence and triage state, the scope, the identities and the declared
objects. It does not copy traffic: bodies are the largest thing in a project by orders
of magnitude, and a snapshot exists to be diffed, not restored.

Immutable structurally rather than by convention — `SnapshotStore` has no update
method, which is what makes the summary columns on the row safe: they are computed
from the contents at insert time and nothing can change one without the other.

**It never says *fixed*.** A finding is what a test produced; its absence from a later
snapshot is the absence of a result. `hexora snapshot diff` reports the claim as
**gone**, with a reason, and only one of the three reasons is about the application:

```text
tool changed    the two snapshots were taken by different builds
source silent   nothing from that check appears in the later snapshot, and Hexora
                cannot tell "ran and found nothing" from "never ran"
not reproduced  the same build ran, the same check raised other claims, and this one
                did not come back — which is still not proof it is fixed
```

New security invariant 11 states this with its tests. A tool-version change is
reported first, because it makes the other two unsafe to rely on.

**A claim nobody re-tested is reported as such.** Found by running an actual retest:
the demo application was repaired, the authorization matrix re-run, it raised nothing —
and the comparison said only "+3 exchanges" while the old `medium/confirmed` claim sat
there looking like a current result. A run that produces no claim never writes to the
claim it did not produce, so a snapshot records when each claim was last written to,
and one nothing has touched is listed under *standing, but nothing re-tested them*
rather than counted as unchanged. Claims that **were** re-tested and came back the same
are listed separately, because "re-tested and still stands" is a result and reads very
differently from silence.

**Also compared:** scope rules added and removed (a host that left scope stopped being
tested, and the output says so), identities, declared objects, and the exchange,
suggestion and finding counts.

- `hexora snapshot take|list|show|diff|remove`. With one id, `diff` compares a
  snapshot with the project as it stands — the comparison a retest actually asks, and
  it does not require saving a second snapshot first.
- A **Snapshots** tab in the desktop window with the same comparison.
- Credentials never reach a snapshot: an identity is recorded as its label and
  privilege, field by field rather than by copying the struct.
- Migration 6. `Contents` is stored as one JSON document and carries
  `#[serde(default)]`, so a snapshot taken by an older build stays readable when a
  later one adds a field — with the default chosen to be the cautious answer, because
  that is what an old snapshot silently supplies.

Verified end to end against the IDOR demo: captured and tested against the vulnerable
build, snapshotted, restarted on a repaired build, re-ran the matrix (which reported
nothing), and read the comparison — then re-ran against the vulnerable build again and
watched the same claim move to *re-tested and unchanged*.

### Fixed

- **The window rendered a port-restricted scope rule as though it covered every
  port.** The CLI and the desktop each had their own copy of "render a `ScopeRule` as a
  line" and they had drifted; the desktop's dropped the port list. There is now one
  `Display` impl on the type and both call it.

### Added — M12.7, persisted identifier suggestions

Every object identifier was declared by hand, so constructed authorization testing was
exactly as broad as what somebody typed. Hexora now reads a project's own traffic and
*offers* the values that behave like object identifiers — and stops there, because the
gap between "this looks like an id" and "this id belongs to User A" is the gap the
whole evidence model stands on.

**A suggestion is a third thing, kept apart from the two that already existed.**

```text
IdentifierCandidate   "acct-1000 varies where an object id would, in 6 requests"
        │  a human decides
        ▼
ObjectDeclaration     "acct-1000 is an account"
        │  a human decides
        ▼
ownership             "…belonging to User A"
```

`IdentifierCandidate` has no owner field and `identifier_candidates` has no owner
column — not as a convention but as an absence, so there is nowhere for an inferred
owner to be written. Accepting a suggestion records that it is an identifier and
creates no declaration. New security invariant 10 states this, with the tests that
enforce it.

**Suggestions are persisted, because an engagement is not one sitting.** Traffic is
captured on Monday and worked on Friday. Migration 5 adds the candidates and their
observations; re-analysis refreshes a proposed candidate's signals in place and leaves
a decided one alone, the same way re-running a test keeps triage.

**The score is an argument, not a number.** A confidence of `0.87` cannot be
disagreed with. Each candidate carries the signed signals behind it, so `hexora
identifiers --show` and the window print the reasoning and its total:

```text
 +12  varies in place            2 different values seen in this place
  +8  resource-like path         follows /accounts/ in the path
  +5  appears in response        came back in 3 responses
 +25  total
```

Signals that argue *against* carry negative weights and are printed with their sign: a
common paging name (`?page=`, `?offset=`), a very short value, a plain word in a path.

**Evidence, not appearance.** A value is offered because it *varies where an identifier
would*, against a path that is holding still — never because it looks numeric. So
`/api/v2/accounts/1000` never suggests `v2`, and `/status` against `/profile` suggests
neither, because a path shape with nothing constant in it is an endpoint varying rather
than an identifier. `?page=2` varies in a resource-like path and is argued down by
name.

**Observed bytes are preserved exactly.** `1000`, `"1000"` and `%31%30%30%30` are three
candidates. Normalising them would let a tester replay a spelling the application never
received. Where a value sits is part of what it is, so the same value in a path segment
and in a query parameter is two rows — and each row names the endpoint shape it was
seen in (`path segment 1 of /accounts/{}`), because an index alone does not tell two
rows apart.

**It cannot send.** `suggest::analyze(&TrafficStore, &ObjectStore, &CandidateStore)`
takes no transport at all, mutates no captured request or response, and creates no
finding. Reading a project is safe at any point in an engagement, including after the
client has gone home.

- `hexora identifiers <project> [--analyze] [--status <s>] [--show <id>] [--accept
  <id>] [--reject <id>] [--json]`.
- An **Identifiers** tab in the desktop window: the suggestions, their reasons on
  demand, and explicit Accept / Reject. It says in three places that accepting names no
  owner, because that is the sentence the milestone turns on.
- Candidates whose source traffic has since been deleted are still listed, with how
  many of their observations are still in the project.

Verified end to end against the existing IDOR demo: seven captured exchanges produced
four suggestions, all four the account ids and none of the endpoint names; the
suggestions survived reopening the project in a separate process; accepting one in the
window declared no object and named no identity; and the M12.5 constructed-attempt
behaviour is unchanged.

### Added — M12.6, wire-exact traffic and raw request mode

Two pieces of debt, both about the same thing: a security tool must not quietly change
the bytes it is supposed to be showing you.

**Encoded response bodies are kept.** The transport now hands back the body twice — the
transfer-decoded bytes as they arrived, and the application bytes they decode to — and
both are stored. `hexora history --body --wire` returns the gzip stream; `--body`
returns the JSON inside it. `encoded_body` was written as NULL since M3, which meant
`--wire` silently returned the decoded body for exactly the responses where the
distinction mattered.

- The boundary is named and documented (`docs/architecture.md`): **raw bytes** →
  **transfer-decoded** (framing removed, `Content-Encoding` untouched) →
  **content-decoded**. Request-smuggling research is about the first step and
  content-encoding research about the second; a single "wire body" would be useless
  for both.
- No second buffer where there is nothing to keep: when no coding was reversed the
  encoded form is *absent* rather than a duplicate, and the read path falls back.
  `Bytes` is reference-counted, so keeping the compressed form costs no copy.
- Both forms stay bounded — the arriving bytes by `max_body_bytes`, the expansion by
  `max_decompressed_bytes` and the ratio check — and a decompression bomb still
  truncates rather than erroring, so what arrived before the cut is still evidence.
- `content_encoding` records what was *actually reversed*, not what the header
  announced. A truncated body is never decoded, and a row saying otherwise would
  describe a transformation nobody performed.

**Requests can be sent as bytes.** `RequestSource::{Structured, Raw}` makes explicit
what used to be implicit. A structured request is serialized from the message model,
which normalizes line endings and can add framing headers. A raw request is written
byte for byte:

- `hexora repeat --raw`, and a Structured/Raw switch in the desktop repeater. Nothing
  changes mode on its own: a request captured raw reloads raw, and converting is an
  explicit operation with a visible result.
- Bare LF stays bare LF, header casing and order survive, duplicates survive, a
  `Content-Length` that disagrees with the body is sent wrong, and non-UTF-8 and NUL
  bytes pass through. Proven against a real socket by asserting what the server
  received, not what Hexora believed it sent.
- **Raw mode does not bypass scope.** `ScopeGuard::send_raw` decides on the service the
  request is addressed to and the target read out of its request line; an absolute-form
  line contributes its path, never its authority, so rewriting it cannot point the
  connection somewhere unscoped. A raw request whose request line cannot be read is
  refused rather than sent.
- An identity's credential cannot be applied to a raw request — doing so would mean
  rewriting a header block the tester wrote deliberately. The error says so and says
  what to do instead.
- The bytes are stored content-addressed (`requests.raw_hash`), so re-sending a raw
  request while fuzzing one header stores the variants rather than copies of
  everything that did not change. Provenance is the existing one: `parent_id`,
  identity, origin — `repeat --tree` answers "where did this come from?" unchanged.
- Migration 4 is additive and backward compatible: rows written before raw mode
  existed are structured by definition, and the column default says so.

### Fixed

- **The repeater's own documentation claimed byte preservation it did not have.** The
  panel said "what is typed is what is sent, including a `Content-Length` that
  disagrees with the body" while structured editing re-serialized the message. It now
  describes what each mode actually promises.
- **The history detail pane showed a `Host` header that was never sent.** The
  structured *view* of a raw request was built with `HttpRequest::get`, which adds one
  from the service — so a request deliberately sent without a `Host` displayed with
  one. Found by looking at the window.
- **The window did not mark raw rows** although the CLI did. Also found by looking.

### Not implemented

There are no attack chains. Object identifiers must be declared by hand: Hexora does
not suggest which values in a request look like one, and until it does, constructed
testing is only as broad as what a tester has told it. Credentials are stored in
cleartext; encryption under a project passphrase is still only in the threat model.

The macOS and Linux trust-store paths are written, unit-tested and type-checked but
have not been run on those platforms; only Windows has been verified end to end. The
desktop UI has been inspected on Windows at one window size, with a real project open;
it has not been seen on macOS, on Linux, at a small window, or on a high-density
display. The HTML report is shown in the window as text rather than rendered, and
nobody has opened one in a browser and said it reads correctly. Connection reuse and
redirects return `NotImplemented` naming the milestone that will provide them.

Raw mode is HTTP/1.x request bytes only: there is no raw frame injection for HTTP/2 or
HTTP/3, and no raw WebSocket frames. Those want wire models of their own rather than a
byte buffer. See `docs/roadmap.md`.
