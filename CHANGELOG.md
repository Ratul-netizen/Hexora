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

### Not implemented

The desktop UI shows neither the authorization matrix, the findings list nor the
report — half of what the engine can do is reachable only from a terminal. There are
no attack chains. The matrix replays a request verbatim — substituting one identity's object identifiers into
another's request, to *construct* cross-identity attempts rather than only replaying
captured ones, is not implemented. Credentials are stored in cleartext; encryption
under a project passphrase is still only in the threat model.

The macOS and Linux trust-store paths are written, unit-tested and type-checked but
have not been run on those platforms; only Windows has been verified end to end. The
desktop UI compiles, launches and its logic is unit-tested, but its visual result has
not been inspected — treat the layout as unreviewed. The same applies to the HTML
report: its structure is tested and its escaping is tested, but nobody has opened the
page in a browser and said it reads correctly. Connection reuse and
redirects return `NotImplemented` naming the milestone that will provide them. The traffic store keeps both body forms, but the transport still returns
only the decoded bytes, so `encoded_body` is NULL in practice — the remaining half of
the M1.5 gap. A repeater request edited to bare-LF line endings is re-serialized with
CRLF, and says so. See `docs/roadmap.md`.
