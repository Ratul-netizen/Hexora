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

### Not implemented

The macOS and Linux trust-store paths are written and unit-tested but have not been run
on those platforms; only Windows has been verified end to end. Connection reuse and
redirects return `NotImplemented` naming the milestone that will provide them. The traffic store keeps both body forms, but the transport still returns
only the decoded bytes, so `encoded_body` is NULL in practice — the remaining half of
the M1.5 gap. A repeater request edited to bare-LF line endings is re-serialized with
CRLF, and says so. See `docs/roadmap.md`.
