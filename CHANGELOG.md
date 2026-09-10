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

### Not implemented

No HTTP request is sent by any code path in this release. See `docs/roadmap.md`.
