# Changelog

All notable changes to Hexora are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

### Added — M0 Architecture foundation
- Cargo workspace with eleven core crates and three applications.
- Shared domain model (`hexora-types`): request/response, identities, scope, findings,
  structured errors, secret-redacting types.
- Storage abstraction with versioned SQLite migrations (`hexora-storage`).
- Engine trait surfaces for HTTP, proxy, scanner, fuzzer, OAST, workflows, fingerprinting.
- Extension model: manifest, permission set, capability-gated host interface.
- Burp Montoya compatibility layer interfaces and compatibility-matrix format.
- Tauri desktop shell + React/TypeScript frontend scaffold.
- `hexora` CLI skeleton with the milestone-0 command surface.
- GitHub Actions CI: fmt, clippy (deny warnings), test, audit, frontend typecheck/build.
- Documentation: architecture, threat model, roadmap, development guide, M1 plan.
