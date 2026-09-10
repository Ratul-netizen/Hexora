# Hexora

**The Modern Offensive Security Workbench**

Hexora is a web and API security testing platform for **authorized** penetration
testing, application security testing and security research. It is built as a fast
native core in Rust, with a desktop client (Tauri + React), a headless CLI that shares
the same engine, and an extension system with a real permission model.

> ⚠️ **For authorized security testing only.** Using Hexora against systems you do not
> own or have written permission to test is illegal in most jurisdictions.

---

## Status: M0 — architecture foundation

Hexora **cannot yet be used as a proxy.** This repository currently contains a tested
foundation, not a usable tool. It is honest about that everywhere: unimplemented paths
return `NotImplemented` rather than empty results, and `hexora --help` lists only
commands that genuinely work.

| Area | Status |
| ---- | ------ |
| Domain model (HTTP messages, scope, identities, findings, limits, secrets) | **IMPLEMENTED** |
| Project storage: SQLite metadata + content-addressed blob store, migrations | **IMPLEMENTED** |
| Scope enforcement at the transport boundary | **IMPLEMENTED** |
| Extension permission model | **IMPLEMENTED** |
| AI tool-permission gate | **IMPLEMENTED** |
| CLI (`project init`, `project info`, `version`) | **IMPLEMENTED** |
| Desktop shell (status window) | **IMPLEMENTED** |
| HTTP engine — actually sending requests | **PLANNED (M1)** |
| Proxy, TLS interception | **PLANNED (M2)** |
| Traffic history, Repeater | **PLANNED (M3–M4)** |
| Scanner, Fuzzer, Workflows, OAST, AI, Burp compatibility | **PLANNED** |

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

Requires Rust 1.85+, Node 20+, pnpm 9+.

```bash
# Core crates and CLI
cargo test --workspace --exclude hexora-desktop
cargo run -p hexora-cli -- --help

# Frontend
pnpm -C frontend install
pnpm -C frontend build
```

The desktop shell additionally needs [Tauri's system
dependencies](https://tauri.app/start/prerequisites/). Full instructions:
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
