# Hexora

**The Modern Offensive Security Workbench**

Hexora is a web/API security testing platform for **authorized** penetration testing,
application security testing and security research. It is built as a fast native core
(Rust) with a desktop client (Tauri + React), a headless CLI, and a sandboxed
extension system.

> ⚠️ Hexora is for authorized security testing only. Using it against systems you do
> not own or have written permission to test is illegal in most jurisdictions.

## Status

**M0 — architecture foundation.** The workspace, core interfaces, storage schema,
extension/compatibility interfaces, CI and documentation exist. The HTTP engine (M1)
is not implemented yet; see `docs/roadmap.md` for exactly what is and is not real.

Nothing in this repository fakes a working implementation. Unimplemented surfaces
return `HexoraError::NotImplemented` and are listed in `docs/roadmap.md`.

## Layout

| Path                        | Contents |
| --------------------------- | -------- |
| `core/`                     | Rust engine crates (types, http, tls, proxy, storage, scanner, fuzzer, oast, workflows, fingerprint, extensions) |
| `apps/cli`                  | `hexora` headless CLI |
| `apps/desktop`              | Tauri shell + React frontend host |
| `apps/server`               | Team/collaboration server (later milestone) |
| `frontend/`                 | React + TypeScript UI |
| `extensions/sdk`            | TypeScript extension SDK |
| `compatibility/burp-montoya`| Burp Montoya API compatibility layer (independently versioned) |
| `docs/`                     | Architecture, threat model, roadmap, development guide |

## Getting started

Requires Rust 1.85+, Node 20+, pnpm 9+.

```bash
cargo build --workspace
cargo test --workspace
pnpm install
pnpm -C frontend dev
```

See `docs/development.md`.

## License

AGPL-3.0-or-later. Hexora is an independent implementation. It contains no
proprietary code, assets or trademarks from other security products.
