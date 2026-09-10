# Development guide

## Prerequisites

| Tool | Version | Notes |
| ---- | ------- | ----- |
| Rust | 1.85+ | Pinned in `rust-toolchain.toml`; `rustup` installs it automatically |
| Node | 20+ | For the frontend |
| pnpm | 9+ | `corepack enable` |

Installing Rust:

```bash
# Windows
winget install --id Rustlang.Rustup -e

# macOS / Linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Restart your terminal afterwards so `cargo` is on `PATH`.

The desktop shell additionally needs the [Tauri v2 system
dependencies](https://tauri.app/start/prerequisites/) — WebView2 on Windows, WebKitGTK
on Linux, Xcode command-line tools on macOS. The core crates and the CLI build without
them.

## Building and testing

```bash
# Core crates and CLI — no system dependencies needed
cargo test --workspace --exclude hexora-desktop

# Everything, once Tauri's system dependencies are installed
cargo test --workspace

# What CI runs
cargo fmt --all -- --check
cargo clippy --workspace --exclude hexora-desktop --all-targets -- -D warnings
cargo test --workspace --exclude hexora-desktop

# Frontend
pnpm -C frontend install
pnpm -C frontend typecheck
pnpm -C frontend build
```

Running the CLI:

```bash
cargo run -p hexora-cli -- --help
cargo run -p hexora-cli -- project init ./scratch/demo
cargo run -p hexora-cli -- project info ./scratch/demo --json
```

Running the desktop shell (needs Tauri prerequisites):

```bash
pnpm -C frontend install
cargo run -p hexora-desktop
```

## Conventions

### Rust

- `#![forbid(unsafe_code)]` in every crate. A parser bug must not become memory
  corruption.
- `#![warn(missing_docs)]`. Public items are documented.
- Errors are structured types, never stringly-typed. Add a variant rather than
  formatting a message.
- No `unwrap()` outside tests, except where a comment states why the invariant holds.
- Secrets go in `Secret<T>`. If you find yourself calling `.expose()`, keep the value's
  lifetime as short as possible and never hand it to a logger.

### Comments

Comment the *why*, not the *what*. `// increment counter` is noise; a note explaining
that `foreign_keys` is per-connection and off by default is what stops the next person
losing an afternoon.

### Tests

Test names are sentences describing the property under test:

```rust
fn out_of_scope_automated_requests_never_reach_the_transport()
fn a_confident_finding_without_evidence_is_rejected()
```

A failing test should tell you what broke without opening the file.

Write tests that could genuinely fail. A test asserting that a getter returns what a
setter stored proves nothing. Tests worth having here cover: scope bypasses, secret
leakage, resource limits, migration behaviour, permission narrowing, and finding
validation — the things that are invariants rather than conveniences.

Property tests (`proptest`) are used where the input space is large and adversarial —
path normalization and scope matching. Do not add them where a handful of examples say
more.

### Commits

One logical change per commit, present tense, explaining why where it is not obvious.
Reference the milestone (`M1: …`) when the change belongs to one.

## Adding a milestone's worth of code

1. Read [`architecture.md`](architecture.md) and
   [`security-invariants.md`](security-invariants.md) first. Most invariants are
   invariants precisely because the natural way to write the code violates them.
2. If your subsystem sends requests, it takes a `ScopeGuard`-wrapped transport. It does
   not open sockets itself, and it does not check scope itself.
3. If it stores bodies, they go to the blob store, not into a table.
4. If it produces findings, they go through `Finding::validate`.
5. New crates get split out of `core/engine` when there is real code to separate — not
   in advance.

## Not-yet-implemented surfaces

Unfinished work returns `HexoraError::NotImplemented`, which fails loudly. Do not
return empty collections, plausible-looking placeholder data, or `Ok(())` from a path
that does nothing — a security tool that appears to have scanned and found nothing is
worse than one that says it cannot scan yet.

Documentation uses **IMPLEMENTED / IN PROGRESS / PLANNED** labels, and no feature is
described in the present tense before it works.
