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

### Windows: MSVC build tools, and a Git Bash trap

The `x86_64-pc-windows-msvc` target needs a C++ linker:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override `
  "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools"
```

**Do not build from Git Bash.** Git for Windows ships GNU coreutils at
`/usr/bin/link.exe`, which shadows MSVC's `link.exe` on `PATH`. Cargo then hands object
files to the wrong program and you get a baffling error that looks nothing like a
toolchain problem:

```text
error: linking with `link.exe` failed: exit code: 1
  = note: link: extra operand '....rcgu.o'
          Try 'link --help' for more information.
note: you may need to install Visual Studio build tools with the "C++ build tools" workload
```

That `Try 'link --help'` line is coreutils talking. The suggested fix is a red herring:
the build tools may already be installed and simply not be the `link.exe` that was
found.

Build from **PowerShell** or a **Developer Command Prompt** instead. If you must use
Git Bash, load the MSVC environment first so its `bin` directory precedes `/usr/bin`:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo test --workspace
```

CI is unaffected: the `windows-latest` runner has Visual Studio installed and runs
steps in PowerShell, where coreutils is not on `PATH`.

### Toolchain policy

Two separate things, easy to conflate:

| File | Meaning |
| ---- | ------- |
| `rust-toolchain.toml` | The **exact** compiler used for development and CI. Pinned, so every machine agrees. |
| `rust-version` in `Cargo.toml` | The **minimum** compiler Hexora claims to support (MSRV). |

They are deliberately different values. The MSRV is `1.88`, which is not a preference —
it is the floor imposed by the dependency graph (`plist`, `serde_with`, `time`,
`darling` and the ICU crates, pulled in via Tauri and `url`, all declare 1.88). The
development toolchain is pinned to a specific recent stable.

Do not raise the MSRV to match whatever compiler you happen to have. Raise it only when
a dependency or a language feature genuinely requires it, and say which in the commit.

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

`frontend/pnpm-workspace.yaml` exists only to allow esbuild's postinstall script. pnpm
10 and newer refuse dependency build scripts by default, and esbuild's is what unpacks
its platform binary — without the allowance `pnpm build` fails on a fresh checkout with
an error that says nothing about the cause.

Running the CLI:

```bash
cargo run -p hexora-cli -- --help
cargo run -p hexora-cli -- project init ./scratch/demo
cargo run -p hexora-cli -- project info ./scratch/demo --json
```

Running the desktop shell (needs Tauri prerequisites):

```bash
pnpm -C frontend install
pnpm -C frontend dev            # leave this running
cargo run -p hexora-desktop     # in a second terminal
```

**A debug build loads the dev server, not `frontend/dist`.** `tauri.conf.json` sets
both `devUrl` and `frontendDist`, and a debug binary uses the first — so
`pnpm build && cargo run -p hexora-desktop` opens a window showing
`ERR_CONNECTION_REFUSED`, which looks like a broken application rather than a missing
dev server. Either run the dev server alongside it, as above, or build in release
(`cargo tauri build`), which embeds `dist`.

## Structured and raw requests

Two ways to send, and they promise different things:

```bash
# Serialized from the message model: header order, casing and duplicates survive, but
# bare LF becomes CRLF and missing framing headers may be added.
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --edit

# Written byte for byte. Nothing is parsed on the way out.
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --raw --edit
```

A request captured in raw mode reloads in raw mode without the flag — the mode is a
property of the stored request, not of the command. `hexora history` marks those rows
`[raw]`, and the desktop repeater has a Structured/Raw switch.

Raw mode does not bypass scope: the destination is the service the request is addressed
to, and the path comes from reading the request line. A raw request whose first line
cannot be read is refused rather than sent.

## Response bodies exist twice

```bash
hexora history ./scratch/demo --body req_01a08b…          # content-decoded: the JSON
hexora history ./scratch/demo --body req_01a08b… --wire   # transfer-decoded: the gzip
```

The names are exact and are defined in [`architecture.md`](architecture.md): *raw
bytes* → *transfer-decoded* (framing removed, `Content-Encoding` untouched) →
*content-decoded*. When no coding was reversed there is only one form and `--wire`
returns it.

## Platform-gated code is only checked by CI

Anything behind `#[cfg(windows)]`, `#[cfg(target_os = "macos")]` or
`#[cfg(not(any(...)))]` is invisible to the local gate: your compiler only builds the
branch for the machine you are on. `core/proxy/src/trust.rs` has three such branches,
and a dead-code warning in the Linux one passed every local check and failed CI.

Cross-checking with `cargo check --target` does not work here either — `ring` needs a C
toolchain for the target, which a Windows machine does not have.

What does work, when you have touched a `cfg`-gated path and want to know before
pushing: temporarily flip the gates so the branch you care about compiles natively.

```rust
// Disable the branch for this machine...
#[cfg(all(windows, target_os = "none"))]
fn platform_install(..)

// ...and enable the one you want checked in its place.
#[cfg(windows)]
fn platform_install(..)
```

Then `cargo clippy -p <crate> --all-targets -- -D warnings`, and revert. It takes a
minute and catches exactly the class of failure that otherwise costs a CI round trip.

Otherwise: push and read the CI result. The matrix covers Linux, macOS and Windows for
that reason.

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
