# Dependency policy

Hexora is a security tool. Its own supply chain is part of its threat surface, so
dependencies get more scrutiny here than in an ordinary application.

## Rules

1. **Add a dependency because it is needed now**, not because it might be useful later.
   The workspace manifest lists only crates that something currently compiles against.
2. **Prefer the boring, widely-audited crate** over the clever one, especially for
   parsing and cryptography.
3. **Never hand-roll cryptography.** If a task needs crypto and no obvious well-reviewed
   crate exists, that is a signal to change the design, not to write it.
4. **Version bumps need a reason.** "Upgrading for the sake of upgrading" churns the
   lockfile and hides the changes that matter.
5. **`Cargo.lock` is committed.** This is a workspace producing applications, so
   reproducible builds matter more than testing against the newest resolvable graph.

## Audit

CI runs `cargo audit` on every push and pull request.

- **Security advisories fail the build.** They are not negotiable and are not ignored
  to get CI green.
- **Unmaintained-crate warnings do not fail the build.** They almost always arrive
  through a transitive dependency nobody in this repository controls, and a job that is
  permanently red is a job nobody reads. They are still reported, and anything reaching
  code that touches network input or credentials gets treated as a real finding.

## Accepted advisories

Any advisory deliberately accepted must be recorded here, with:

- the advisory ID and a link,
- the dependency and **the path by which it enters the graph** (`cargo tree -i <crate>`),
- what functionality is affected, and whether Hexora reaches the vulnerable code,
- the mitigation, if any,
- why it cannot currently be fixed,
- what would let it be removed.

An empty section below means the audit is genuinely clean, not that nobody looked.

### Currently accepted

_None._

## Secret scanning

CI runs `gitleaks` over the **full history**, not just the tip — a credential deleted
from the current tree is still a credential.

Do not add broad ignore rules to make a finding go away. If a scanner flags test data,
the fix is to make the test data unmistakably fake (see the `TEST_USER` /
`TEST_PASSWORD_NOT_A_SECRET` fixtures in `core/types/src/identity.rs`), not to teach the
scanner to stay quiet.

This applies to plausible-looking values from public specifications too. RFC 7617's
worked Basic-auth example is a real, decodable credential string as far as a scanner is
concerned, and there is no way for a reviewer scrolling a diff to tell it apart from a
live one at a glance. Assert on the decoded value instead of embedding the encoded
literal.

## Notable dependencies

| Crate | Why it is here | Notes |
| ----- | -------------- | ----- |
| `rusqlite` (bundled) | Project metadata store | `bundled` compiles SQLite from source, so behaviour does not vary with whatever SQLite the host happens to ship |
| `r2d2` / `r2d2_sqlite` | Connection pooling | The proxy writes while the UI reads |
| `sha2` | Content addressing for the blob store | Not used for anything security-critical; it is a dedup and integrity key |
| `tauri` | Desktop shell | Drags in the largest part of the dependency graph and sets the MSRV floor |
| `clap` | CLI | |
| `tracing` | Structured logging | Secrets never reach it — see `docs/security-invariants.md`, invariant 2 |

## MSRV

`rust-version` in `Cargo.toml` is the **minimum** supported compiler.
`rust-toolchain.toml` pins the **exact** compiler used for development and CI. They are
different values on purpose; see `docs/development.md`.

The MSRV is currently `1.88`, which is imposed by the dependency graph rather than
chosen: `plist`, `serde_with`, `time`, `darling` and the ICU crates all require it, and
they arrive via Tauri and `url`. Do not raise the MSRV to match whatever compiler is
installed locally.
