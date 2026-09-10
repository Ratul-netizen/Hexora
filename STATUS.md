# Where we are

**Pick-up-anywhere note.** Read this first on a new machine or after a break; it is the
only file that needs to be current for you to resume. Updated at the end of every
milestone.

- **Last updated:** M2.4 (interception hooks)
- **Branch:** `main` · **Remote:** `github.com/Ratul-netizen/Hexora`
- **Toolchain:** Rust 1.98 pinned in `rust-toolchain.toml` · MSRV 1.88

---

## Done

| Milestone | What it gave us |
| --------- | --------------- |
| **M0** — Architecture foundation | Domain model, SQLite storage + content-addressed blob store, migrations, scope enforcement at the transport chokepoint, extension permission model, AI tool gate, CLI + Tauri shells, CI, threat model, security invariants |
| **M1.1** — HTTP/1.x over TCP | Wire-preserving parser (permissive but loud, records smuggling quirks), RFC 9112 §6.3 framing, per-phase timeouts, incremental limits, `hexora send` |
| **M1.2** — TLS | rustls with SNI/ALPN, platform trust store, per-transport verification opt-out, mTLS client certs, TLS observations recorded on the exchange |
| **M1.5** — Chunked + compression | Chunked decoding with desync quirks, trailers, gzip/deflate/brotli with bomb protection enforced while expanding |
| **M1.3** — Streaming bodies | Incremental chunked state machine, `BodyStream` owning the connection, `send_streaming()` returning at the response head |
| **M2.1** — Interception CA | Per-installation CA, per-host leaf minting, RFC 1123 host validation, easy removal |
| **M2.2** — HTTP proxy | Absolute-form forwarding, hop-by-hop stripping, capture via an observer, loopback by default |
| **M2.3** — TLS interception | `CONNECT` tunnelling, double handshake, selective interception with exempt and only-mode |
| **M2.4** — Interception hooks | Forward / replace / drop / respond on requests, forward / replace / drop on responses, with a queue that cannot wedge the browser |

## Next

**M3 — traffic storage.** Captured exchanges currently scroll past in the console and
are then gone. M3 connects them to the SQLite metadata store and content-addressed blob
store built in M0, which have been sitting unused since — and closes the M1.5 gap where
compressed bodies are decoded in place without the original wire bytes being kept.

M2.5 (trust installation and first-run) can follow; the CLI already prints per-platform
instructions, so what remains there is desktop UX rather than mechanism.

M1.4 (connection pooling) stays deferred: the fuzzer needs it, the proxy does not, and
a pool that mis-frames one response corrupts the next.

**Known gap to close in M3:** compressed responses are decoded in place, so the
original wire bytes are not retained. That is at odds with "preserve the wire" and is
only acceptable until the traffic store keeps both forms.

Full plan: [`docs/roadmap.md`](docs/roadmap.md).

## Open decisions

| Question | Status | Blocks |
| -------- | ------ | ------ |
| **First customer**: solo pentesters / small consultancies / bug bounty hunters | **Unanswered** | Nothing until M4. Decides whether M12 (authorization testing → reports) or M13 (scanner) comes first. Recommendation: consultancies — the gap between Caido Team and Burp's $13,600 Enterprise tier, and the evidence architecture already fits |
| Write positioning analysis into `docs/positioning.md`? | Unanswered | Nothing |

---

## Getting a machine ready

```bash
# 1. Rust
winget install --id Rustlang.Rustup -e          # Windows
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # macOS/Linux

# 2. Windows only: MSVC C++ build tools, INCLUDING the Windows SDK
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override \
  "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# 3. Frontend
corepack enable && pnpm -C frontend install
```

### Two Windows traps that cost hours

1. **Do not build from Git Bash.** Git for Windows ships a coreutils `link.exe` at
   `/usr/bin/link.exe` that shadows MSVC's linker. The error looks nothing like a
   toolchain problem — it says `link: extra operand` and suggests installing build
   tools you may already have. Build from **PowerShell** or a Developer Command
   Prompt, or `call vcvars64.bat` first.
2. **`--includeRecommended` matters.** Installing the VCTools workload without it can
   omit the Windows SDK, and you get `LNK1181: cannot open input file 'kernel32.lib'`.

Both are written up in [`docs/development.md`](docs/development.md).

## The gate — run this before every commit

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
pnpm -C frontend typecheck && pnpm -C frontend build
```

All six must pass. `cargo audit` currently reports **0 vulnerabilities** and 7
unmaintained-crate warnings, all transitive through Tauri and recorded in
[`docs/dependencies.md`](docs/dependencies.md).

## Try it

```bash
cargo run -p hexora-cli -- send http://example.com/
cargo run -p hexora-cli -- send https://example.com/ --insecure   # self-signed targets
cargo run -p hexora-cli -- project init ./scratch/demo

# The proxy. Export and install the CA first, then point a browser at it.
cargo run -p hexora-cli -- ca --export hexora-ca.crt
cargo run -p hexora-cli -- proxy --listen 127.0.0.1:8080
cargo run -p hexora-cli -- proxy --only target.example.com   # leave your own traffic alone
```

---

## Things worth remembering

Written down because they were learned the hard way and are easy to undo by accident.

- **The parser is hand-written on purpose.** `httparse` would be the obvious choice and
  is the wrong one: a client parser normalizes away exactly the ambiguity a security
  tool exists to find. See the module docs in `core/http/src/parse.rs`.
- **`Secret<T>` has no `Serialize` impl.** That is not an oversight — it makes leaking
  a credential through `serde_json::to_string` a *compile error*. Persistence opts in
  per field via `redact::exposed`.
- **Scope normalization decodes to a fixed point.** Decoding once left a real bypass:
  `/%2561dmin` → `/%61dmin` → `/admin`. Found by a property test, not by review.
- **Unimplemented paths return `NotImplemented` naming their milestone.** Never an
  empty result — a security tool that appears to have run and found nothing is worse
  than one that says it cannot run yet.
- **Tests that assert OS-specific error classifications will fail in CI.** Closing a
  socket with data queued gives `ECONNRESET` on Windows and a clean EOF on Linux.
- **Windows schannel rejects a locally generated CA passed as a file.** It checks
  revocation, and a local CA has no revocation list, so you get
  `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` even though the certificate is fine. Install
  it into the store with `certutil` instead; `curl --ssl-revoke-best-effort` works for
  a quick test.
- **Inside a CONNECT tunnel the client sends origin-form targets**, which carry no
  scheme. Forwarding one naively replays it upstream over plaintext and silently
  downgrades a connection the user believes is encrypted. The scheme comes from the
  CONNECT authority, and a test asserts the captured URL stays `https://`.
- **Interception records what the server said, never what the tester substituted.**
  A replaced or dropped response is still observed as it arrived. Recording a
  substitution as the server's own behaviour would put a fabricated response into the
  evidence behind a finding.
- **"Interception enabled" and "interception watched" are different states.** With no
  consumer attached nothing pauses, because a queue nobody reads would hang every
  request while looking like a crashed proxy.

## Documentation map

| File | For |
| ---- | --- |
| [`docs/roadmap.md`](docs/roadmap.md) | What exists, what is next, in what order and why |
| [`docs/feature-parity.md`](docs/feature-parity.md) | Burp / Caido / ZAP matrix and competitive position |
| [`docs/architecture.md`](docs/architecture.md) | Crate layout and where invariants are enforced |
| [`docs/security-invariants.md`](docs/security-invariants.md) | The rules the codebase does not break |
| [`docs/threat-model.md`](docs/threat-model.md) | Hostile targets, extensions, local attackers — and the limits |
| [`docs/storage.md`](docs/storage.md) | Why bodies are not in the database |
| [`docs/development.md`](docs/development.md) | Building, testing, conventions |
| [`docs/dependencies.md`](docs/dependencies.md) | Dependency, audit and secret-scanning policy |
