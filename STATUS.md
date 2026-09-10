# Where we are

**Pick-up-anywhere note.** Read this first on a new machine or after a break; it is the
only file that needs to be current for you to resume. Updated at the end of every
milestone.

- **Last updated:** M12.1 (authorization testing)
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
| **M3** — Traffic storage | Proxied exchanges persist into a project: metadata in SQLite, bodies content-addressed and deduplicated, both the wire and decoded forms kept, TLS details and framing quirks recorded, keyset-paginated `hexora history` |
| **M4** — Repeater | Load a request from history, edit it in `$EDITOR`, resend it, diff the responses. Nothing is auto-corrected — a wrong `Content-Length` is reported and sent as written. Sends keep a link to what they derived from, so `--tree` answers "which edit caused this?" |
| **M2.5** — Trust and first run | `hexora setup` gets a machine ready in one command. The CA installs into the *user* trust store (no admin), is verified by asking the platform rather than trusting an exit code, and removes cleanly. Firefox is detected and called out because it ignores the system store |
| **M5** — Desktop UI | The Tauri window does the whole loop: open a project, install the CA, run the proxy, watch traffic arrive live, inspect an exchange, send it to the repeater, edit, resend, diff. Same crates as the CLI — there is no second engine |
| **M12.1** — Authorization testing | Replay one captured request as every identity and say what the differences prove. Structural comparison, an unauthenticated control that stops a public page becoming six findings, declared object ids that both convict and exonerate, confidence that has to be earned by reproduction. Identities and scope now persist in the project |

## Next

**Hexora can now answer the question testers actually get paid for.** Capture a request
once, and `hexora authz` will replay it as everyone else and tell you whether the
application checks *who* is asking or only that somebody is — with the evidence
attached, in the project, citable months later.

What that leaves open, in the order it matters:

- **File the findings.** `hexora authz` prints its findings; nothing writes them to the
  `findings` table, which has been in the schema since M0. Until that lands a run's
  conclusions live in a terminal, and the project holds only the traffic behind them.
  Small, well-defined, and the prerequisite for everything below.
- **The report.** The gap nobody fills well: a document that cites the exact exchange
  behind every claim. The evidence model was built for this and now has real findings
  to carry.
- **Construct the attempts, do not only replay them.** The matrix replays a request as
  written. Substituting one identity's object identifiers into another's request —
  "can User B reach *User A's* invoice id?" — is the other half of M12 and finds bugs
  a replay cannot.
- **M13 — the scanner.** Still the thing buyers compare on, and still the thing most
  likely to waste a tester's day if it is wrong.

**Two honesty notes carried forward:**

The macOS and Linux trust paths in `core/proxy/src/trust.rs` are written, unit-tested
and type-checked, but have never been *run* on those platforms. Only Windows is
verified end to end.

The desktop UI compiles, launches and its logic is unit-tested, but its visual result
has not been inspected on any platform — nobody has looked at the window and said "that
reads correctly". Treat the layout as unreviewed.

The authorization matrix has been exercised end to end against a local application
with a deliberate IDOR: it found the bug at High/Confirmed, correctly cleared a
per-identity endpoint that scores 1.00 on similarity, and correctly reduced a public
page to a single finding. It has not been run against a large real application, where
response noise is worse than any fixture.

M1.4 (connection pooling) stays deferred: the fuzzer needs it, the proxy does not, and
a pool that mis-frames one response corrupts the next.

**Debt carried out of M3:** the schema and the store keep both body forms, and the
proxy records the `Content-Encoding` that was applied — but the transport still hands
back only the decoded bytes, so `encoded_body` is written as NULL in practice. The
column, the migration and the read path (`hexora history --body --wire`) are all in
place; what remains is threading the encoded bytes out of `BodyStream::collect`. Until
that lands, `--wire` returns the decoded body for compressed responses.

**Debt carried out of M4:** a request edited to bare-LF line endings is re-serialized
with CRLF, because `HttpRequest` stores fields rather than bytes. The warning says so
explicitly rather than hiding it. Byte-exact raw sending needs a send path that
bypasses the message model.

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

All six must pass. `cargo audit` currently reports **0 vulnerabilities** and 8
warnings — 7 unmaintained crates and one unsoundness in `glib`, all transitive through
Tauri and recorded in [`docs/dependencies.md`](docs/dependencies.md).

## Try it

```bash
# Everything at once, on a machine you control.
cargo run -p hexora-cli -- setup ./engagement

cargo run -p hexora-cli -- send http://example.com/
cargo run -p hexora-cli -- send https://example.com/ --insecure   # self-signed targets
cargo run -p hexora-cli -- project init ./scratch/demo

# The CA, a step at a time.
cargo run -p hexora-cli -- ca --status      # does this machine trust it?
cargo run -p hexora-cli -- ca --install     # asks first
cargo run -p hexora-cli -- ca --untrust     # remove from the store, keep the files
cargo run -p hexora-cli -- ca --delete      # untrust and remove everything
cargo run -p hexora-cli -- ca --export hexora-ca.crt
cargo run -p hexora-cli -- proxy --listen 127.0.0.1:8080
cargo run -p hexora-cli -- proxy --only target.example.com   # leave your own traffic alone

# Capture into a project, then read it back.
cargo run -p hexora-cli -- proxy --project ./scratch/demo
cargo run -p hexora-cli -- history ./scratch/demo
cargo run -p hexora-cli -- history ./scratch/demo --body req_01a08b… > response.bin

# The repeater: resend, edit, compare, and see what descended from what.
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --dry-run
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --edit
cargo run -p hexora-cli -- repeat ./scratch/demo req_01a08b… --tree
cargo run -p hexora-cli -- repeat ./scratch/demo req_A --diff req_B

# Authorization testing: is the application checking who is asking?
cargo run -p hexora-cli -- scope add ./scratch/demo api.example.com
export TOKEN_B=...                      # never on the command line: ps reads that
cargo run -p hexora-cli -- identity add ./scratch/demo "User B"     --kind bearer --from-env TOKEN_B --owns acct-2000
cargo run -p hexora-cli -- identity list ./scratch/demo
cargo run -p hexora-cli -- authz ./scratch/demo req_01a08b… --as-identity "User A"
cargo run -p hexora-cli -- authz ./scratch/demo req_01a08b… --as-identity "User A" --verify

# The desktop window. Same engine, no terminal.
pnpm -C frontend build && cargo run -p hexora-desktop
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
- **An anonymous control is what makes a matrix trustworthy.** Without it, a public
  page produces one "violation" per identity, all of them true and all of them
  worthless. With it, the run says the only thing that is actually the case.
- **Declared object identifiers cut both ways.** They are what raises a similarity
  match to a disclosure — and what clears an endpoint that returns each caller their
  own record in an identical document shape. `GET /profile` scores 1.00 against the
  owner's response and is not a bug; only the ids inside can say so.
- **Scope is why `hexora authz` needs a project that has one.** Authorization replays
  are automated traffic, and the guard refuses automated traffic to undeclared hosts.
  The run asks once, before sending, so a misconfigured scope is one sentence rather
  than one failure per identity.
