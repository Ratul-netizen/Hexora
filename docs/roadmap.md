# Roadmap

Status labels: **IMPLEMENTED** · **IN PROGRESS** · **PLANNED**

Nothing is described in the present tense before it works. If you find a feature
claimed here that does not exist, that is a bug in this file.

---

## M0 — Architecture foundation · IMPLEMENTED

- Cargo workspace, toolchain pin, lint and format configuration
- Domain model: HTTP messages, IDs, scope, identities, findings, limits, secrets, errors
- SQLite metadata database with transactional migrations
- Content-addressed blob store for bodies
- Backend-agnostic repository interfaces
- Scope enforcement at the transport boundary
- Extension permission model
- AI tool-permission gate
- CLI shell (`project init`, `project info`, `version`)
- Tauri + React shell reporting engine status
- CI: fmt, clippy, test, frontend typecheck and build
- Architecture, threat model, storage and security-invariant documentation

---

## M1 — HTTP engine · PLANNED · **next**

The first milestone that puts bytes on a wire.

- HTTP/1.1 client over TCP and TLS (rustls)
- Connection pooling, keep-alive, per-host limits
- Real implementation of `HttpTransport`
- Streaming bodies with incremental limit enforcement
- Content decoding (gzip, deflate, brotli) with bomb protection
- Chunked transfer decoding, including deliberately malformed input
- Timeouts and cancellation at every phase
- Redirect handling (opt-in, scope-checked at each hop)
- Fuzz targets for the response parser
- Integration tests against a local test server, including hostile-response cases

**Done when** the CLI can send a request to a local server, record the exchange, and
survive a test suite of malformed and hostile responses without panicking or exceeding
its limits.

**Explicitly not in M1:** proxy, UI, HTTP/2, HTTP/3, WebSockets.

---

## M2 — Proxy · PLANNED

- HTTP proxy and `CONNECT` tunnelling
- Per-installation interception CA with generated leaf certificates
- Certificate management and export
- Intercept, forward, drop, modify
- Match and replace rules
- WebSocket pass-through

---

## M3 — Traffic history · PLANNED

- SQLite implementations of the repository traits
- Capture pipeline from proxy to storage
- History browsing, filtering and pagination in the UI
- Search over captured traffic
- Blob garbage collection

---

## M4 — Repeater · PLANNED

- Request tabs, editing, resend
- Request branching with parent relationships preserved
- Response comparison
- Collections and variables

At M4 Hexora becomes a genuinely usable tool rather than a foundation.

---

## Later

Ordered by dependency, not by date. Anything below here is a direction, not a
commitment.

| Milestone | Contents |
| --------- | -------- |
| M5 | Target map and attack surface inventory |
| M6 | Passive scanner |
| M7 | Active scanner and verification engine |
| M8 | Fuzzer / Intruder |
| M9 | Workflow engine |
| M10 | TypeScript extension SDK |
| M11 | Extension runtime and sandboxing (WASM) |
| M12 | Burp Montoya compatibility layer — **separate subproject** |
| M13 | OAST |
| M14 | GraphQL, JWT, OAuth modules |
| M15 | Authorization testing |
| M16 | AI subsystem |
| M17 | Reporting |
| M18 | Team server |

---

## Notes on the harder items

**Burp compatibility (M12)** is a multi-month engineering project of its own, not a
checkbox. It requires an out-of-process JVM, a JNI or RPC bridge, and an independent
implementation of a large public API. It will be independently versioned and ship with
a public compatibility matrix (FULL / PARTIAL / UNSUPPORTED per API) rather than a
claim of universal support. It is deliberately last among the extension work.

**HTTP/2 and HTTP/3** are not in M1. Getting HTTP/1.1 right — including the malformed
cases that make a proxy useful for security testing — is more valuable than breadth.

**The AI subsystem (M16)** comes after the scanner and the verification engine, not
before. An AI layer over an unreliable core produces confident nonsense; the gate and
the evidence model exist now so that when it arrives, it is constrained by
construction.
