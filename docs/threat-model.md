# Threat model

Hexora is a security tool that holds a client's credentials, intercepts their traffic,
and deliberately talks to systems that may be hostile. That combination makes it a
high-value target and an unusually exposed one.

This document states what Hexora defends against, how, and — equally important — what
it does not defend against.

**Status:** written at M0, before the network stack exists. Sections marked
_(not yet implemented)_ describe the design the relevant milestone must satisfy, not
current behaviour.

---

## Assets

| Asset | Why it matters |
| ----- | -------------- |
| Testing identity credentials | Live access to a client's systems |
| Captured traffic | Session tokens, PII, business data |
| The interception CA private key | Can forge certificates for any site the user visits |
| Project databases | The engagement's findings and evidence |
| The tester's machine | Compromise reaches every client they work with |
| The client's systems | Hexora sends them traffic; a bug here damages a third party |

---

## Actor 1: A hostile target

**The most important actor.** Hexora connects to systems chosen precisely because
their security is unknown, and a target that detects a scanner has every incentive to
attack back.

### Oversized and slow responses

A target answers with a 40 GB body, or a body that arrives one byte per second for a
week, or a header block that never terminates.

**Defence.** Every network operation carries a `Limits` value bounding body size,
header size, header count and per-phase timeouts. Automated subsystems use tighter
limits than interactive ones. Truncation is recorded so evidence never silently
misrepresents a partial response. _(Enforcement lands with M1; the types and the
checks exist and are tested now.)_

### Decompression bombs

A few kilobytes of gzip expanding to tens of gigabytes.

**Defence.** Two bounds together, checked incrementally as output is produced: an
absolute cap on decompressed size, and a maximum expansion ratio. Neither works alone
— a small bomb has a huge ratio, a large legitimate JSON document has a modest one, and
tiny inputs produce wild ratios harmlessly. See `Limits::check_decompression`.

### Malformed HTTP, TLS and WebSocket data

Deliberately broken framing, invalid status lines, non-UTF-8 headers, oversized
frames, parser-confusion payloads.

**Defence.** Parsers return `ProtocolError` and never panic. The message model stores
headers and bodies as raw bytes, so invalid input is *representable* rather than
something the parser must reject or mangle — which is also what makes Hexora usable
for smuggling research. `#![forbid(unsafe_code)]` in every crate means a parser bug
cannot become memory corruption. Fuzz targets for the HTTP parsers are an M1
deliverable.

### Connection and memory exhaustion

Thousands of slow connections, or responses sized to exhaust RAM.

**Defence.** Per-host connection caps, global concurrency limits, bounded buffers,
cancellation on every operation.

### SSRF-by-proxy and scope escape

The most Hexora-specific risk: a target redirects, or a payload generator mutates a
path, such that automated traffic reaches somewhere it was never authorized.

**Defence.** Invariant 1. Redirects are **not** followed by default, precisely because
a 302 can point at a host outside scope. Scope exclusions are checked against
normalized as well as raw paths so encoding and dot-segment tricks cannot walk a
fuzzer into a carve-out. Wildcard host rules never match IP literals.

### Prompt injection via response content

A target serves text crafted to steer the AI layer, which is reading that response as
input.

**Defence.** Invariant 5. Approval decisions derive from the structure of a proposed
tool call, never from model output. Credential access is forbidden outright rather than
gated behind a dialog the user cannot meaningfully evaluate.

---

## Actor 2: A malicious or careless extension

Extensions are third-party code running inside a process that holds credentials and
traffic. Most are fine. The model must not depend on that.

**Defence.** Invariant 4: capabilities are granted explicitly and can only be
narrowed. Dangerous capabilities (filesystem, raw network, process execution,
credential access) are never implied by any other and must be requested by name. The
install dialog states consequences, not capability names. Extensions sending traffic
go through the same `ScopeGuard` as everything else.

**Limitations — read these.**

- **Tier 1 (native Rust) and Tier 3 (Burp/Java) extensions are not sandboxed by the
  permission model alone.** Native code can ignore it. The permission model is a
  correctness and transparency mechanism for cooperative code; it is not a security
  boundary against hostile native code.
- Real isolation requires process or WASM sandboxing. The intended direction is WASM
  for the new extension tier and an out-of-process JVM with an RPC interface for Burp
  compatibility. Neither exists yet.
- Until then, **installing a native or Burp extension is equivalent to running an
  arbitrary program as your user**, and the UI must say so in those words.

---

## Actor 3: A local attacker

Someone with access to the tester's machine, or to a project directory shared over
Dropbox/Slack/a NAS.

### What Hexora does

- Secrets are wrapped in `Secret<T>`, so they do not leak into logs or crash dumps.
- Sensitive headers are redacted by default in exports and reports.
- Blob integrity is verified on read, so tampered evidence is detected rather than
  silently used in a report.
- A project written by a newer Hexora is refused rather than partially interpreted.

### What Hexora does not do — be clear about this

- **Project data is not encrypted at rest by default.** A project directory contains
  captured traffic and, if identities are configured, credentials. Anyone who can read
  the directory can read those. Optional passphrase encryption of the credential
  columns is planned; whole-project encryption is not, because it would conflict with
  the portability that makes a project directory useful.
- **The interception CA private key is stored on disk** and is only as protected as
  the filesystem. A stolen CA key lets an attacker impersonate any site to that
  machine. The CA must be per-installation, never shipped, never shared, and easy to
  regenerate and remove. _(M2.)_
- **Hexora does not defend against malware already running as your user.** Nothing at
  application level can.
- **Full-disk encryption and OS account hygiene are prerequisites**, not things Hexora
  can substitute for.

---

## Actor 4: A malicious project or import file

Project directories, HAR files, OpenAPI and Postman documents, Burp exports and
extension packages all arrive from outside.

**Defence.** Invariant 7. Parsers are defensive and bounded; archive extraction must
reject absolute paths and `..` traversal; blob reads are hash-verified; schema versions
are checked before use. An imported file must never be able to write outside the
project directory or cause execution.

---

## Actor 5: Hexora itself, misconfigured

The likeliest real-world incident is not an attacker. It is a scan aimed at the wrong
host, or a fuzzer left running against production overnight.

**Defence.** Empty scope blocks all automated traffic rather than allowing it.
Refusals are logged at `warn` so a misconfigured scope looks like a problem rather than
like a clean scan that found nothing. Privileged actions — scope changes, permission
grants, AI approvals, bulk deletion — are recorded in the project audit log, so a
tester can answer "what did this tool do, and when".

---

## Non-goals

- Hexora does not try to be undetectable by a WAF or IDS. Evasion for evasion's sake
  is not a design goal.
- Hexora does not protect a client's systems from an authorized tester. That is what
  the rules of engagement are for; scope enforcement supports them, it does not
  replace them.
- Hexora sends no telemetry, so there is no telemetry threat surface. This is
  invariant 8 and is not configurable, because a tester's traffic patterns reveal who
  their client is.

---

## Open questions

Tracked here rather than resolved prematurely:

1. Where does the CA key live on each platform, and can OS keychains hold it?
2. Should credential columns be encrypted with a project passphrase by default, given
   the usability cost of prompting on every open?
3. Can the Burp/JVM bridge be confined enough (separate process, restricted RPC, no
   filesystem) to be honestly described as sandboxed?
4. What is the right default when a redirect crosses from in-scope to out-of-scope
   mid-chain for a *human-driven* request?
