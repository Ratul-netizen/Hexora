# Security invariants

These are the rules Hexora does not break. They are not aspirations: each one names
where it is enforced and which test proves it. A change that violates an invariant is
a bug regardless of what it enables.

If you are adding a subsystem, read this first. Most of these are invariants precisely
because the natural way to write the code violates them.

---

## 1. Automated components never send out-of-scope requests

**Rule.** Scanner, fuzzer, workflows, extensions, authorization testing and AI tools
may only send requests to targets the project scope authorizes. Human-driven
components (proxy, repeater) are *not* blocked, because a tester typing a URL has made
a decision — but their out-of-scope requests are flagged so the UI can offer to widen
the scope explicitly.

**Why.** Scope is the technical expression of the engagement's rules of engagement.
Traffic sent outside it may be a crime, and a fuzzer that wanders onto a third party's
infrastructure is the failure mode that ends a testing company.

**Enforced by.** `hexora_engine::guard::ScopeGuard`, which wraps the transport. Every
subsystem receives its transport already wrapped, so the check happens once, below all
of them, rather than in each caller. A `Scope` struct on its own would not achieve
this; the guard is what makes the invariant real.

**Corollaries.**

- An **empty scope means nothing is in scope**, never everything. A new or
  misconfigured project cannot become a licence to scan the internet.
- Exclusions beat inclusions, always, whatever order they were added in.
- Exclusions are matched against the raw *and* normalized path, so `/admin`,
  `/%61dmin`, `/x/../admin` and `/%2fadmin` are all refused by a rule excluding
  `/admin`. Without this a payload generator would walk straight through a carve-out.
- Wildcard host rules never match IP literals. Authorization for a hostname does not
  extend to whatever address it currently resolves to.

**Tests.** `core/engine/src/guard.rs` — `out_of_scope_automated_requests_never_reach_the_transport`,
`an_excluded_path_cannot_be_reached_by_encoding_it`, `an_empty_scope_stops_all_automated_traffic`.
`core/types/src/scope.rs` — the `property_tests` module.

---

## 2. Secrets never appear in logs, `Debug` output or error messages

**Rule.** Credentials, session cookies, bearer tokens and API keys must not reach a
log file, a crash report, a `Debug` rendering or an error string.

**Why.** Hexora holds live credentials for a client's systems. A stack trace pasted
into a bug report must not be a credential disclosure.

**Enforced by.** `hexora_types::redact::Secret<T>`, whose `Debug` prints `<redacted>`
and which has no `Display`. Reading the value requires `.expose()`, so every place a
secret can escape is one grep away. `Credential` stores its material in `Secret`, so a
`Debug` of an entire `Identity` — or of a struct containing one — is safe.

**Corollaries.**

- Header values on the sensitive list (`Authorization`, `Cookie`, `Set-Cookie`,
  `X-API-Key`, …) are redacted by default when traffic is rendered outside the UI.
  The UI itself shows them: that is the tester's job.
- Turning redaction off is a per-export, explicit user action.

**Tests.** `core/types/src/redact.rs`, and `secrets_do_not_leak_through_identity_debug_output`
in `core/types/src/identity.rs`.

---

## 3. Resource limits are enforced at the network boundary, while bytes arrive

**Rule.** Every network operation carries a `Limits` value and enforces it
incrementally — not after the response has been fully read.

**Why.** Targets can be hostile. A 40 GB body, an endless header block or 40 KB of
gzip that expands to 40 GB must not take the process down. Checking *after* reading
means the damage is already done.

**Enforced by.** `hexora_types::limits::Limits`, threaded through `SendOptions`.
Decompression is bounded by both an absolute output cap and an expansion ratio, since
neither alone distinguishes a bomb from a large legitimate document.

**Corollaries.**

- Automated subsystems use tighter limits than interactive ones.
- A truncated body is **recorded as truncated**. Evidence derived from a partial
  response must disclose that, or a report makes a claim the data does not support.

**Tests.** `core/types/src/limits.rs` — `a_classic_zip_bomb_is_stopped_by_the_ratio_check`,
`a_slow_bomb_is_stopped_by_the_absolute_cap`, `ordinary_compression_ratios_pass`.

---

## 4. Extensions receive no permission implicitly

**Rule.** An extension holds exactly the capabilities the user approved. There is no
code path that widens a grant at runtime.

**Why.** An extension runs inside a process holding a client's credentials and
traffic. "It only needed filesystem access temporarily" is how that becomes an
incident.

**Enforced by.** `hexora_engine::permission::GrantSet`, which has no `add` method.
It can be constructed from a user's approval and thereafter only narrowed
(`revoke`, `intersect`). Dangerous capabilities — filesystem, raw network, process
execution, credential access — are never implied by any other capability and must each
be requested by name.

**Corollaries.**

- A sub-runtime or spawned task holds at most its parent's grants (`intersect`).
- An extension whose *required* permissions were declined is not enabled at all,
  rather than loaded into a state where it fails halfway through a scan.
- `RawNetwork` is called out as dangerous specifically because it bypasses invariant 1:
  a connection that does not go through the engine is not scope-checked or captured.

**Tests.** `core/engine/src/permission.rs` — `a_new_extension_starts_with_nothing`,
`dangerous_capabilities_are_never_implied_by_anything`, `intersecting_can_only_narrow`.

---

## 5. The AI layer cannot bypass any other control

**Rule.** The AI proposes tool calls; it does not call the engine. Anything that sends
traffic or changes project data stops for a human. Approved calls still go through
scope enforcement and permission checks.

**Why.** Two distinct risks. First, an LLM can loop or misjudge and aim thousands of
requests at production. Second, and more subtly: the AI's *input* includes response
bodies from the target, which are attacker-controlled text. Prompt injection is a
given, not an edge case.

**Enforced by.** `hexora_engine::ai::ToolGate`. Approval is derived from the
*structure* of the proposed call, never from model output. Reading stored credentials
is `Forbidden` outright — an approval dialog there would be theatre, because the user
cannot meaningfully evaluate a credential-dump request that originated inside a
model's reasoning.

**Corollaries.**

- Approval prompts state target, request count and expected duration. "The assistant
  wants to run a scan" is not a decision anyone can make.
- A standing "allow for this project" approval never covers a bulk send. Permission
  given for a three-request probe must not authorize fifty thousand.
- AI approval is *additional* to scope, never a substitute: an approved call still
  goes through `ScopeGuard`.

**Tests.** `core/engine/src/ai.rs` — `credentials_are_never_available_to_the_ai`,
`a_standing_approval_does_not_cover_bulk_traffic`, `every_call_that_sends_traffic_requires_approval`.

---

## 6. A finding requires evidence

**Rule.** A heuristic match is not a finding. Nothing above `Confidence::Reported` may
exist without attached evidence that points at real, re-runnable traffic.

**Why.** The output of this tool goes into a report a client acts on. A false positive
delivered confidently costs the tester their credibility; a hallucinated one costs
more.

**Enforced by.** `Finding::validate`, called before a finding is persisted or
exported, plus `FindingSource::max_unverified_confidence` — passive checks and the AI
layer can only ever self-assert `Reported`. Promotion beyond that requires the
verification engine.

**Corollaries.**

- Evidence references request and response IDs, not prose, so the UI can open the
  exact exchange behind any claim.
- Findings at `Reported` are legitimate and useful — they are *leads*. They must be
  labelled as unconfirmed everywhere they appear.
- An actionable finding without reproduction steps is rejected.

**Tests.** `core/types/src/finding.rs` — `a_confident_finding_without_evidence_is_rejected`,
`ai_cannot_self_certify_above_reported`.

---

## 7. Imported data is untrusted input

**Rule.** Project files, HAR files, OpenAPI and Postman documents, Burp project
exports, extension packages and stored blobs are parsed defensively. None of them may
cause path traversal, command execution, unbounded allocation or a panic.

**Why.** These arrive by email, from a client, or from a marketplace. "It's just our
own project format" is how a file format becomes an execution vector.

**Enforced by.** Parsers return structured `ProtocolError`/`StorageError` values
rather than panicking; the blob store verifies content against its hash on every read
and reports `BlobIntegrity` rather than returning altered bytes; a project written by a
newer Hexora is refused (`SchemaTooNew`) rather than opened and silently corrupted.

**Tests.** `core/storage/src/blob.rs` — `corrupted_blobs_are_detected_rather_than_returned`.
`core/storage/src/migrations.rs` — `a_newer_schema_is_refused_rather_than_downgraded`.
`core/types/src/scope.rs` — `matching_never_panics`.

---

## 8. Hexora never sends traffic the user did not ask for

**Rule.** No telemetry, no update pings, no crash reporting, no reputation lookups.
No connection to any host that is not a testing target or an explicitly configured
service.

**Why.** A tester's traffic reveals who their client is and what they are testing. In
some engagements, an outbound connection from the tester's machine is itself a
disclosure. This must be true by construction, not by configuration.

**Enforced by.** Review. Any new outbound connection in a pull request needs an
explicit justification. There is no telemetry code to disable because there is none to
write.

---

## Changing an invariant

These can change — but through a deliberate decision recorded in `docs/`, with the
enforcing code and tests updated in the same change. What must not happen is an
invariant quietly ceasing to hold because a new subsystem took a different path to the
network.
