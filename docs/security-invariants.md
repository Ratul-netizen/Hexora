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

## 2. Secrets never appear in logs, `Debug` output, error messages or serialized output

**Rule.** Credentials, session cookies, bearer tokens and API keys must not reach a
log file, a crash report, a `Debug` rendering, an error string, an export, or an IPC
payload to the frontend.

**Why.** Hexora holds live credentials for a client's systems. A stack trace pasted
into a bug report must not be a credential disclosure — and neither must a project
export or a debug dump of an identity.

**Enforced by.** `hexora_types::redact::Secret<T>`, which has:

- a `Debug` that prints `<redacted>`,
- no `Display`, so it cannot be interpolated into a message by accident,
- and **no `Serialize`**.

The missing `Serialize` is the load-bearing part. Redacting `Debug` alone is not
enough: a credential leaks just as completely through `serde_json::to_string` as
through a log line, and that call is far more likely to be written by someone building
an export or an IPC response. Because `Secret` has no `Serialize` impl,
`#[derive(Serialize)]` on any struct holding one is a **compile error**, not a silent
leak. `Credential` and `Identity` are therefore deliberately not `Serialize`.

Reading a secret requires `.expose()`. Persisting one requires the
`redact::exposed` serde adapter, opted into per field. Both are one grep away.

**Corollaries.**

- Header values on the sensitive list (`Authorization`, `Cookie`, `Set-Cookie`,
  `X-API-Key`, …) are redacted by default when traffic is rendered outside the UI.
  The UI itself shows them: that is the tester's job.
- Turning redaction off is a per-export, explicit user action.
- Anything that needs to show an identity to the frontend or a report sends a
  purpose-built redacted view, never `Identity` itself.
- `Deserialize` **is** implemented on `Secret`: loading a stored credential back is
  necessary and is not a disclosure.

**Tests.** `core/types/src/redact.rs` — `secret_debug_never_leaks_the_value`,
`secret_nested_in_a_struct_still_redacts`, `the_exposed_adapter_round_trips_a_secret`.
`core/types/src/identity.rs` — `secrets_do_not_leak_through_identity_debug_output`.
The no-`Serialize` property is enforced by the compiler rather than by a test, which is
stronger: a test can only catch the cases someone thought to write.

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

**Enforced by the type system, since M13.1.** `FindingStore::save` and
`FindingStore::record` take a `Verified`, and the only way to obtain one is
`Verified::conclude`, which requires a `Verification`. A detector's output is a
`Hypothesis`, and there is no `From`, no `into_finding`, and no constructor anywhere
that turns one into the other. A check that is merely suspicious does not get an
error when it tries to store a claim — it does not compile.

```text
Detector  →  Hypothesis   ──✗──▶  FindingStore
                 │
             Verifier  (a controlled experiment, through a Lab)
                 ▼
            Verification  ──▶  Verified  ──✓──▶  FindingStore
```

**Confidence is derived, never chosen.** `Verification::confidence` is a total
function from what the experiment showed to what may be claimed, and it is the only
place the decision is made:

| Verification | Confidence |
| ------------ | ---------- |
| `Reproduced` — the effect happened again | `Confirmed` |
| `Supported { Distinctive }` — hard to explain another way | `Firm` |
| `Supported { Consistent }` — consistent, and with other causes too | `Tentative` |
| `Observed` — nothing to experiment on, e.g. a missing header | `Reported` |
| `Refuted` / `Inconclusive` | **no finding at all** |

A detector cannot assert its own confidence, so
`FindingSource::max_unverified_confidence` is no longer the only thing standing
between a passive check and a confident claim.

**Still enforced at runtime, as the backstop.** `Finding::validate` runs inside
`Verified::conclude`, so a verifier that returns `Supported` with no evidence gets
`None` rather than a finding. The type keeps honest code honest; the check catches the
bug.

**The one door, named so it cannot be taken by accident.**
`Verified::asserted_by_a_human` accepts a `FindingSource::Manual` finding and nothing
else — a person who says they reproduced something *is* the verifier. `validate` still
applies, so a human cannot record an evidence-free `Confirmed` either. A separate
`Verified::from_trusted_finding` exists for tests behind the `test-support` feature,
which no shipped binary enables.

**Corollaries.**

- Evidence references request and response IDs, not prose, so the UI can open the
  exact exchange behind any claim.
- Findings at `Reported` are legitimate and useful — they are *leads*. They must be
  labelled as unconfirmed everywhere they appear, and `Confidence::is_actionable` is
  false there.
- An actionable finding without reproduction steps is rejected.
- A refuted hypothesis is reported to the tester and stored nowhere. "The check ran
  and knocked it down" is worth seeing; it is not worth recording as a claim.

**Tests.** `core/types/src/finding.rs` —
`a_confident_finding_without_evidence_is_rejected`,
`ai_cannot_self_certify_above_reported`; `core/types/src/verify.rs` —
`the_confidence_ladder_is_a_function_of_the_experiment`,
`an_experiment_that_did_not_support_the_hypothesis_produces_no_finding`,
`a_verifier_that_supports_a_claim_with_no_evidence_still_gets_nothing`,
`an_observation_with_nothing_to_experiment_on_is_a_lead_and_not_more`,
`a_human_may_assert_a_finding_and_nothing_else_may`; `core/storage/src/findings.rs` —
`a_finding_with_no_evidence_has_no_way_to_reach_the_store`;
`core/authz/src/analysis.rs` —
`a_detector_raises_a_hypothesis_and_cannot_produce_anything_more`,
`an_experiment_that_refutes_the_hypothesis_produces_nothing`.

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

## 9. A generated request says where it came from, and changes only what it claims to

**Rule.** Every request Hexora builds rather than replays records its provenance —
the request it was built from, the identity it was sent as, and the exact
substitution that produced it — and the substitution touches nothing else in the
message. The captured request it was built from is never modified.

A request sent in **raw mode** goes further: nothing is normalized at all. What the
tester wrote is what reaches the socket, and the bytes are stored so it can be re-sent
identically months later. Hexora never claims byte-preservation it does not have —
structured sends are serialized from a model and say so.

**Why.** A constructed request is one nobody sent by hand. Six weeks later, "why did
Hexora ask for `invoice-1001` as User B?" has to be answerable from the project, or
the traffic in it is noise a reader cannot distinguish from the tester's own work.
And a substitution that quietly changed a second thing — a path that walked
somewhere else, a header that was rewritten, a body that was re-serialized — would
produce an answer about a request nobody chose while reading as though it were about
the one on screen.

**Enforced by.** `core/authz/src/construct.rs`, and the `constructed_attempts` table.
The substitution is applied to a clone; a declared value is refused if it contains a
control character, exceeds `MAX_IDENTIFIER_LEN`, or would leave its slot once
encoded; a credential header is never an object location, in either direction.

**Corollaries.**

- **Raw mode is not an exception.** A request the tester wrote as bytes is written to
  the socket unchanged — and it still goes through `ScopeGuard::send_raw`, which
  decides on the service it is addressed to and the target read out of its request
  line. An absolute-form request line contributes its *path*, never its authority, so
  rewriting the line cannot point the connection at a host nobody scoped. A raw
  request whose request line cannot be read at all is refused rather than sent,
  because a request nobody can scope must not reach a socket.
- **Ownership is declared, never inferred.** A value that looks like an identifier is
  not one. Nothing constructs a request on the strength of a guess about what a
  string means.
- **A 200 is not a finding.** An identity receiving a response to a request for
  somebody else's object has shown nothing until the response can be tied to that
  object — see invariant 6. Where it cannot be, the result is a lead.
- **Constructed traffic is automated traffic.** It goes through the same
  `ScopeGuard`, on the same transport, as everything else — invariant 1 applies
  unchanged, and there is no flag that bypasses it.
- **A run is bounded.** `ConstructionPlan::limit` caps how many requests one run may
  send, and `HARD_MAX_ATTEMPTS` caps the cap. An authorization test that turns into a
  crawl is one that gets an engagement stopped.

**Tests.** `core/repeater/src/lib.rs` —
`an_out_of_scope_raw_request_from_an_automated_origin_is_refused`,
`a_raw_request_whose_line_points_elsewhere_is_scoped_by_its_path`;
`core/http/src/transport.rs` — `a_raw_request_reaches_the_socket_byte_for_byte`,
`an_absolute_form_target_does_not_choose_the_socket`;
`core/authz/src/construct.rs` —
`an_out_of_scope_target_is_refused_before_anything_is_sent`,
`the_provenance_of_every_constructed_request_is_recorded`,
`substituting_never_touches_anything_but_the_slot`,
`a_path_traversal_payload_stays_inside_its_segment`,
`a_credential_header_is_never_an_object_location`,
`the_attempt_limit_is_enforced_and_reported`,
`a_200_with_nothing_identifiable_in_it_is_not_a_finding`.

---

## 10. Identifier suggestions never establish ownership

Hexora reads captured traffic and offers values that *might* be object identifiers.
It never decides that they are, and it never decides whose they are. Three statements
are kept strictly apart, and only the first is machine-made:

```text
IdentifierCandidate   "acct-1000 varies where an object id would, in 6 requests"
        │  a human decides
        ▼
ObjectDeclaration     "acct-1000 is an account"
        │  a human decides
        ▼
ownership             "…belonging to User A"
```

The reason is that nothing in the bytes distinguishes them. `/api/users/1000` might be
a user id, an account id, a tenant id, a page number or a schema version, and a tool
that guessed would put a fabricated premise underneath every finding built on top of
it — including the constructed authorization tests of invariant 9, whose entire claim
is *this object belongs to somebody else*.

**What this means in the code.**

- `IdentifierCandidate` has **no owner field**, and the `identifier_candidates` table
  has no owner column. This is not a convention: there is nowhere to put one.
- Accepting a candidate sets a status. It does not create an `ObjectDeclaration`, and
  no code path anywhere turns a candidate into one automatically.
- The analyzer is a read. It sends no request, mutates no captured request or
  response, and creates no finding — so it takes no `HttpTransport` at all, which is
  why it cannot reach a network even by mistake.
- Suggestions are *evidence-shaped*, not scored by appearance: a value is offered
  because it varies where an identifier would, against a path that is holding still.
  A number that never varies is not offered; a word that varies where an endpoint
  varies is not offered either.
- Observed bytes are preserved exactly. `1000`, `"1000"` and `%31%30%30%30` are three
  candidates, because normalising them would let a tester replay a spelling the
  application never received.

**Tests.** `core/types/src/candidate.rs` —
`a_candidate_carries_no_owner_field_at_all`; `core/authz/src/suggest.rs` —
`no_amount_of_traffic_produces_an_ownership_claim`,
`three_spellings_of_the_same_number_are_three_different_candidates`,
`a_path_segment_is_offered_exactly_as_it_was_observed`,
`top_level_endpoint_names_are_not_suggested_as_identifiers`,
`a_number_that_never_varies_is_not_suggested`,
`a_value_already_declared_as_an_object_is_the_strongest_signal`.

---

## 11. The absence of a finding is never evidence that it was fixed

Invariant 6 says a finding requires evidence. This is its dual, and it exists because
the second visit to an engagement is where a security tool is most tempted to lie.

A finding is what a test *produced*. When a later run does not produce it, what has
been established is that one test did not raise one claim — which is a fact about a
test run, not about an application. So `hexora snapshot diff` never says *fixed*.
It says the claim is **gone**, and it says why, from a vocabulary in which only one
answer is about the application at all:

| `WhyGone` | What it means | About the application? |
| --------- | ------------- | ---------------------- |
| `ToolChanged` | The two snapshots were taken by different builds | No |
| `SourceSilent` | Nothing from that check appears in the later snapshot | No |
| `NotReproduced` | The same build ran, the same check raised other claims, this one did not come back | As much as anything here can be |

Even `NotReproduced` is named for what was observed rather than what it might imply.
The test may not have covered the same request; the application may now fail
differently rather than correctly. `WhyGone::is_about_the_application` returns true for
that one variant and there is deliberately no `is_fixed`.

**The failure mode this closes, found by running a real retest.** The demo application
was repaired, the authorization matrix re-run, and it reported nothing — and the
comparison said only "+3 exchanges". The old claim was still standing at
`medium/confirmed`, looking exactly like a current result, because a run that produces
no claim never writes to the claim it did not produce. A snapshot therefore records
when each claim was **last written to**, and a claim nothing has touched between two
snapshots is reported as *standing, but nothing re-tested it* rather than silently
counted as unchanged. Unknown — a snapshot taken before that field existed — is
treated the same way: not re-tested.

**Other things that are not fixes, and are labelled as such.**

- A host that left scope stopped being tested. The comparison prints removed scope
  rules and says so in words.
- A finding count that fell is a count, printed as a count. It is never a headline.
- Hexora has no registry of which checks ran; that arrives with the verification
  framework (M13.1). Until then "the check ran and found nothing" and "the check never
  ran" are the same picture, and `SourceSilent` says exactly that rather than guessing.

**Tests.** `core/types/src/snapshot.rs` —
`a_claim_the_later_side_does_not_hold_is_gone_and_never_fixed`,
`a_disappearance_says_nothing_when_the_source_raised_nothing_at_all`,
`a_different_build_makes_every_disappearance_inconclusive`,
`two_passive_checks_are_two_different_sources`,
`a_claim_nobody_re_tested_is_not_a_claim_that_survived_a_retest`,
`a_snapshot_written_before_a_field_existed_still_loads`;
`apps/cli/src/snapshot.rs` — `a_disappearance_is_never_described_as_fixed`,
`the_two_inconclusive_reasons_say_so_in_the_first_word`,
`a_comparison_holding_only_untested_claims_does_not_print_nothing_changed`;
`core/storage/src/snapshots.rs` —
`a_snapshot_survives_the_findings_it_copied_being_rewritten`,
`a_retest_that_no_longer_produces_a_claim_reads_as_not_reproduced`,
`capturing_records_labels_and_privilege_and_never_a_credential`.

---

## 12. Passive scanning never sends, and never claims more than it saw

The passive pass reads exchanges the project already holds. It makes no request, and
that is a property of the code rather than a rule somebody keeps:

```rust
pub fn scan(project: &Project, selection: &Selection) -> Result<Summary>
```

No `HttpTransport`, no `Lab`, and nothing in a `Project` that can reach a network. A
test that installed a mock transport and asserted it was never called would be a
weaker statement than this one, because it would imply a transport existed.

**What a passive check may produce, and what happens to each.**

| Product | Means | Becomes |
| ------- | ----- | ------- |
| Observation, informational | true, and not an issue | listed; never a finding |
| Observation, reportable | true, and worth attention | `Verification::Observed` → a **lead** |
| Hypothesis | suspected, and unsettled | nothing, until an experiment settles it |

`Verification::Observed` caps at `Confidence::Reported`, which is not actionable. **A
passive check cannot state anything more firmly**, and not because it is asked not to:
it does not choose its own verification. The scanner applies the same one to every
observation, so no check can promote itself.

A check that is suspicious rather than certain raises a `Hypothesis` and stops.
Origin reflection is the worked example: one exchange showing
`Access-Control-Allow-Origin` equal to the request's `Origin` is equally consistent
with a server that reflects anything and a server with that one origin allowed. The
difference is a second request with a different `Origin`, which this pass does not
make, so it produces no finding at all.

**`Server: nginx/1.24.0` is a fact, not a vulnerability.** Technology disclosure is
recorded as informational and never reaches the findings list. Deciding a version is a
vulnerability needs a vulnerability database, a patch level and usually a
distribution's backporting policy, and a tool that files it anyway teaches people to
skim past findings.

**Every reportable result resolves to an exchange.** An observation carries the
`RequestId` it came from, and a grouped one carries up to three. There is no path that
produces "endpoint X looks vulnerable" without one.

**Credentials never become scanner evidence**, in either direction. An `Exchange` is
assembled with request credential headers replaced and `Set-Cookie` values replaced —
name and attributes kept, value gone — so a check cannot leak what it was never given,
and neither can anything that later holds an exchange. This was not theoretical: the
regression test below caught a real leak introduced by an unrelated performance change
that began retaining an exchange per grouped observation.

**Out-of-scope traffic is not analysed by default.** The proxy records everything it
sees, because it must see a host before anybody can decide it is in bounds, so a
project holds the tester's own browsing. A pass reads in-scope traffic, counts what it
skipped, and reports both. `--everything` exists and says what it is doing.

**Detector versions are recorded with execution.** A `scan_runs` row says which checks
ran, at which versions, over how much traffic, and what each produced — including
zero, which is the row that matters. It is what lets invariant 11 distinguish *the
check ran and raised nothing* from *the check never ran*, and it is why
`WhyGone::DetectorChanged` can now exist.

**Tests.** `core/scan/tests/passive_scan.rs` —
`the_scanner_has_nowhere_to_put_a_transport`,
`no_credential_reaches_an_observation_a_finding_or_a_run_record`,
`every_finding_is_a_lead_and_never_more`,
`every_finding_cites_an_exchange_the_project_can_resolve`,
`a_reflected_origin_becomes_a_hypothesis_and_not_a_finding`,
`a_technology_banner_is_listed_and_never_filed`,
`out_of_scope_traffic_is_skipped_and_counted_rather_than_analysed`,
`five_hundred_endpoints_missing_one_header_are_one_finding`,
`a_run_records_every_detector_including_the_silent_ones`,
`malformed_and_hostile_traffic_does_not_stop_the_pass`,
`a_non_utf8_header_value_is_read_without_panicking`;
`core/scan/src/lib.rs` — `credentials_are_stripped_in_both_directions`;
`apps/cli/src/detectors.rs` — `every_passive_check_declares_that_it_does_not_send`.

---

## 13. A proof of concept carries placeholders, never credentials

A reproduction is the most-forwarded artefact an engagement produces. It goes into a
ticket, an email, a chat channel and eventually a screenshot, and it is the one
document whose whole purpose is to be run by somebody who was not there.

So it never carries a session:

```text
sent:        Authorization: Bearer eyJhbGciOi...
reproduced:  Authorization: Bearer <USER_A_AUTHORIZATION>
```

The scheme stays, so a reader can see what kind of value the header wants. The
credential is replaced with a token named after the identity the request was sent as,
and **the same identity gets the same token in every step** — so a reader supplies two
values and runs the whole thing, and can see at a glance that step 1 and step 2 were
sent as different people, which is usually the entire finding.

The recorded length is the credential's, not the header value's: a reader who pastes a
40-byte token where a 200-byte one belongs should be able to notice, and a count that
included `Bearer ` would be measuring the wrong thing.

**Compiled from evidence, never invented.** Every step points at a `RequestId` the
project holds, and the bytes come from that stored request. If a citation can no
longer be resolved, the step says so and stops — a reproduction built from a guess
fails when run, and the reader concludes the finding was wrong rather than that the
evidence was missing.

**`curl` is offered only when curl can do it.** curl recomputes `Content-Length`,
normalises line endings, and cannot express a header block containing a bare LF —
which are precisely the requests a smuggling or parser-differential finding is
*about*. `Curl::Inexpressible` is therefore a first-class outcome carrying a reason,
and the raw form is always present. Emitting a command that silently sent something
else would undo `RequestSource::Raw` at the last step.

**A lead does not get a runnable block.** The report compiles a reproduction for
findings that are actionable and for no others. A script attached to an unverified
claim is the thing most likely to be forwarded without the sentence that qualified it,
and `hexora poc` prints the qualification on the artefact itself when asked for one
anyway.

**Tests.** `core/report/src/poc.rs` —
`no_credential_survives_into_a_reproduction`,
`one_identity_gets_one_placeholder_across_every_step`,
`a_placeholder_measures_the_credential_and_not_the_scheme`,
`curl_is_refused_with_a_reason_when_it_would_send_something_else`,
`a_request_the_project_no_longer_holds_is_stated_rather_than_invented`,
`a_lead_says_on_the_artefact_that_it_is_a_lead`,
`a_shell_quoted_value_cannot_escape_its_quotes`,
`a_non_utf8_body_is_described_rather_than_mangled`;
`core/report/src/lib.rs` —
`an_established_finding_carries_a_runnable_reproduction_and_a_lead_does_not`,
`a_rendered_reproduction_carries_placeholders_rather_than_credentials`.

---

## 14. A comparison never sets evidence aside without saying so

Two responses from a real application always differ somewhere — a timestamp, a nonce,
a CSRF token. Ignoring those is necessary for a comparison to mean anything, and it is
exactly the point where a tool starts quietly altering the evidence it reports on.

So normalization is a **policy the caller passes in**, and two rules hold:

1. **Nothing is removed.** A field the policy set aside is still in the difference
   list, carrying the reason and both values. A reader can see what was ignored and
   disagree with it.
2. **The policy is reportable.** `Policy::describe()` goes into the CLI output, the
   matrix JSON, the finding's evidence line and the window, so a report never says
   "these two responses matched" without saying what was allowed not to match.

`Policy::strict()` sets nothing aside at all, and is what to use when the question is
whether two documents are identical.

**`id`, `uuid` and `key` are never treated as dynamic.** They are precisely what a
cross-identity comparison exists to look at; a policy that set one aside would set
aside the finding. `an_identifier_is_never_treated_as_dynamic` asserts it by name.

**Credential-named fields report the difference and withhold the value.** That a
session token differs between two identities is correct and worth seeing. What it was
does not belong in a comparison, a matrix, or a report — see invariants 4 and 13.

**Duplicate keys are reported rather than collapsed.** `{"id":"1000","id":"1001"}` is
valid JSON that every parser reduces to one key, and which one survives is the
parser's business rather than the application's. The comparison flags the body instead
of comparing something the server did not send.

**The original bytes are never touched.** The normalized form lives inside one
comparison and is never stored, quoted as evidence, or re-sent. Every other layer
still cites the response exactly as it arrived.

**Tests.** `core/types/src/structure.rs` —
`a_strict_policy_sets_nothing_aside`,
`a_field_the_policy_sets_aside_is_still_reported_with_its_reason`,
`the_policy_says_what_it_did`,
`an_identifier_is_never_treated_as_dynamic`,
`a_credential_field_reports_the_change_and_withholds_the_value`,
`a_credential_is_recognised_however_the_application_spells_it`,
`a_repeated_key_is_reported_rather_than_silently_collapsed`,
`the_bodies_are_never_modified`;
`core/authz/src/analysis.rs` —
`a_credential_in_a_body_does_not_reach_the_evidence`,
`the_same_document_without_an_anonymous_control_stays_a_lead`.

---

## Changing an invariant

These can change — but through a deliberate decision recorded in `docs/`, with the
enforcing code and tests updated in the same change. What must not happen is an
invariant quietly ceasing to hold because a new subsystem took a different path to the
network.
