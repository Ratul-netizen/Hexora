# Feature parity target

The goal: **everything a professional does daily in Burp Suite Professional and Caido,
on Windows and Linux**, plus ZAP's automation surface. Network/infrastructure testing is
explicitly out of scope for now — see [`roadmap.md`](roadmap.md).

## The competitive picture

Three competitors, lopsided in three different directions:

| | Manual UX | Scanner | CI / automation | Reporting | Price |
| --- | --- | --- | --- | --- | --- |
| Burp Suite Pro | dated (Swing) | **best in class** | weak — Enterprise only | adequate | ~$475/user/yr |
| Burp Enterprise (DAST) | n/a | best | good | good | **$13,600+/yr** |
| Caido | **best in class** | **none at all** | good | thin | free / $200/yr / $30 user/mo |
| ZAP | worst | good | **best in class** | good (SARIF) | **free**, Apache 2.0 |
| HCL AppScan | scan-and-report (no proxy) | good — SAST+DAST+IAST+SCA, ML triage | good | good (enterprise dashboards) | quote-only, ~$25K–$1M/yr |
| Invicti (ex-Netsparker) | **none** (no proxy/Repeater) | **best in class — proof-based** | good | good | quote-only, ~$20K–$37K/yr |
| Acunetix (by Invicti) | scan-and-report | strong — same engine + OAST | adequate | thin | quote-only, ~$4.5K–$37K/yr |
| **Nullhawk target** | Caido-class | evidence-driven | ZAP-class | **best in class** | TBD |

The table above is the "attacker's toolkit" axis (manual UX first). The three rows added
below it — **HCL AppScan, Invicti, Acunetix** — are a different animal: enterprise DAST
platforms that scan-and-report at scale and are measured on *scanner accuracy*, not manual
UX. They matter here because their whole pitch is the thing Nullhawk is built on — *"is this
finding real?"* — and they charge enterprise money for it. See
[§4a](#4a-the-enterprise-dast-tier) for the detail.

**Nobody holds all four columns.** That is the position worth attacking, and it is more
defensible than price.

Two facts that should kill any pricing-led strategy:

- **ZAP is free, Apache 2.0, and funded.** Checkmarx hired all three project leaders in
  2024. A competent DAST scanner already costs $0, from a team with full-time staff.
- **Caido already took the "cheap and modern" position** at 40% of Burp's price.

Competing on price means fighting a funded free product on one side and an executing
low-cost incumbent on the other. Compete on the combination instead — and specifically
on **time-to-report**, which is where the money actually is for consultancies.

Status labels: **DONE** · **IN PROGRESS** · **PLANNED** · **DEFERRED** · **WON'T BUILD**

Nothing is marked DONE before it works. As of M0, everything below is PLANNED.

---

## 1. Interception and traffic

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| HTTP/1.1 proxy | ✅ | ✅ | PLANNED M2 | |
| HTTPS interception (own CA) | ✅ | ✅ | PLANNED M2 | Per-install CA, never shipped |
| HTTP/2 proxy | ✅ | beta | PLANNED M5 | Caido only reached this in v0.58 — it is hard, and it is table stakes for modern targets |
| WebSocket interception | ✅ | ✅ | PLANNED M6 | |
| HTTP/3 (QUIC) | ⚠️ partial | ❌ | DEFERRED | Nobody has this properly; not a blocker for adoption |
| Invisible / transparent proxying | ✅ | ✅ | PLANNED M5 | Needed for thick clients and mobile |
| Upstream proxy chaining | ✅ | ✅ | PLANNED M5 | |
| Client certificates / mTLS | ✅ | ✅ | PLANNED M5 | |
| Match & Replace rules | ✅ | ✅ | **DONE M7** | `nullhawk matchreplace`: literal or regex rules over request/response headers, bodies and the request first line; empty pattern adds a header, empty replacement removes what matched; applied to in-scope traffic only |
| Traffic history + filtering | ✅ | ✅ | PLANNED M3 | |
| Query language over traffic | Bambda | **HTTPQL** | **DONE M8** | See §6 |

## 2. Manual testing toolkit

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Repeater | ✅ | ✅ Replay | PLANNED M4 | |
| Repeater collections/tabs | ✅ | ✅ | PLANNED M4 | |
| **Request branching with lineage** | ❌ | ❌ | PLANNED M4 | Nullhawk original — variants keep their parent |
| Request pipelines (race conditions) | ⚠️ single-packet | ✅ Pipeline | **DONE M7** | `nullhawk race <request> --count N` replays a captured request N times concurrently and reports the spread; more than one 2xx on a single-use action is the race. Concurrent in-flight sends (HTTP/2 supported); last-byte single-packet synchronisation is a future refinement |
| Comparer (response diff) | ✅ | ⚠️ | PLANNED M4 | |
| Decoder | ✅ | ✅ | PLANNED M7 | |
| Sequencer (token randomness) | ✅ | ❌ | **DONE M9** | `nullhawk sequencer`: from a file of tokens or extracted from captured traffic by response header or cookie name. Reports per-character Shannon entropy and effective bits/token, and flags predictable ones — a sequential/evenly-spaced counter (which fixed length and charset hide), a tiny alphabet, repeats — with a conservative verdict that says plainly when the sample is too small. Caido has no sequencer |
| Site map / target tree | ✅ | ✅ Sitemap | PLANNED M5 | |
| Scope definition | ✅ | ✅ | **DONE M0** | Already enforced, not just represented |
| Session handling rules / macros | ✅ | ⚠️ | **DONE M9/M15.2** | Two complementary paths: `identity refresh` adopts a fresh session from prior proxy traffic; `identity renew` replays a recorded login/refresh request and reads the new token out of its response (a Set-Cookie, a response header, or a dot-path in the JSON body) — the API-token / refresh-endpoint case. Both reshape the value into the identity's credential kind and never print it |

## 3. Automated attack

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Intruder: Sniper | ✅ | ✅ | **DONE M6** | `nullhawk fuzz --mode sniper` (the default); one list walked through each marked position in turn |
| Intruder: Battering Ram | ✅ | ✅ | **DONE M6** | `--mode battering-ram`; one list, the same value in every position at once |
| Intruder: Pitchfork | ✅ | ✅ | **DONE M6** | `--mode pitchfork`; one list per position, advanced in lockstep |
| Intruder: Cluster Bomb | ✅ | ✅ | **DONE M6** | `--mode cluster-bomb`; one list per position, the Cartesian product (memory-bounded to the ceiling) |
| No throttling on Pro | ✅ | ✅ | PLANNED M6 | Community Burp throttles; this is a real adoption driver |
| Payload processing pipeline | ✅ | ✅ | PLANNED M6 | |
| Match/filter on results | ✅ | ✅ | PLANNED M6 | Status, length, regex, JSONPath, similarity, timing |
| Attack result diffing | ✅ split view | ⚠️ | PLANNED M6 | |

## 4. Scanning

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Passive checks | ✅ | ❌ | **IMPLEMENTED M13.2** | Six checks: security headers, cookie attributes, CORS, technology disclosure, cache directives on authenticated responses, recorded TLS. Each result is a *lead* — a passive check cannot state anything more firmly |
| Passive check catalogue size | large | — | **six** | Deliberately small. The differentiator is what a result means, not how many there are |
| Scanner says which checks ran | ⚠️ | — | **IMPLEMENTED M13.2** | A run records every detector and version, including the ones that raised nothing — so "clean" can be told from "never ran" |
| Active scanner | ✅ | ❌ | **IMPLEMENTED M13.3+** | An evidence-driven scanner across the common web-vulnerability classes — see the per-class rows below. Every finding is a verified result, not a signature match; Caido ships no active scanner at all |
| Crawler | ✅ | ❌ | PLANNED M13.8 | Scoped in `roadmap.md` as CR.a–f: a static extractor + a scheduled, scope-guarded frontier, GET-only and never auto-submitting, feeding the scanner's project; JS-rendered discovery merges with browser integration (M18) |
| **Caido ships no active scanner at all** | — | — | — | Strong evidence the market adopts on manual quality first |
| Custom scan checks | BChecks | ❌ | **DONE M15.5** | `nullhawk check`: a check is a saved query (the `nullhawk-query` language) plus a finding template; it runs in the passive scanner and files a lead when it matches. Matches on metadata and headers (body fields refused at add time). By construction it can only ever raise a lead capped at `Confidence::Reported` — never an actionable finding, never an active hypothesis — so a user-written check cannot overclaim. Caido has no check DSL at all |
| Evidence-verified findings | ⚠️ | ⚠️ | **IMPLEMENTED M13.1** | The store accepts only a `Verified`, which only a verification produces — a detector's suspicion does not compile into a finding |
| OAST / Collaborator | ✅ | ⚠️ hosted | **IMPLEMENTED** | Self-hosted HTTP+DNS collaborator (`nullhawk oob serve`) wired into the verification lab: blind SSRF, blind OS command injection and out-of-band SQLi confirm through a callback bearing an unguessable token. No third-party service — the whole point Burp's hosted Collaborator cannot make |
| Findings with Markdown + export | ⚠️ | ✅ | **IMPLEMENTED M12.3** | |
| Finding says which check and version produced it | ⚠️ | — | **IMPLEMENTED M13.2** | Printed in the report, and what lets a retest tell a fix from a rewritten check |
| Runnable proof of concept generated from evidence | ⚠️ manual | ⚠️ manual | **IMPLEMENTED M12.9** | Built from the stored exchanges, with credentials as named placeholders. `curl` where curl can express the request, and a stated reason where it cannot |
| Response comparison names the field that differed | ⚠️ visual diff | ⚠️ visual diff | **IMPLEMENTED M12.10** | By JSON path with array indices kept, under a normalization policy that is reported rather than applied silently. Credential-named fields report the difference and withhold the value |
| Active scanner with a request budget | ✅ | ✅ | **IMPLEMENTED M13.3** | One queue per host rather than a global limit, a plan produced by a function that cannot send, and a run that says when it stopped early instead of reading as clean |
| Scanner says which of its own suspicions it cannot settle | ❌ | ❌ | **IMPLEMENTED M13.3** | `nullhawk detectors` names the dead ends. A suspicion nothing can answer is a gap in the tool, not coverage |
| Reflected input reported with its context | ⚠️ | ⚠️ | **IMPLEMENTED M13.4** | Which characters survived and what they landed inside, under the response's declared content type. A JSON echo is ruled out rather than filed |
| Scanner declines to name a vulnerability class it did not establish | ❌ | ❌ | **IMPLEMENTED M13.4** | The finding says what the bytes did and what it would take to know more. It does not name a vulnerability class |
| Open redirect resolved rather than substring-matched | ⚠️ | ⚠️ | **IMPLEMENTED M13.5** | Protocol-relative, backslash and userinfo forms are resolved the way a browser resolves them; a value merely carried in the header is refuted with the reason |
| Redirect destinations are never followed | ❓ | ❓ | **IMPLEMENTED M13.5** | Invariant 16. The header is read; no request is made to a host the target named |
| Detects a session that is read but not verified | ⚠️ | ⚠️ | **IMPLEMENTED M13.6** | A JWT with one signature character changed, header and payload byte-identical. A cross-identity matrix cannot see this: every identity in one holds a valid token |
| Scanner refuses to replay state-changing requests | ⚠️ | ⚠️ | **IMPLEMENTED M13.6** | Invariant 18, enforced by the scheduler rather than by each check |
| Cross-identity access tested across captured traffic | ⚠️ | ⚠️ | **IMPLEMENTED M13.7** | Owner inferred from the captured credential by exact match, never guessed. Same `replay_once` and confidence ladder as the on-demand matrix |
| Correctly-scoped endpoints are cleared without a declaration | ❌ | ❌ | **IMPLEMENTED M13.7** | Every value differing is the shape of per-caller data; an IDOR returns the owner's values, not different ones |
| SQL injection — error, boolean, time-based **and out-of-band** | ✅ | ❌ | **IMPLEMENTED** | Error- and boolean-differential; then a time-based test that requires the delay to scale from D to 2D (not merely "was slow"); then an OOB path (MSSQL `xp_dirtree`, Oracle `UTL_INADDR`/`UTL_HTTP`) confirmed by a collaborator callback. Reproduced before it is named |
| OS command injection (in-band + **blind via OAST**) | ✅ | ❌ | **IMPLEMENTED** | Proven by the shell evaluating an arithmetic expansion, confirmed by a second sum; where output is not reflected, a payload made to fetch the collaborator confirms the blind case |
| Path traversal | ✅ | ❌ | **IMPLEMENTED** | Confirmed by file-content signatures from outside the application root, not a reflected path |
| Server-side template injection | ✅ | ❌ | **IMPLEMENTED** | The engine computes an arithmetic result the input carried, confirmed by a second product; names the engine family (Jinja/Twig, Freemarker/EL, ERB…) rather than guessing |
| SSRF (cloud-metadata + **blind via OAST**) | ✅ | ❌ | **IMPLEMENTED** | Metadata contents returned from an internal address versus a benign control; a blind fetch that reveals nothing is caught by a collaborator callback |
| Reflected XSS **confirmed in a real browser** | ✅ | ❌ | **IMPLEMENTED** | A reflecting input — a query parameter or a reflected request header (`User-Agent`, `Referer`) — is loaded headless, and filed only when a marker-setting payload actually executes; a value that reflects but is encoded is refuted, not reported as XSS |
| Stored XSS **confirmed in a real browser** | ✅ | ❌ | **IMPLEMENTED** | A payload stored through a GET input, then a clean, payload-free load in the browser; execution on a request that never carried the payload is what separates stored from reflected. POST-body stores are out of reach by the same rule that forbids replaying POST |
| DOM-based XSS (sink tracing) | ✅ DOM Invader | ❌ | **IMPLEMENTED** | Drives a browser with `innerHTML`/`eval`/`document.write` instrumented and files only when a URL source (`location.hash`/`search`) is seen reaching a sink — a flow the server, and any WAF, never sees |
| CRLF / HTTP header injection | ✅ | ❌ | **IMPLEMENTED** | An encoded line break in an input that adds a marker header to the response, confirmed by a second random token; refuted when the break is stripped |
| Sensitive-response caching / exposure | ⚠️ | ❌ | **IMPLEMENTED** | Confirms a shared cache serves one identity's authenticated response to a caller with no session, gated on a declared owned identifier so a public page is not mistaken for a leak |
| Web cache poisoning | ⚠️ (Param Miner ext) | ❌ | **IMPLEMENTED** | An unkeyed header behind a unique cache-buster, confirmed served back to a request that never sent it; the buster means it never poisons a key a real user shares |
| Host header injection (reset poisoning) | ⚠️ | ❌ | **IMPLEMENTED** | Confirms an absolute URL (a reset link, a redirect) is built from a spoofable `X-Forwarded-Host`; the marker must land inside a URL, not merely reflect as text |
| Intruder / payload iteration | ✅ | ✅ | **IMPLEMENTED M14.1** | `nullhawk fuzz`. Responses grouped by `(status, length)` so the outlier is one short row; concludes nothing, because what a difference means is the tester's judgement |
| Payload iteration is rate-limited and stoppable | ⚠️ | ⚠️ | **IMPLEMENTED M14.1** | Reuses the scheduler's budget, pause and Ctrl-C. A truncated list says so rather than reading as "nothing stood out" |

| A header on every request the tool sends | ✅ | ✅ | **IMPLEMENTED M14.2** | `nullhawk header add`, stored on the project. Bug bounty programmes require it so research traffic is attributable; applied before the identity's credential, and never spliced into a raw send |
| Match-and-replace on proxied traffic | ✅ | ✅ | **DONE M7** | General rules now: the request-header add case that `--attach-headers` covered is one shape of it. Body rewrites keep a present `Content-Length` honest; a body/first-line change updates the exchange the proxy forwards and records |

| Programme terms filter what gets reported | ❌ | ❌ | **IMPLEMENTED M14.3** | `nullhawk programme exclude`. Bug bounty programmes reject whole finding classes; a run that files forty of them is a run whose output gets skipped. Excluded classes are still looked for and still named in the report |

| Session handling / re-authentication | ✅ | ✅ | **DONE M15.1/M15.2** | `identity refresh` adopts a session from proxy traffic; `identity renew` replays a recorded login/refresh request and takes the fresh token from its response. Two paths, one for browser sessions and one for API tokens |
| Login sequence recorder | ✅ | ⚠️ | **PARTIAL M15.2** | `identity renew --from <captured login>` replays a single recorded login/refresh request and extracts the new token. A multi-step recorded sequence, and password logins behind captcha/MFA/SSO, remain out of scope by design |

## 4a. The enterprise DAST tier

A different competitive set from Burp/Caido/ZAP: enterprise **DAST platforms** that crawl
and scan at scale, report into governance dashboards, and are bought by AppSec teams rather
than hands-on testers. They are named here because their headline feature is the one
Nullhawk is architected around — *proof that a finding is real* — sold at enterprise prices.

**Corporate note.** **Invicti Security owns both Invicti and Acunetix.** The company was
**Netsparker**, acquired **Acunetix**, and rebranded Netsparker to **Invicti** in 2021.
Today they are deliberately tiered siblings: **Invicti = enterprise** (what was "Acunetix
360" / "Netsparker Cloud" is now **Invicti Enterprise**), **Acunetix = SMB / hands-on**.
The naming is a trap — "Acunetix 360" is effectively Invicti Enterprise, not a separate
Acunetix product. ([invicti.com](https://www.invicti.com/vulnerability-scanner-comparison/invicti-vs-acunetix))

### HCL AppScan

Legacy enterprise AppSec suite (originally IBM AppScan, now HCLSoftware). One of the few
vendors bundling **SAST + DAST + IAST + SCA + API** in one platform, FIPS 140-3 certified,
with centralised governance — bought by large/regulated/government orgs, on-prem
(Enterprise/Standard) or SaaS (AppScan 360°). Accuracy play is **Intelligent Finding
Analytics (IFA)**: ML that clusters and triages findings, claiming **up to ~98% false-
positive reduction**. **No Burp-style proxy / Repeater / Intruder** — it has a
manual-explore step to guide the crawler, but it is scan-and-report, not an interactive
bench. Pricing is quote-only and among the highest in the market: third-party estimates put
DAST at **~$25K–$100K+/yr** and full-platform enterprise deals at **$500K–$1M+**. Criticisms:
dated/cumbersome UI, steep learning curve, slow scans on large sites.
([IFA docs](https://help.hcl-software.com/appscan/ASoC/appseccloud_DAST_IFA.html),
[pricing](https://beaglesecurity.com/blog/article/hcl-appscan-pricing.html))

### Invicti (formerly Netsparker)

Enterprise DAST/ASPM platform, SaaS or on-prem, for teams scanning many apps/APIs at scale.
Its signature is **Proof-Based Scanning**: after the scanner flags a candidate, the engine
**safely, read-only re-exploits it to produce demonstrable evidence** — for suspected SQLi
it runs a benign query returning the DB version; for file inclusion it reads a known system
file — and tags confirmed findings distinctly from unconfirmed. Claims **~99.98% accuracy**
and that **>94% of direct-impact vulns are auto-confirmed**. DAST+IAST (server agent),
out-of-band detection, REST/SOAP/GraphQL API scanning, SPA/DOM crawling, broad auth. But it
is **automation-first, not a manual bench**: a request builder and encoder helpers, but **no
intercepting proxy, no Repeater/Intruder/Sequencer, no extension ecosystem** — the opposite
of Burp. Pricing quote-based, third-party data ~**$20K–$37K/yr**. Criticisms: residual false
positives on framework-protected XSS, weaker complex-auth handling, resource-heavy scans.
([Proof-Based Scanning](https://www.invicti.com/blog/web-security/cutting-through-uncertainty-proof-based-scanning-announcing-white-paper),
[manual tools](https://www.invicti.com/features/advanced-manual-scanning-tools))

### Acunetix (by Invicti)

The **SMB / hands-on sibling** — same core engine and proof-of-exploit philosophy, lighter
and faster, single-instance (Standard) up to multi-user (Premium). Known for **AcuMonitor**
(its **OAST / out-of-band** service catching blind, async and second-order vulns via
callback) and the **AcuSensor** agent for gray-box DAST+IAST. Crawls SPA/JS, scans
REST/SOAP/GraphQL. Again **scan-and-report** — bundles some free standalone manual utilities
(HTTP editor, subdomain scanner) but is not an interactive proxy suite. Pricing quote-based,
~**$4.5K–$37K/yr** by target count. Same criticisms as Invicti, and explicitly *"not a
stand-in for human pentesting."*
([API/OAST](https://www.acunetix.com/product/api-security/),
[pricing](https://pentest.ae/blog/acunetix-pricing-2026/))

### Where Nullhawk stands against this tier

- **Evidence-first is exactly what they monetise — gated behind enterprise licensing.**
  Invicti/Acunetix's Proof-Based Scanning and HCL's ML triage both answer *"is this real?"*.
  Nullhawk answers it structurally — the store accepts only a verified result, and every
  finding compiles a runnable PoC — at practitioner scale, not $20K–$1M/yr.
- **They are scan-and-report engines; none has a manual bench.** Invicti openly has no proxy
  or extension ecosystem; AppScan and Acunetix are scan-and-report. Nullhawk couples
  automated evidence generation *with* a first-class manual toolkit (Repeater, Intruder,
  match-and-replace, sequencer) — the divide none of them cross.
- **Proof-based confirmation only reaches "directly exploitable" classes.** Invicti itself
  auto-confirms ~94% of *direct-impact* vulns; business-logic, auth/authorization
  (IDOR/BOLA) and chained flaws fall back to ML triage or manual review. Nullhawk's
  cross-identity engine confirms exactly the authorization classes their automated proofs
  do not reach — the owner is inferred from the captured credential, never guessed.
- **Their accuracy numbers are vendor claims with a standing asterisk** — reviewers keep
  citing edge-case false positives (framework XSS) and complex-auth friction. Nullhawk's
  browser-confirmed XSS refutes a reflected-but-encoded value instead of filing it, and its
  OAST is self-hosted rather than a vendor service.
- **All three are quote-only, target-metered, multi-year enterprise licensing.** The wedge
  is the same as against Burp/ZAP: a transparent, practitioner-oriented tool that is
  evidence-first *without* the enterprise weight and price.

> Accuracy stats (Invicti 99.98%/94%, HCL ~98% FP reduction) are vendor claims; all pricing
> is third-party/reseller estimate, not a vendor price list — treat as ballpark.

## 5. Extensibility

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Extension API | Montoya (Java) | JS/TS | **DONE M17/M19** | The SDK contract, permission-gated registry, and the WASM sandbox that runs the module. `nullhawk-ext` defines the manifest and `nullhawk ext install/list/permissions/enable/remove` installs with exactly the granted capabilities. `nullhawk-wasm` runs an extension's module (wasmi, a pure-Rust interpreter) with **no host imports** — no filesystem, network or clock — bounded by fuel and a memory cap, so a runaway or hostile module fails the run, not the tool. `nullhawk ext run` executes a passive-check module (exchange JSON in, observations out); validated with a real Rust guest compiled to wasm32. Wiring the runtime into the scanner loop, and the store, remain. See docs/extensions.md |
| Extension store | BApp Store | Plugin store | PLANNED M19 | Depends on the WASM runtime |
| Permission model for extensions | ❌ | ❌ | **DONE M0** | Neither competitor has one |
| Burp extension compatibility | — | mapping docs | DEFERRED M20+ | Separate subproject; out-of-process JVM |

## 6. Query, automation, workflow

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Traffic query language | Bambda (Java) | HTTPQL | **DONE M8** | `nullhawk-query`: boolean logic (AND/OR/NOT, implicit AND, parens) over `field OP value` clauses — `:` contains, `= != > < >= <=`, `~ !~` regex — across method/host/path/url/scheme/port/ext/status/duration/identity/origin/secure/sizes and the header/body fields. Wired into `nullhawk history --query` and the desktop History query box; bodies are read back only when a query mentions them |
| Node-based workflows | ❌ | ✅ | PLANNED M10 | |
| Scripted automation | Bambda | JS nodes | PLANNED M10 | |
| Headless / CLI | ⚠️ Enterprise | ✅ server mode | **DONE (CLI) M11** | The whole tool is a headless CLI already; `nullhawk run <plan.yaml>` drives a full engagement non-interactively. A long-running client/server split (run on a VPS) is still to do |
| CI/CD integration | Enterprise only | ⚠️ | **DONE M11** | `nullhawk run` executes a declarative plan and, via `fail_on`, exits non-zero when findings cross a severity — a pipeline gate. Findings export as SARIF for GitHub code scanning. This is Burp-Enterprise-tier automation at the CLI, no separate product |

## 7. Browser integration

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Embedded browser | ✅ Chromium | ⚠️ | **DONE M18** | Drives the user's installed Chrome/Edge over CDP (a throwaway profile, killed on drop) rather than shipping a 150 MB Chromium — `core/browser`, used by `nullhawk domxss` |
| DOM XSS testing | DOM Invader | ❌ | **DONE M18** | `nullhawk domxss <url>`: installs sink instrumentation over CDP (innerHTML/outerHTML, insertAdjacentHTML, document.write, eval, string timers), navigates with a canary in `location.hash` and `location.search`, and reports each proven source→sink flow. Caido has none |
| Pre-configured proxy + cert | ✅ | ✅ | PLANNED M18 | |

## 8. AI

| Capability | Burp Pro | Caido | Nullhawk | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Payload suggestions | Burp AI | ⚠️ | PLANNED M21 | |
| Explain request/finding | Burp AI | ⚠️ | PLANNED M21 | |
| Autonomous follow-up | Explore Issue | ❌ | PLANNED M21 | |
| **Tool-permission gate** | ❌ | ❌ | **DONE M0** | Neither competitor gates AI actions |
| **Evidence required for AI claims** | ❌ | ❌ | **DONE M0** | |

## 9. Nullhawk-only

Not parity — reasons to switch.

| Capability | Status | Why it matters |
| ---------- | ------ | -------------- |
| Multi-identity authorization testing | PLANNED M12 | Replay one request as anonymous/userA/userB/admin and diff. The highest-value manual work in most engagements, and almost entirely mechanical |
| Evidence-gated findings | designed M0 | A finding cannot claim confidence it has not earned |
| Extension permission model | DONE M0 | |
| AI tool gate | DONE M0 | |
| Attack chains with retained evidence | PLANNED M12 | Report is close to automatic |
| Scope enforced at a chokepoint | DONE M0 | |

## What to take from ZAP

ZAP is worth mining specifically for its **automation surface**, not its scan rules.
That distinction is what keeps this from being a scope explosion: the automation items
below are mostly cheap, and several are things we would have had to invent anyway.

| Adopt | Effort | Where | Why |
| ----- | ------ | ----- | --- |
| **Declarative YAML automation plans** | low | M10 | **DONE** — `nullhawk run <plan.yaml>`: an ordered `project → scope → import → crawl → scan → report` plan, run non-interactively (the plan is the consent), with `fail_on` to gate CI. Visual node workflows (for humans) are still to do; the YAML plan (for pipelines) is the one that matters here |
| **SARIF output** | very low | M11 | **DONE** — `nullhawk report --format sarif` renders SARIF 2.1.0 (valid against the schema; findings at their severity level, leads as notes, no credentials). GitHub code scanning ingests it natively |
| **Docker images + daemon mode** | medium | M11 | Already planned, but ZAP proves it must be first-class rather than an afterthought |
| **Contexts** | medium | M9 | ZAP groups URLs + auth + session + technology into one object. A distinctly better model than Burp's scattered scope / session-rule / macro configuration, and session handling is the thing everyone hates |
| **Browser-driven crawling** | high | M13+M18 | In July 2026 ZAP made its **Client Spider the recommended crawler**, replacing the AJAX Spider. This independently confirms the "drive a real browser over CDP" decision — and means the crawler and browser-integration milestones should merge rather than be built twice |
| **OpenAPI / GraphQL / SOAP importers** | low | M5 | **OpenAPI 3.x + Swagger 2.0 DONE** (`nullhawk import openapi`, JSON/YAML): parses the spec, fills path params and required query params, and — with `--send` — fetches the safe operations through the scope guard and records them for scanning, the frontier the crawler cannot find because an API has no HTML links. GraphQL DONE too (`nullhawk import graphql`: parses an introspection result, generates a sendable query per root field — required args filled, `{ __typename }` where it returns an object — and POSTs the queries; mutations only with `--include-mutations`). SOAP still to do |
| **Alert filters** | low | M13.2 | False-positive suppression. Consultancies need it; Caido lacks it |

### What we will not take from ZAP

| | Why |
| --- | --- |
| Porting ZAP's scan rules | Apache 2.0 permits it, but they are Java, there are hundreds, and we would be maintaining a fork of someone else's ongoing research forever. **Read them as a reference for check design** — that is the real value of the licence — and write our own against the evidence model |
| The HUD browser overlay | Genuinely clever, genuinely niche |
| Zest | Legacy scripting format |
| Multi-language scripting (Jython, Groovy, JS, …) | Pick TypeScript and WASM. Supporting four runtimes is four sandboxes to secure |

**Scope discipline:** M1–M5 do not change because of any of this. SARIF and YAML plans
fold into M10/M11 where they are nearly free. Everything else is *reordering*, not
addition.

## What we will not build

| | Why |
| --- | --- |
| Network/infrastructure scanning | Different product. Revisit after web parity |
| Exploitation framework, C2, payloads | Different product, different liability |
| Our own CVE database | Never maintain one; consume NVD/OSV |
| Bundled Nmap | [NPSL forbids redistribution in proprietary/commercial products](https://nmap.org/npsl/) and Windows builds bundle Npcap, which [also forbids redistribution without an OEM licence](https://npcap.com/oem/redist). Detect-and-invoke only, if ever |
| Bundled Chromium | 150 MB for a feature CDP gives us against the user's own browser |
| Enterprise scan farm | Burp Enterprise territory; not a solo-buildable product |

## Licensing notes for anything we integrate

- **Nuclei / nuclei-templates — MIT.** Safe to integrate and even bundle. The most
  attractive integration target if we ever want off-the-shelf checks.
- **Nmap — NPSL.** Not GPL. Prohibits inclusion in proprietary/commercial products;
  OEM licence required for embedding.
- **Npcap — proprietary.** Free version does not permit redistribution.

Nullhawk is AGPL-3.0, which changes the analysis versus a proprietary product, but
"invoke a tool the user installed" is materially safer than "ship it" in every case.
Get advice before bundling anything.

---

## Sources

- [Burp Suite Professional releases](https://portswigger.net/burp/releases/professional-community-edition-2026-2-3)
- [Burp Suite feature overview 2026](https://codeant.ai/blogs/burp-suite-features)
- [Caido v0.58.0 — Replay Pipeline, HTTP/2 beta, HTTPQL](https://www.caido.io/blog/2026-08-24-release-v0-58-0/)
- [Caido v0.57.0](https://www.caido.io/blog/2026-06-05-release-v0-57-0/)
- [Caido — Burp Suite tool mapping](https://docs.caido.io/burp-suite/core/tools)
- [Nmap Public Source License](https://nmap.org/npsl/)
- [Npcap OEM redistribution licence](https://npcap.com/oem/redist)
- [Nuclei documentation](https://docs.projectdiscovery.io/opensource/nuclei/overview)
- [ZAP Updates — July 2026 (Client Spider becomes the recommended crawler)](https://www.zaproxy.org/blog/2026-08-06-zap-updates-july-2026/)
- [ZAP Automation Framework](https://www.securecodebox.io/docs/scanners/zap-automation-framework/)
- [ZAP review 2026](https://appsecsanta.com/zap)
- [Burp Suite pricing](https://www.g2.com/products/burp-suite/pricing)
- [Caido vs Burp Suite comparison](https://afine.com/blogs/caido-vs-burp-suite-a-penetration-testers-comparison)
