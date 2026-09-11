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
| **Hexora target** | Caido-class | evidence-driven | ZAP-class | **best in class** | TBD |

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

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| HTTP/1.1 proxy | ✅ | ✅ | PLANNED M2 | |
| HTTPS interception (own CA) | ✅ | ✅ | PLANNED M2 | Per-install CA, never shipped |
| HTTP/2 proxy | ✅ | beta | PLANNED M5 | Caido only reached this in v0.58 — it is hard, and it is table stakes for modern targets |
| WebSocket interception | ✅ | ✅ | PLANNED M6 | |
| HTTP/3 (QUIC) | ⚠️ partial | ❌ | DEFERRED | Nobody has this properly; not a blocker for adoption |
| Invisible / transparent proxying | ✅ | ✅ | PLANNED M5 | Needed for thick clients and mobile |
| Upstream proxy chaining | ✅ | ✅ | PLANNED M5 | |
| Client certificates / mTLS | ✅ | ✅ | PLANNED M5 | |
| Match & Replace rules | ✅ | ✅ | PLANNED M7 | Caido's redesign (param/header-aware) is the better model to copy |
| Traffic history + filtering | ✅ | ✅ | PLANNED M3 | |
| Query language over traffic | Bambda | **HTTPQL** | PLANNED M8 | See §6 |

## 2. Manual testing toolkit

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Repeater | ✅ | ✅ Replay | PLANNED M4 | |
| Repeater collections/tabs | ✅ | ✅ | PLANNED M4 | |
| **Request branching with lineage** | ❌ | ❌ | PLANNED M4 | Hexora original — variants keep their parent |
| Request pipelines (race conditions) | ⚠️ single-packet | ✅ Pipeline | PLANNED M7 | Caido's Pipeline is the reference |
| Comparer (response diff) | ✅ | ⚠️ | PLANNED M4 | |
| Decoder | ✅ | ✅ | PLANNED M7 | |
| Sequencer (token randomness) | ✅ | ❌ | PLANNED M9 | Rarely used but pros expect it |
| Site map / target tree | ✅ | ✅ Sitemap | PLANNED M5 | |
| Scope definition | ✅ | ✅ | **DONE M0** | Already enforced, not just represented |
| Session handling rules / macros | ✅ | ⚠️ | PLANNED M9 | The thing people hate configuring; big UX opportunity |

## 3. Automated attack

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Intruder: Sniper | ✅ | ✅ | PLANNED M6 | |
| Intruder: Battering Ram | ✅ | ✅ | PLANNED M6 | |
| Intruder: Pitchfork | ✅ | ✅ | PLANNED M6 | |
| Intruder: Cluster Bomb | ✅ | ✅ | PLANNED M6 | |
| No throttling on Pro | ✅ | ✅ | PLANNED M6 | Community Burp throttles; this is a real adoption driver |
| Payload processing pipeline | ✅ | ✅ | PLANNED M6 | |
| Match/filter on results | ✅ | ✅ | PLANNED M6 | Status, length, regex, JSONPath, similarity, timing |
| Attack result diffing | ✅ split view | ⚠️ | PLANNED M6 | |

## 4. Scanning

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Passive checks | ✅ | ❌ | **IMPLEMENTED M13.2** | Six checks: security headers, cookie attributes, CORS, technology disclosure, cache directives on authenticated responses, recorded TLS. Each result is a *lead* — a passive check cannot state anything more firmly |
| Passive check catalogue size | large | — | **six** | Deliberately small. The differentiator is what a result means, not how many there are |
| Scanner says which checks ran | ⚠️ | — | **IMPLEMENTED M13.2** | A run records every detector and version, including the ones that raised nothing — so "clean" can be told from "never ran" |
| Active scanner | ✅ | ❌ | PLANNED M13.3–M13.7 | |
| Crawler | ✅ | ❌ | NOT PLANNED YET | Hexora scans traffic it was given; discovering endpoints on its own is a separate question |
| **Caido ships no active scanner at all** | — | — | — | Strong evidence the market adopts on manual quality first |
| Custom scan checks | BChecks | ❌ | PLANNED M15 | |
| Evidence-verified findings | ⚠️ | ⚠️ | **IMPLEMENTED M13.1** | The store accepts only a `Verified`, which only a verification produces — a detector's suspicion does not compile into a finding |
| OAST / Collaborator | ✅ | ⚠️ hosted | PLANNED M16 | Self-hostable is a selling point |
| Findings with Markdown + export | ⚠️ | ✅ | **IMPLEMENTED M12.3** | |
| Finding says which check and version produced it | ⚠️ | — | **IMPLEMENTED M13.2** | Printed in the report, and what lets a retest tell a fix from a rewritten check |
| Runnable proof of concept generated from evidence | ⚠️ manual | ⚠️ manual | **IMPLEMENTED M12.9** | Built from the stored exchanges, with credentials as named placeholders. `curl` where curl can express the request, and a stated reason where it cannot |
| Response comparison names the field that differed | ⚠️ visual diff | ⚠️ visual diff | **IMPLEMENTED M12.10** | By JSON path with array indices kept, under a normalization policy that is reported rather than applied silently. Credential-named fields report the difference and withhold the value |
| Active scanner with a request budget | ✅ | ✅ | **IMPLEMENTED M13.3** | One queue per host rather than a global limit, a plan produced by a function that cannot send, and a run that says when it stopped early instead of reading as clean |
| Scanner says which of its own suspicions it cannot settle | ❌ | ❌ | **IMPLEMENTED M13.3** | `hexora detectors` names the dead ends. A suspicion nothing can answer is a gap in the tool, not coverage |
| Reflected input reported with its context | ⚠️ | ⚠️ | **IMPLEMENTED M13.4** | Which characters survived and what they landed inside, under the response's declared content type. A JSON echo is ruled out rather than filed |
| Scanner declines to name a vulnerability class it did not establish | ❌ | ❌ | **IMPLEMENTED M13.4** | The finding says what the bytes did and what it would take to know more. It does not name a vulnerability class |
| Open redirect resolved rather than substring-matched | ⚠️ | ⚠️ | **IMPLEMENTED M13.5** | Protocol-relative, backslash and userinfo forms are resolved the way a browser resolves them; a value merely carried in the header is refuted with the reason |
| Redirect destinations are never followed | ❓ | ❓ | **IMPLEMENTED M13.5** | Invariant 16. The header is read; no request is made to a host the target named |
| Detects a session that is read but not verified | ⚠️ | ⚠️ | **IMPLEMENTED M13.6** | A JWT with one signature character changed, header and payload byte-identical. A cross-identity matrix cannot see this: every identity in one holds a valid token |
| Scanner refuses to replay state-changing requests | ⚠️ | ⚠️ | **IMPLEMENTED M13.6** | Invariant 18, enforced by the scheduler rather than by each check |
| Cross-identity access tested across captured traffic | ⚠️ | ⚠️ | **IMPLEMENTED M13.7** | Owner inferred from the captured credential by exact match, never guessed. Same `replay_once` and confidence ladder as the on-demand matrix |
| Correctly-scoped endpoints are cleared without a declaration | ❌ | ❌ | **IMPLEMENTED M13.7** | Every value differing is the shape of per-caller data; an IDOR returns the owner's values, not different ones |
| Intruder / payload iteration | ✅ | ✅ | **IMPLEMENTED M14.1** | `hexora fuzz`. Responses grouped by `(status, length)` so the outlier is one short row; concludes nothing, because what a difference means is the tester's judgement |
| Payload iteration is rate-limited and stoppable | ⚠️ | ⚠️ | **IMPLEMENTED M14.1** | Reuses the scheduler's budget, pause and Ctrl-C. A truncated list says so rather than reading as "nothing stood out" |

| A header on every request the tool sends | ✅ | ✅ | **IMPLEMENTED M14.2** | `hexora header add`, stored on the project. Bug bounty programmes require it so research traffic is attributable; applied before the identity's credential, and never spliced into a raw send |
| Match-and-replace on proxied traffic | ✅ | ✅ | ❌ | M14.2 covers requests Hexora sends. Traffic through the proxy is the browser's and is not rewritten, so manual browsing still needs the header set in the browser |

| Programme terms filter what gets reported | ❌ | ❌ | **IMPLEMENTED M14.3** | `hexora programme exclude`. Bug bounty programmes reject whole finding classes; a run that files forty of them is a run whose output gets skipped. Excluded classes are still looked for and still named in the report |

## 5. Extensibility

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Extension API | Montoya (Java) | JS/TS | PLANNED M17 | TypeScript first |
| Extension store | BApp Store | Plugin store | PLANNED M19 | |
| Permission model for extensions | ❌ | ❌ | **DONE M0** | Neither competitor has one |
| Burp extension compatibility | — | mapping docs | DEFERRED M20+ | Separate subproject; out-of-process JVM |

## 6. Query, automation, workflow

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Traffic query language | Bambda (Java) | HTTPQL | PLANNED M8 | HTTPQL's approach is far friendlier than compiling Java lambdas |
| Node-based workflows | ❌ | ✅ | PLANNED M10 | |
| Scripted automation | Bambda | JS nodes | PLANNED M10 | |
| Headless / CLI | ⚠️ Enterprise | ✅ server mode | PLANNED M11 | Caido's client/server split (run on a VPS) is genuinely better |
| CI/CD integration | Enterprise only | ⚠️ | PLANNED M11 | |

## 7. Browser integration

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Embedded browser | ✅ Chromium | ⚠️ | PLANNED M18 | **Drive the user's installed Chrome over CDP** rather than shipping a 150 MB Chromium |
| DOM XSS testing | DOM Invader | ❌ | PLANNED M18 | |
| Pre-configured proxy + cert | ✅ | ✅ | PLANNED M18 | |

## 8. AI

| Capability | Burp Pro | Caido | Hexora | Notes |
| ---------- | :------: | :---: | ------ | ----- |
| Payload suggestions | Burp AI | ⚠️ | PLANNED M21 | |
| Explain request/finding | Burp AI | ⚠️ | PLANNED M21 | |
| Autonomous follow-up | Explore Issue | ❌ | PLANNED M21 | |
| **Tool-permission gate** | ❌ | ❌ | **DONE M0** | Neither competitor gates AI actions |
| **Evidence required for AI claims** | ❌ | ❌ | **DONE M0** | |

## 9. Hexora-only

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
| **Declarative YAML automation plans** | low | M10 | ZAP's Automation Framework is the entire CI story in one file. Visual workflows are for humans; YAML is for pipelines. We need both, and currently plan only the first |
| **SARIF output** | very low | M11 | The DevSecOps lingua franca — GitHub code scanning ingests it natively. Almost free, and it feeds the time-to-report thesis |
| **Docker images + daemon mode** | medium | M11 | Already planned, but ZAP proves it must be first-class rather than an afterthought |
| **Contexts** | medium | M9 | ZAP groups URLs + auth + session + technology into one object. A distinctly better model than Burp's scattered scope / session-rule / macro configuration, and session handling is the thing everyone hates |
| **Browser-driven crawling** | high | M13+M18 | In July 2026 ZAP made its **Client Spider the recommended crawler**, replacing the AJAX Spider. This independently confirms the "drive a real browser over CDP" decision — and means the crawler and browser-integration milestones should merge rather than be built twice |
| **OpenAPI / GraphQL / SOAP importers** | low | M5 | Cheap, high value for API work |
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

Hexora is AGPL-3.0, which changes the analysis versus a proprietary product, but
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
