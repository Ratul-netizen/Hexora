# Nullhawk — User Manual

**The modern offensive security workbench.** Nullhawk is a web and API security testing
platform for **authorized** penetration testing and security research: an intercepting proxy,
a repeater, an intruder, an evidence-driven scanner, authorization testing, a scope-checked
crawler, an out-of-band collaborator, LLM and DOM-XSS testing, and a headless CI runner — with
a command-line interface and a desktop app over the same engine.

> ⚠️ **Authorized use only.** Point Nullhawk at systems you own or have explicit written
> permission to test. The proxy can decrypt TLS, the scanner and intruder send traffic, and the
> collaborator receives callbacks — all of which are hostile acts against a system you are not
> authorized to test. You are responsible for staying inside your engagement's scope and rules.

---

## Contents

1. [Install](#1-install)
2. [Licensing: free and Pro](#2-licensing-free-and-pro)
3. [First run](#3-first-run)
4. [Core concepts](#4-core-concepts)
5. [Capturing traffic](#5-capturing-traffic)
6. [Reviewing and replaying](#6-reviewing-and-replaying)
7. [Scope, programme, and identity headers](#7-scope-programme-and-identity-headers)
8. [Identities and authorization testing](#8-identities-and-authorization-testing)
9. [Scanning: passive and active](#9-scanning-passive-and-active)
10. [Intruder, fuzzing, race, and sequencer](#10-intruder-fuzzing-race-and-sequencer)
11. [Coverage: crawler and import](#11-coverage-crawler-and-import)
12. [Specialized testing: DOM-XSS, LLM, out-of-band](#12-specialized-testing)
13. [Extensions](#13-extensions)
14. [Findings, proof, and reporting](#14-findings-proof-and-reporting)
15. [Snapshots and retest](#15-snapshots-and-retest)
16. [The CI runner](#16-the-ci-runner)
17. [The desktop app](#17-the-desktop-app)
18. [Command reference](#18-command-reference)
19. [Getting help](#19-getting-help)

---

## 1. Install

**Desktop app (recommended for interactive work).** Download the installer for your OS from the
project's releases and run it:

- **Windows** — `Nullhawk_<version>_x64-setup.exe` (installer) or the `.msi`.
- **macOS** — `Nullhawk_<version>_universal.dmg` (Intel + Apple Silicon).
- **Linux** — `.deb`, `.rpm`, or the `.AppImage`.

Pre-release builds are **unsigned**, so the OS will warn ("unknown publisher" / Gatekeeper). On
Windows choose **More info → Run anyway**; on macOS right-click the app → **Open** the first time.

**CLI.** Download the `nullhawk` binary for your OS from the same release, or build from source:

```
cargo build --release -p nullhawk-cli
# binary at target/release/nullhawk (nullhawk.exe on Windows)
```

The CLI is a terminal tool — run it from a shell, not by double-clicking. Verify:

```
nullhawk --version
```

---

## 2. Licensing: free and Pro

Nullhawk runs at the **free tier** with no licence. A Pro licence unlocks the features that send
significant traffic or serve teams.

| Capability | Free | Pro |
| --- | :---: | :---: |
| Intercepting proxy, CA, `send` | ✅ | ✅ |
| History, repeater, match & replace | ✅ | ✅ |
| **Passive** scanner | ✅ | ✅ |
| Identities, identifiers, authorization replay | ✅ | ✅ |
| Crawler, import, sequencer, DOM-XSS, extensions | ✅ | ✅ |
| Findings, PoC, Markdown/HTML reports | ✅ | ✅ |
| **Active** scanner (sends its own traffic) | — | ✅ |
| **Intruder** without a throttle | — | ✅ |
| **SARIF** export (for CI) | — | ✅ |
| **Snapshots** and retest comparison | — | ✅ |
| Shared **team** projects, audit log, SSO | — | ✅ |

Activate a licence:

```
nullhawk license activate your-licence.nullhawklic   # or via the desktop Licence tab
nullhawk license show                                # tier, licensee, expiry
```

Without a valid licence, a Pro-gated command stops with a message naming the feature; nothing is
silently degraded.

---

## 3. First run

The fastest path sets up a project, the interception CA, and OS trust in one step:

```
nullhawk setup ./engagement
```

It asks before touching your trust store — **installing the CA is the most consequential thing
Nullhawk does**, and it never happens as a side effect. To set everything up but leave trust
alone, add `--no-trust`. Everything `setup` does can also be done a command at a time:

```
nullhawk project init ./engagement           # create the project
nullhawk ca --dir ./engagement --install     # create + trust the interception CA
nullhawk scope add ./engagement example.com  # declare what you're allowed to touch
```

A **project** is a directory. Every command that reads or writes engagement data takes the
project path as an argument.

---

## 4. Core concepts

**Project.** A directory holding captured traffic, scope, identities, findings, settings, and
extensions. Portable — the whole engagement travels as one folder.

**Scope.** The hosts you are authorized to touch. In-scope declarations gate the scanner, the
crawler, and the automated senders; exclusions always win over inclusions. Scoping is a safety
rail, not a convenience.

**The confidence ladder.** Nullhawk separates what it *saw* from what it *proved*:

- **Observation → lead** — a fact from passive analysis (e.g. "no HSTS on an HTTPS response").
  Capped at *reported* confidence: a lead to check, never a declared vulnerability.
- **Hypothesis** — a suspicion a passive pass raised but cannot settle without sending something
  (e.g. a possibly-reflected origin). It waits for a verifier.
- **Verified finding** — a hypothesis an **active** experiment established.

This is why the passive scanner is safe to run any time (it only reads captured traffic) and the
active scanner is a separate, spelled-out act (it sends). A passive check can never overclaim.

**Credentials are redacted.** When an exchange is stored, credential request headers and
`Set-Cookie` values are replaced, so checks, reports, and extensions cannot leak a session token.

---

## 5. Capturing traffic

**The proxy.** Point a browser (or any client) at Nullhawk and it sees the traffic:

```
nullhawk proxy --project ./engagement --listen 127.0.0.1:8080
```

Configure your browser/system to use `127.0.0.1:8080` as its HTTP/HTTPS proxy, and install the
CA (`nullhawk ca --install`) so HTTPS can be decrypted. Useful flags:

- `--only <host>` — decrypt only this host; tunnel everything else untouched (the safer posture).
- `--exempt <host>` — never decrypt this host (use for certificate-pinned apps); accepts `*.` wildcards.
- `--in-scope-only` — record only in-scope traffic.
- `-k, --insecure-upstream` — don't verify the target's certificate (staging with self-signed certs).
- `--attach-headers` — put the project's attached headers on in-scope requests your browser makes
  (see [§7](#7-scope-programme-and-identity-headers)).

**The CA.** Manage the interception certificate authority:

```
nullhawk ca --dir ./engagement            # show the CA, fingerprint, and trust status
nullhawk ca --dir ./engagement --install  # trust it (asks first)
nullhawk ca --dir ./engagement --export ca.pem   # write the cert + trust instructions
nullhawk ca --dir ./engagement --uninstall       # untrust and delete
```

**One-off requests.** `send` is like `curl`, except nothing you wrote is rewritten — header
order, casing, and duplicates go out exactly as given:

```
nullhawk send https://example.com/login -X POST -H 'Content-Type: application/json' -d '{"u":"a"}'
```

Add `-k` to accept any TLS cert (reported every time), `--client-cert`/`--client-key` for mTLS.

---

## 6. Reviewing and replaying

**History** browses what the proxy captured:

```
nullhawk history ./engagement                       # list exchanges
nullhawk history ./engagement --query 'status>=500 AND host:api'
nullhawk history ./engagement --body <request-id>   # dump one response body
```

See the query fields with `nullhawk help history`.

**Repeat** (the repeater) resends a captured request, optionally editing it first. It sends the
request *exactly* as saved — a wrong `Content-Length` is reported, never silently corrected:

```
nullhawk repeat ./engagement <request-id> --edit     # opens in $EDITOR
nullhawk repeat ./engagement <request-id> --dry-run  # show what would be sent
nullhawk repeat ./engagement <request-id> --raw      # edit and send as raw bytes
nullhawk repeat ./engagement <request-id> --variants # show derived variants
```

Raw mode preserves bare LFs, wrong lengths, and duplicate-header order; structured mode
serializes a clean message model.

**Match & replace** rewrites proxied traffic with rules (Burp/Caido-style):

```
nullhawk matchreplace ./engagement ...   # add/list/replace rules; applies to in-scope traffic
```

---

## 7. Scope, programme, and identity headers

**Scope** declares what you may touch:

```
nullhawk scope add ./engagement example.com
nullhawk scope add ./engagement '*.example.com' --path-prefix /api
nullhawk scope add ./engagement staging.example.com --exclude   # exclusions win
nullhawk scope list ./engagement
```

**Programme** records the engagement's terms — the rules Nullhawk must obey and what the target
will not accept (e.g. a bug-bounty programme's constraints):

```
nullhawk programme ./engagement ...
```

**Attached headers** are identification headers a programme may require on your traffic (for
example `X-HackerOne-Research`). Declare them once and Nullhawk puts them on in-scope requests it
sends, and on your browser's in-scope traffic when the proxy runs with `--attach-headers`:

```
nullhawk header ./engagement ...
```

---

## 8. Identities and authorization testing

**Identities** are the personae a project tests as (e.g. `admin`, `user-a`, `anonymous`):

```
nullhawk identity ./engagement ...    # add/list/manage identities and their credentials
```

**Identifiers and objects** find and declare object references for access-control testing.
Analysis reads captured traffic and offers values that *vary* where an identifier would; it sends
nothing and declares no ownership on its own:

```
nullhawk identifiers ./engagement --analyze     # offer candidate identifiers
nullhawk identifiers ./engagement --accept <value>
nullhawk object ./engagement ...                # declare which identifiers are objects, and who owns them
```

**Authorization testing** (`authz`) replays a captured request as several identities and compares
what came back — the core IDOR/BOLA and privilege-escalation check:

```
nullhawk authz ./engagement <request-id>                 # replay as every other identity
nullhawk authz ./engagement <request-id> --as user-b     # replay as specific identities
nullhawk authz ./engagement <request-id> --confirm       # replay a violation again before reporting
```

Use `--unsafe` deliberately for requests whose method may change data.

---

## 9. Scanning: passive and active

**Passive** (free) reads only what's already captured and sends nothing, so it's safe at any
point in an engagement:

```
nullhawk scan passive ./engagement
nullhawk scan passive ./engagement --detector cache.sensitive   # one check
nullhawk scan passive ./engagement --host api.example.com --since 2026-01-01T00:00:00Z
nullhawk scan passive ./engagement --no-save                    # print without recording
```

It produces **observations** (facts, filed as leads) and **hypotheses** (suspicions that wait for
a verifier). List the built-in checks with `nullhawk detectors`.

**Active** (**Pro**) settles the hypotheses a passive pass raised by running experiments — this
is the only `scan` pass that sends traffic to the target:

```
nullhawk scan active ./engagement --dry-run   # show exactly what would be sent, and to which hosts
nullhawk scan active ./engagement             # run the experiments
```

An active run only tests hypotheses a passive pass already raised — nothing is invented — so run
`scan passive` first.

---

## 10. Intruder, fuzzing, race, and sequencer

**Fuzz / intruder** sends one request many times, once per payload, and compares what came back.
The unthrottled intruder is **Pro**; a throttled run is available at the free tier:

```
nullhawk fuzz ./engagement <request-id> ...     # payload positions and lists
```

**Race** sends one captured request many times at once, to find a race condition (single-use
codes, balance/redeem flows):

```
nullhawk race ./engagement <request-id> ...
```

**Sequencer** measures how unpredictable a token is — session IDs, CSRF and reset tokens:

```
nullhawk sequencer ./engagement ...
```

---

## 11. Coverage: crawler and import

**Crawl** widens coverage by fetching in-scope pages and feeding them to the project. It respects
scope; out-of-scope links are recorded, not fetched, unless you name them explicitly:

```
nullhawk crawl ./engagement ...
```

**Import** turns an API description into traffic the scanner can work over:

```
nullhawk import openapi ./engagement spec.yaml     # OpenAPI 3.x / Swagger 2.0
nullhawk import graphql ./engagement introspection.json
```

---

## 12. Specialized testing

**DOM-XSS** drives a real browser to find DOM-based cross-site scripting (a DOM Invader analog):

```
nullhawk domxss ./engagement ...
```

**LLM** endpoints are surfaced by a dedicated passive check and can be probed for prompt-handling
issues (see the `llm.endpoint` detector).

**Out-of-band (OOB) collaborator** provides a callback host for detecting blind SSRF, blind
injection, and similar out-of-band interactions. Callbacks it receives are correlated back to the
request that caused them.

---

## 13. Extensions

An extension is a manifest plus a WebAssembly module. It receives **only** the capabilities you
approve — nothing is granted implicitly — and the exact grant is recorded in the project. A
passive-check extension runs in a sandbox (no filesystem, network, or clock; bounded by fuel and
memory) over each captured exchange during `scan passive`, folding its observations in as leads.

```
nullhawk ext install ./engagement jwt-tools.manifest.yaml          # grants required capabilities only
nullhawk ext install ./engagement jwt-tools.manifest.yaml --grant-all
nullhawk ext list ./engagement
nullhawk ext permissions ./engagement com.example.jwt-tools
nullhawk ext enable|disable ./engagement com.example.jwt-tools
nullhawk ext run jwt-tools.manifest.yaml --exchange exchange.json  # test a module against one exchange
```

If a *required* capability is declined, the extension installs **disabled** rather than
half-working. See [`docs/extensions.md`](./extensions.md) to write one.

---

## 14. Findings, proof, and reporting

**Findings** are read and triaged from the project:

```
nullhawk findings ./engagement            # list, with severity, confidence, and status
nullhawk findings ./engagement <id> ...   # inspect and triage
```

Every passive finding is a **lead** until verified — it says what was seen, not that the target
is exploitable.

**PoC** compiles a finding into steps someone can run:

```
nullhawk poc ./engagement <finding-id>
```

**Report** turns a project's findings into a document to hand over:

```
nullhawk report ./engagement --format markdown > report.md
nullhawk report ./engagement --format html > report.html
nullhawk report ./engagement --format sarif > findings.sarif   # SARIF is Pro (for CI)
```

Reports state coverage honestly ("what was tested, not a clean bill of health") and keep
credentials redacted. Response bodies quoted into a report are shown as the application served
them — review before sharing.

---

## 15. Snapshots and retest

**Snapshots** (**Pro**) record what an engagement looks like at a moment and compare two moments,
so a retest can show what was fixed, what regressed, and what is new:

```
nullhawk snapshot ./engagement ...        # record now, or compare two snapshots
```

Because findings carry the detector and version that produced them, a claim that stopped
appearing because a *check* was rewritten is not mistaken for one that was fixed.

---

## 16. The CI runner

**Run** executes a declarative plan file end to end — import, crawl, scan, report — for a
pipeline:

```
nullhawk run plan.yaml
```

Pair it with a gate file to fail the build on findings above a threshold, and with SARIF export
(Pro) to surface findings in your CI's security tab.

---

## 17. The desktop app

The desktop app is the same engine behind a window, organized into tabs that mirror the CLI:

- **Setup** — project, scope, identities, attached headers, programme, and session renewal.
- **Proxy / History** — live capture and the captured-traffic browser.
- **Repeater** — edit and resend requests.
- **Scan / Findings** — run passive (and active, with Pro) scans and triage findings.
- **Authz, Race, DOM-XSS, Sequencer, Import** — the specialized tools.
- **Licence** — activate a licence and see the current tier.

The interface and engine negotiate a version on start; if they disagree the app says so rather
than risk showing you a request decoded under the wrong contract.

---

## 18. Command reference

| Command | What it does |
| --- | --- |
| `project` | Create, inspect, and manage projects |
| `setup` | Set up a machine: project, CA, and trust (first-run path) |
| `send` | Send a single HTTP request, sent exactly as written |
| `proxy` | Run the intercepting proxy |
| `ca` | Manage the interception certificate authority |
| `history` | Browse captured traffic |
| `repeat` | Resend a request, optionally editing it |
| `matchreplace` | Rewrite proxied traffic with rules |
| `scope` | Show and change what the engagement may touch |
| `programme` | The engagement's terms and constraints |
| `header` | Identification headers put on your traffic |
| `identity` | Manage the identities a project tests as |
| `identifiers` / `object` | Find and declare object references |
| `authz` | Replay a request as several identities and compare |
| `scan passive` | Observations over captured traffic (free) |
| `scan active` | Settle hypotheses by sending experiments (**Pro**) |
| `detectors` | List the checks this build has |
| `fuzz` | Send one request once per payload (unthrottled intruder is **Pro**) |
| `race` | Send one request many times at once |
| `sequencer` | Measure token unpredictability |
| `crawl` | Crawl in-scope targets to widen coverage |
| `import` | Import an OpenAPI/GraphQL description as traffic |
| `domxss` | Drive a browser to find DOM-based XSS |
| `ext` | Install and manage extensions |
| `findings` | Read and triage findings |
| `poc` | Compile a finding into runnable steps |
| `report` | Turn findings into a document (SARIF is **Pro**) |
| `snapshot` | Record and compare engagement snapshots (**Pro**) |
| `run` | Run a declarative plan file for CI |
| `license` | Activate and inspect a licence |

---

## 19. Getting help

- `nullhawk --help` — the full command list.
- `nullhawk <command> --help` — a command's options.
- `nullhawk help <topic>` — longer guidance for topics like `history` query syntax.

For extension authoring see [`docs/extensions.md`](./extensions.md); for producing a licensed,
signed release see [`docs/release.md`](./release.md).

---

*Nullhawk is licensed under AGPL-3.0-or-later. Test only what you are authorized to test.*
