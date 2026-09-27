# Writing a Nullhawk extension

An extension is a **manifest** plus a **WASM module**. The manifest declares what the extension
is and what it needs; the module is the code. Nullhawk installs an extension with exactly the
capabilities the user approves — nothing is granted implicitly, and a capability that was never
granted is never available (security invariant 4).

> Status: this build installs, validates and permission-gates extensions (`nullhawk ext`), runs a
> passive-check module in the WASM sandbox (`nullhawk ext run`), **and runs installed passive-check
> extensions as part of `nullhawk scan passive`** — their observations are folded into the scan as
> leads. The extension store (distribution) is the remaining step. The manifest, permission and
> ABI contracts below are stable; author against them now.

## The module ABI

The module is WebAssembly with **no host imports** — it gets its linear memory and nothing else,
so it cannot touch the filesystem, network or clock. It exports:

- `memory` — its linear memory.
- `alloc(len: i32) -> i32` — reserve `len` bytes, return a pointer; the host writes the input there.
- `run(ptr: i32, len: i32) -> i64` — read `len` bytes of input JSON at `ptr`, and return a packed
  `(out_ptr << 32) | out_len` pointing at the output JSON in the same memory.

For a passive check the input is one exchange as JSON and the output is an array of observations.
Execution is bounded by **fuel** (an infinite loop is trapped, not left to hang) and a memory
cap, so a hostile or buggy module fails the run rather than the tool. Test a module before you
ship it:

```
nullhawk ext run path/to/manifest.yaml --exchange exchange.json
```

### The passive-check input (exchange JSON)

One exchange, metadata and headers only — **never a body**, and credential request headers and
`Set-Cookie` values arrive already replaced, exactly as the built-in checks see them. A module is
no more privileged than the checks shipped in the box:

```json
{
  "method": "POST",
  "url": "http://127.0.0.1:8077/boom",
  "host": "127.0.0.1",
  "path": "/boom",
  "port": 8077,
  "secure": false,
  "status": 500,
  "authenticated": false,
  "response_bytes": 33,
  "origin": "proxy",
  "request_headers": [{ "name": "Accept", "value": "*/*" }],
  "response_headers": [{ "name": "Content-Type", "value": "application/json" }]
}
```

### The passive-check output (observations JSON)

An array of observations. `title` is required; `detail` and `severity` are optional, so the
simplest useful module returns `[{"title": "..."}]`. `severity` is one of `info`, `low`,
`medium`, `high`, `critical` (default `medium`); an unrecognised word makes that observation drop
rather than silently downgrade. `[]` means "nothing to report".

```json
[{ "title": "a 500 response was seen", "detail": "the server erred", "severity": "medium" }]
```

Every observation an extension emits is concluded as a **lead** (capped at `Reported`
confidence), the same as a built-in or custom passive check — an extension states what it saw, it
cannot declare a vulnerability. An extension runs in the scan only if it is enabled and holds
`http_read`; a passive extension without that grant never sees the traffic.

A minimal Rust guest is `cargo build --release --target wasm32-unknown-unknown` of a `cdylib`
that exports `alloc` and `run`; point the manifest's `entry` at the resulting `.wasm`.

## The manifest

JSON or YAML. Example (`jwt-tools.manifest.yaml`):

```yaml
id: com.example.jwt-tools      # stable, reverse-DNS, lowercase
name: JWT Tools
version: 1.2.0                 # your extension's version
api_version: 1                 # the Nullhawk extension API you target
kind: passive_check            # what you plug into (see below)
entry: jwt_tools.wasm          # the module to load, relative to the manifest
description: Flags weak or unverified JWTs in captured traffic
author: Example Security
permissions:
  required: [http_read]        # without these the extension will not enable
  optional: [project_write]    # nice-to-have; the user may decline them
```

`api_version` must be one this build speaks (currently **1**); a newer manifest is refused
rather than loaded against a contract it does not match.

### Kinds

| `kind` | Plugs into |
| --- | --- |
| `passive_check` | Observes an exchange, may emit observations (leads). |
| `active_check` | Sends requests and settles hypotheses. |
| `report` | Renders findings into a document format. |
| `ui` | Adds tabs, panels or menu entries. |
| `workflow` | An automation the user can run. |

## Capabilities

An extension asks for capabilities; the user grants a subset. Ask for the least you need.

| Capability | The extension can… | Dangerous |
| --- | --- | :---: |
| `http_read` | See proxied traffic, including cookies and auth tokens | |
| `http_send` | Send requests to in-scope targets | |
| `project_read` | Read targets, history and findings | |
| `project_write` | Modify project data and create findings (implies `project_read`) | |
| `ui` | Add tabs and menu entries | |
| `scanner` | Register scanner checks | |
| `workflow` | Define and run workflows | |
| `filesystem` | Read/write files anywhere on the machine | ⚠ |
| `network:raw` | Open connections that bypass scope and capture | ⚠ |
| `process:execute` | Run other programs | ⚠ |
| `credentials` | Read stored identity credentials in cleartext | ⚠ |

`project_write` implies `project_read`; nothing implies a dangerous capability — each must be
requested by name and is flagged prominently at install.

## Managing extensions

```
nullhawk ext install <project> jwt-tools.manifest.yaml   # grants required only
nullhawk ext install <project> jwt-tools.manifest.yaml --grant-all   # also grants optional
nullhawk ext list <project>
nullhawk ext permissions <project> com.example.jwt-tools
nullhawk ext disable <project> com.example.jwt-tools
nullhawk ext remove <project> com.example.jwt-tools
```

Install never grants a capability the manifest did not request. If a *required* capability is
not granted, the extension installs **disabled** — a declined requirement is a switched-off
extension, not one that fails halfway through a run. The manifest and the exact grant are stored
in the project, so the record of what third-party code was permitted travels with the
engagement.
