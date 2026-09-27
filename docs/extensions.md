# Writing a Hexora extension

An extension is a **manifest** plus a **WASM module**. The manifest declares what the extension
is and what it needs; the module is the code. Hexora installs an extension with exactly the
capabilities the user approves — nothing is granted implicitly, and a capability that was never
granted is never available (security invariant 4).

> Status: this build installs, validates and permission-gates extensions
> (`hexora ext`). Executing the WASM module in a sandbox is the runtime milestone (M19). The
> manifest and permission contract below are stable; author against them now.

## The manifest

JSON or YAML. Example (`jwt-tools.manifest.yaml`):

```yaml
id: com.example.jwt-tools      # stable, reverse-DNS, lowercase
name: JWT Tools
version: 1.2.0                 # your extension's version
api_version: 1                 # the Hexora extension API you target
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
hexora ext install <project> jwt-tools.manifest.yaml   # grants required only
hexora ext install <project> jwt-tools.manifest.yaml --grant-all   # also grants optional
hexora ext list <project>
hexora ext permissions <project> com.example.jwt-tools
hexora ext disable <project> com.example.jwt-tools
hexora ext remove <project> com.example.jwt-tools
```

Install never grants a capability the manifest did not request. If a *required* capability is
not granted, the extension installs **disabled** — a declined requirement is a switched-off
extension, not one that fails halfway through a run. The manifest and the exact grant are stored
in the project, so the record of what third-party code was permitted travels with the
engagement.
