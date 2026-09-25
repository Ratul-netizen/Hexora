# CI integration

Hexora's CLI and desktop app run the same engine, so anything you can conclude in the
window you can produce headless in a pipeline. The bridge is **SARIF** — the format
GitHub code scanning and GitLab ingest natively — via `hexora report --format sarif`.

## What makes Hexora's SARIF worth more than a scanner's

Two properties fall out of the data model rather than being bolted on:

- **Established findings gate a build; leads never do.** A verified finding is emitted at
  its severity's level (`error` / `warning` / `note`). An unverified *lead* is emitted at
  `note` and tagged `unverified`, so it shows up for a human to weigh but cannot turn a
  pipeline red. This is the same discipline the human-facing reports keep — leads are
  counted, never mixed in with findings — carried into the one format where the
  distinction decides whether a merge is blocked.

- **A re-run recognises the same finding.** Each result's `partialFingerprints` is the
  finding's stable id, which persists across runs (a retest updates the row rather than
  creating a new one). GitHub uses that fingerprint to correlate results between runs, so
  a "fail the build only on *new* findings" gate works without fuzzy line-matching.

Credentials do not travel in SARIF: results carry titles, locations and metadata, not the
quoted request and response. Keep the human-facing HTML/Markdown report (under its
redaction policy) for the transcript.

## GitHub

A composite action lives at [`ci/github-action`](../ci/github-action/action.yml). It
renders a Hexora **project** — the directory a run produced — into a SARIF file. It does
not run the engagement: capture and testing are things a person does, and the project
that produces is the input here (check it in, restore it from a cache, or download it as
a build artifact from an earlier job).

```yaml
name: Security findings
on: [push, pull_request]

# code scanning needs this to accept the upload
permissions:
  contents: read
  security-events: write

jobs:
  hexora:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # However your engagement project reaches the runner. Here, from an artifact a
      # prior job uploaded; it could equally be committed or restored from a cache.
      - uses: actions/download-artifact@v4
        with:
          name: engagement
          path: ./engagement

      - uses: ./ci/github-action
        with:
          project: ./engagement
          output: hexora.sarif
          severity: low          # optional: drop info-level noise

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: hexora.sarif
```

Once uploaded, findings appear under **Security → Code scanning**, keyed so that
re-running shows which are new. Branch protection can then require the check, which turns
"a new High-severity finding was verified" into a merge blocker.

## GitLab

GitLab reads SARIF too, exposed as a SAST report artifact:

```yaml
hexora:
  image: rust:latest
  script:
    - cargo build --release -p hexora-cli
    - ./target/release/hexora report ./engagement --format sarif --output gl-sast.sarif
  artifacts:
    reports:
      sast: gl-sast.sarif
```

## Any other system

`hexora report <project> --format sarif` writes SARIF 2.1.0 to stdout (or to `--output`).
The exit code is `0` when the report renders; gating logic that wants to fail on new
findings should diff the SARIF against a stored baseline, which is exactly what the
GitHub upload does for you. A machine-readable summary is also available with
`--format json`.
