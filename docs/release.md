# Releasing Hexora

Producing a licensable, installable build. Two things a stock `cargo build` does not do: it
embeds no licence public key (so every install runs at the free tier), and it does not sign the
installers. Both are supplied at release time, off the machine that holds the repository.

## 1. The licence signing key — once, ever

Hexora verifies a licence with an Ed25519 public key **baked into the binary at build time**.
The matching private key signs licences and never leaves the seller's control.

```
hexora license keygen --out hexora-issuer.key
```

This writes the PKCS#8 **private key** to `hexora-issuer.key` and prints the 32-byte **public
key** as 64 hex characters.

- **Store `hexora-issuer.key` in a secret manager.** It is the only thing that can mint a paid
  licence. **Never commit it**, and never put it on a build runner.
- **Record the public key hex.** It is not secret; it goes into every release build as
  `HEXORA_LICENSE_PUBKEY`, ideally a CI secret so the value is set in one place.

A build with no `HEXORA_LICENSE_PUBKEY` embeds an all-zero key: it verifies no licence, so every
install stays at the free tier. That is the safe default — you cannot accidentally ship a build
that trusts the wrong issuer, only one that trusts none.

### Issuing a licence to a customer

```
hexora license sign --key hexora-issuer.key --tier pro --licensee "Acme Corp" --days 365 --out acme.hexlic
```

Send `acme.hexlic` to the customer. They install it with `hexora license activate acme.hexlic`
(or the Licence tab in the desktop app); `hexora license show` then reports the tier, licensee
and expiry. Only a licence signed by the private key matching the embedded public key verifies.

## 2. Building the artifacts

Set the public key for the build, then build.

**CLI** (all platforms):

```
HEXORA_LICENSE_PUBKEY=<64 hex> cargo build --release -p hexora-cli
```

**Desktop installers** — run on each target OS (Tauri bundles for the host platform):

```
HEXORA_LICENSE_PUBKEY=<64 hex> cargo tauri build
```

The bundle config (`apps/desktop/src-tauri/tauri.conf.json`) produces, per OS:

- **Windows** — an NSIS installer (`installMode: both`, per-user or per-machine) and an MSI.
- **Linux** — a `.deb` and an AppImage.
- **macOS** — a `.app` and a `.dmg`.

A malformed `HEXORA_LICENSE_PUBKEY` (not 64 hex characters) fails the build rather than shipping
a silently wrong key — see `core/engine/src/license.rs`.

### Automated: the release workflow

`.github/workflows/release.yml` does steps 2 and 3 on a tag. Push a `vX.Y.Z` tag and each OS
runner builds the licensed CLI and the desktop installers and attaches them to a **draft**
GitHub release for review before you publish it. `workflow_dispatch` runs the same build against
a branch for a dry run.

Configure these repository secrets (all optional except the first; a missing signing secret just
leaves that platform unsigned):

| Secret | Purpose |
| --- | --- |
| `HEXORA_LICENSE_PUBKEY` | The 64-hex public key embedded so paid licences verify. Omit and every build is free-tier. |
| `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD` | The base64 Developer ID cert and its password, for macOS signing. |
| `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | macOS signing identity and notarization credentials. |
| `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | The Tauri updater signing key, if you ship auto-updates. |

Windows Authenticode signing is configured in `tauri.conf.json`
(`bundle.windows.certificateThumbprint` / `signCommand`) on a runner that has the certificate;
the workflow leaves Windows unsigned until that is set.

## 3. Code signing

Unsigned installers warn or are blocked by the OS. Signing certificates are held on the release
machine, never in the repository, so this step is done there:

- **Windows (Authenticode).** Sign the `.exe`/`.msi`/NSIS output with `signtool` and an EV or OV
  code-signing certificate. Tauri can invoke signing automatically when
  `bundle.windows.certificateThumbprint` (and `signCommand`/`digestAlgorithm`) are configured on
  the signing machine.
- **macOS (codesign + notarization).** Sign with a Developer ID Application certificate, then
  notarize the `.dmg` with `notarytool` and staple. Tauri reads `APPLE_CERTIFICATE`,
  `APPLE_SIGNING_IDENTITY`, `APPLE_ID`/`APPLE_PASSWORD` from the environment.
- **Linux.** Optionally sign the `.deb` / repository metadata with GPG; AppImages are typically
  distributed with a detached signature.

Keep these values out of the repo — pass them as CI secrets or local environment on the signing
host.

## 4. Verify the release build

Prove the embedded key and a signed licence agree before shipping:

```
# build with the release public key
HEXORA_LICENSE_PUBKEY=<hex> cargo build --release -p hexora-cli

# sign a short-lived licence with the matching private key
hexora license sign --key hexora-issuer.key --tier pro --licensee "Release Test" --days 1 --out test.hexlic

# activate it and confirm the tier
hexora license activate test.hexlic
hexora license show     # -> Tier: Pro, licensee "Release Test"
```

If `license show` still reports Free, the embedded public key and the signing private key do not
match — rebuild with the correct `HEXORA_LICENSE_PUBKEY`.

## Security notes

- The issuer private key is the whole trust root. Keep it offline, back it up, and rotate it
  (re-key + re-issue) if it is ever exposed.
- Hexora is AGPL-3.0-or-later. Distributing a build carries the AGPL's source-availability
  obligation; the `LICENSE` file is bundled into the installers via `bundle.licenseFile`.
