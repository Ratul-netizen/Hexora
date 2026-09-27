# Licence signing — the key ceremony

Nullhawk's paid tiers are gated by an **Ed25519-signed licence file**, verified offline against
a public key **embedded in the release binary**. This is the runbook for the private key that
signs those licences. It is the most sensitive secret the project holds after the interception
CA: anyone with it can mint a licence for any tier, and losing it invalidates every licence
ever signed with it.

The verification side (the gate, trials, graceful expiry) is `core/engine/src/license.rs`.
This document is only the issuer side.

## What the code does

- `EMBEDDED_LICENSE_KEY` is set at **build time** from the `NULLHAWK_LICENSE_PUBKEY` environment
  variable (64 hex characters — the 32-byte public key). When it is **unset**, the key is all
  zeros, which verifies nothing, so the build runs at the free tier. Every ordinary
  `cargo build` and every test is therefore free-tier and cannot be tricked into honouring a
  licence.
- `nullhawk license keygen` generates an Ed25519 keypair.
- `nullhawk license sign` mints a signed licence with the private key.
- `nullhawk license activate` (customer-facing) verifies a licence against the embedded key and
  installs it; `nullhawk license show` reports the tier in force.

Shipping `keygen`/`sign` in the product binary is safe: signing requires the private key,
which a customer does not have, and the build verifies against the *embedded* public key,
which is set separately at release time.

## One-time: generate the issuing key

Do this **once**, on a trusted, offline machine. Keep the private key off the network and out
of the repository forever.

```console
$ nullhawk license keygen --out nullhawk-issuer.key
Wrote the issuing private key to nullhawk-issuer.key — keep it offline and never commit it.

Public key (embed in a release build):
  <64 hex characters>

  NULLHAWK_LICENSE_PUBKEY=<64 hex> cargo build --release -p nullhawk-cli
```

- **`nullhawk-issuer.key`** is the PKCS#8 private key. Store it in a secrets manager / HSM /
  offline vault. Never commit it. `keygen` refuses to overwrite an existing key file.
- The **public key hex** is not secret. Record it; it goes into every release build.

## Every release: embed the public key

```console
$ NULLHAWK_LICENSE_PUBKEY=<the public hex> cargo build --release -p nullhawk-cli
```

A wrong length or a non-hex value fails the build rather than shipping a silently-wrong key.
Verify a freshly built binary embedded the key by signing a throwaway licence and activating
it against that binary (see below); a build with the placeholder key will refuse it.

## Per customer: sign a licence

```console
# Perpetual Pro licence
$ nullhawk license sign --key nullhawk-issuer.key --tier pro \
    --licensee "Acme Pentest Ltd" --out acme.hexlic

# One-year Enterprise licence
$ nullhawk license sign --key nullhawk-issuer.key --tier enterprise \
    --licensee "Acme Pentest Ltd" --days 365 --out acme.hexlic

# Explicit expiry instead of --days
$ nullhawk license sign --key nullhawk-issuer.key --tier pro --expires 2027-01-01T00:00:00Z
```

Omit `--out` to write the licence to stdout (for piping into a delivery pipeline). Send the
customer the `.hexlic` file; they run `nullhawk license activate <file>`.

## Rotation

If the private key is lost or exposed, generate a new keypair, build releases with the new
public key, and re-issue every active licence signed with the old key. There is no
revocation list in the offline scheme — rotation *is* the revocation. (Hard, server-side
revocation is the M22 team/server tier.) Because rotation invalidates every outstanding
licence, treat the private key's storage accordingly.

## What this does not defend

Client-side licensing deters casual sharing of a licence file. It does not stop someone who
can patch the binary — no client-side scheme does, and Nullhawk does not pretend otherwise.
Unbypassable enforcement lives server-side, in the team/server tier.
