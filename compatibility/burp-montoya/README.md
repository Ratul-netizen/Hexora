# Burp Montoya compatibility layer

**Status: PLANNED (M12). Nothing here is implemented.**

This directory is reserved for the compatibility layer that will let Java extensions
written against PortSwigger's public Montoya API run under Hexora.

## Why it is empty

Montoya compatibility is a multi-month engineering project, not a feature checkbox. It
needs:

- an out-of-process JVM host (never in the core process — see `docs/architecture.md`),
- a restricted RPC interface between that host and the Rust core,
- an independent implementation of a large public API surface,
- and a compatibility test suite.

Starting it before the core HTTP engine, proxy and storage work would mean implementing
a compatibility layer over subsystems that do not exist.

## Ground rules for when it starts

1. **Independently versioned.** Its version tracks API coverage, not Hexora releases.
2. **Public compatibility matrix.** Every API is documented FULL / PARTIAL /
   UNSUPPORTED, with the observed behaviour. No blanket claim that "Burp extensions
   work".
3. **Independent implementation only.** Built against public API specifications.
   No proprietary code, assets or trademarks are copied.
4. **Not trusted.** A Burp extension is arbitrary Java. The JVM host gets a restricted
   RPC surface, and its traffic goes through the same scope enforcement as everything
   else. See `docs/threat-model.md`.
