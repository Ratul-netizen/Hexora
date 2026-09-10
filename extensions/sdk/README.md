# Hexora extension SDK

**Status: PLANNED (M10). Nothing here is implemented.**

The TypeScript SDK for Hexora extensions will live here.

The permission model the SDK will surface *is* implemented and tested today, in
`core/engine/src/permission.rs`. Extensions declare required and optional capabilities;
the user grants a subset; the granted set can only ever be narrowed afterwards. See
`docs/security-invariants.md`, invariant 4.

Three extension tiers are planned:

| Tier | Language | Isolation |
| ---- | -------- | --------- |
| 1 | Rust (native) | None — permission model is cooperative, not a boundary |
| 2 | TypeScript / WASM | Sandboxed |
| 3 | Java (Burp Montoya) | Separate process, restricted RPC |

Tier 2 is the intended default, because it is the only one where the permission model
is enforceable rather than advisory.
