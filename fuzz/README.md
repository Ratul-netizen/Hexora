# Fuzz targets

Coverage-guided fuzzing for Hexora's hand-rolled parsers — the code that reads bytes a
hostile peer controls and cannot fall back on a validating library. It complements the
`proptest` suites in the crates (which run on every `cargo test`); fuzzing runs longer, with
coverage feedback and a corpus that persists between runs, so it reaches inputs random
generation rarely hits.

This is a separate package outside the main workspace. A normal `cargo build` or `cargo test`
never touches it — it depends on `libfuzzer-sys` and builds only under nightly `cargo-fuzz`.

## Running

```console
$ cargo install cargo-fuzz          # once
$ cargo +nightly fuzz run hpack_decode
```

`cargo +nightly fuzz list` shows the targets.

## Targets

| Target | What it hammers |
| ------ | --------------- |
| `hpack_decode` | The HTTP/2 response header-block decoder (`h2raw`): HPACK integers, the static table, literal fields and the Huffman/dynamic-table fields it consumes-but-does-not-decode. The property: never panics, loops or reads out of bounds, for any bytes. |
| `ws_frame` | The WebSocket frame parser (`ws`): masking, the 7/16/64-bit length forms and fragmentation. Same property — no bytes make it panic, loop, or read out of bounds. |
| `ws_inflate` | The permessage-deflate inflater (`ws`): a malformed stream or a compression bomb is refused, never a panic or an unbounded run. |
| `crawl_extract` | The CR.a link extractor (`hexora-crawl`): HTML attributes and forms, URL-shaped strings in a text body, and the hand-rolled URL resolver and path normaliser (fed a hostile base URL). The property: never panics, loops or reads out of bounds, and the result stays bounded, for any bytes. |

## Notes

- **Platform.** libFuzzer wants a recent nightly and a clang-based toolchain; it runs cleanly
  on Linux and macOS. On Windows, run it from WSL or CI.
- **A crash** is written to `fuzz/artifacts/<target>/`; reproduce it with
  `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`, then add a
  regression test to the parser's `proptest` module before fixing.
- **The corpus** lives in `fuzz/corpus/<target>/` and is worth keeping between runs; it is
  git-ignored so it does not bloat the repository.
