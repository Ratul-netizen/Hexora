//! Fuzzes the HTTP/2 response header-block decoder (M5.1e).
//!
//! The decoder reads an HPACK block a hostile server controls, and it is hand-rolled, so it
//! is exactly the kind of code fuzzing is for. The property is not that it decodes correctly
//! — a malformed block has none — but that it never panics, loops, or reads out of bounds on
//! any input at all. The proptest in `core/http/src/h2raw.rs` asserts the same property with
//! random input; this chases it with coverage guidance and a persistent corpus.
//!
//! Run: `cargo +nightly fuzz run hpack_decode` (see README.md).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    nullhawk_http::h2raw::fuzz_decode_header_block(data);
});
