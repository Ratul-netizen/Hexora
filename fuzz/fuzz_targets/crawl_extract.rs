//! Fuzzes the CR.a link extractor (CR.f).
//!
//! The extractor reads attacker-controlled response bytes — HTML attributes and forms, and
//! URL-shaped strings in any text body — and resolves each candidate against a base URL with
//! its own hand-rolled parser and path normaliser. That is a panic surface a hostile page
//! aims at, like the HPACK and WebSocket parsers. The property is that no input makes it
//! panic, loop or read out of bounds, and that its output stays bounded; the proptest in
//! `core/crawl/src/lib.rs` asserts the same with coverage guidance and a corpus added here.
//!
//! Run: `cargo +nightly fuzz run crawl_extract`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    nullhawk_crawl::fuzz_extract(data);
});
