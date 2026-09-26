//! Fuzzes the WebSocket frame parser (WS.a).
//!
//! It reads frames a peer controls — masking, 7/16/64-bit lengths, fragmentation — without a
//! conforming library, so it is the panic surface a hostile server aims at. The property is
//! that no bytes make it panic, loop, or read out of bounds; the proptest in
//! `core/http/src/ws.rs` asserts the same with coverage guidance and a corpus added here.
//!
//! Run: `cargo +nightly fuzz run ws_frame`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hexora_http::ws::fuzz_parse_frames(data);
});
