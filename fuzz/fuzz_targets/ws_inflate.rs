//! Fuzzes the permessage-deflate inflater (WS.e).
//!
//! It reconstructs and decompresses a message payload a peer controls; a bomb or a malformed
//! stream must be refused, never panic or run unbounded. The proptest in
//! `core/http/src/ws.rs` asserts the same property.
//!
//! Run: `cargo +nightly fuzz run ws_inflate`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    nullhawk_http::ws::fuzz_inflate(data);
});
