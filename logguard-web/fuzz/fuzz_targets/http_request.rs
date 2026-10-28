//! What a client sends the console before any login: never a panic, never more than the limits.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_web::fuzzing::http_request(data));
