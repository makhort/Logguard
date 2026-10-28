//! A snapshot from any holder of the web key: trimmed, merged and turned into metrics without a panic.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_web::fuzzing::snapshot(data));
