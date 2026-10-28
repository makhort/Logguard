//! An abuse report from any holder of the web key: read, merged and split per provider without a panic.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_web::fuzzing::abuse_report(data));
