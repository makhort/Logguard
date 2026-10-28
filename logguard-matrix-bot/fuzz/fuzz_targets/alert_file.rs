//! logguard's outbox files as the bot reads them.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_matrix_bot::fuzzing::alert_file(data));
