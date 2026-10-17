//! SERVER_NAMES and a text, split at the first NUL byte.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_tg_bot::fuzzing::server_names(data));
