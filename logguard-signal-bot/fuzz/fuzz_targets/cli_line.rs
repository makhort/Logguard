//! Lines of signal-cli's output: replies, errors, notifications, identities.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_signal_bot::fuzzing::cli_line(data));
