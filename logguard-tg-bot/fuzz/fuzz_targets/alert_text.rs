//! logguard's outbox files on their way to Telegram: account names and server addresses replaced, messages well formed.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_tg_bot::fuzzing::alert(data));
