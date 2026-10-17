//! The bot's signing key: whatever is taken signs mails that verify, in a well-formed Autocrypt header.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_mail_bot::fuzzing::signing_key(data));
