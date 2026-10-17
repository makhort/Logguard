//! Replies from the Bot API (updates, errors, sent messages) and state.json.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_tg_bot::fuzzing::telegram_reply(data));
