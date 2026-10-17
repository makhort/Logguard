//! Other files in the outbox (the weekly report; `name`, NUL, content): as the mail's text or attached, back byte for byte.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_mail_bot::fuzzing::file(data));
