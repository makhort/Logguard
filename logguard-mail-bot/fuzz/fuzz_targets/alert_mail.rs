//! logguard's outbox files on their way out as mails: a well-formed PGP/MIME envelope with nothing of the content outside, the content back unchanged inside, nothing left with SANITIZE=on.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_mail_bot::fuzzing::alert(data));
