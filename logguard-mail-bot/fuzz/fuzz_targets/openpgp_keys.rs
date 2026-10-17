//! The recipients' key file: whatever is taken encrypts to every usable address.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_mail_bot::fuzzing::openpgp_keys(data));
