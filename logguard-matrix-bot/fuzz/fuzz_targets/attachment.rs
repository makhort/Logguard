//! Encrypted attachments: what goes in comes out, and damage is caught.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_matrix_bot::fuzzing::attachment(data));
