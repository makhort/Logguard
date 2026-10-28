//! The homeserver's `/keys/query` replies: only devices that sign themselves, and cross-signed ones under a valid master key.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_matrix_bot::fuzzing::keys_query(data));
