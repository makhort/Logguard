//! What anyone allowed to connect sends an agent: refused without the web key, never a panic.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| logguard_web::fuzzing::agent_request(data));
