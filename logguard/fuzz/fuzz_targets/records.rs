//! Log lines in every format logguard reads, through the parsers and the engine.
#![no_main]

use std::sync::{Arc, OnceLock};

use logguard::config::Config;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    static CFG: OnceLock<Arc<Config>> = OnceLock::new();
    logguard::fuzzing::records(CFG.get_or_init(logguard::fuzzing::config), data);
});
