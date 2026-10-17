//! Encrypted messages to the bot: session starts on its real prekeys with fuzzed keys, and
//! messages as sent.
#![no_main]

use std::sync::Mutex;

use logguard_xmpp_bot::fuzzing::Device;

static DEVICE: Mutex<Option<Device>> = Mutex::new(None);

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut device = DEVICE.lock().unwrap_or_else(|e| e.into_inner());
    logguard_xmpp_bot::fuzzing::decrypt(device.get_or_insert_with(Device::new), data);
});
