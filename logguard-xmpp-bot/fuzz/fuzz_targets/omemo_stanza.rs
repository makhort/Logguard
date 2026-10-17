//! XML from other clients: `<encrypted>` messages, device lists, bundles; logguard's
//! outbox messages.
#![no_main]

use std::sync::Mutex;

use logguard_xmpp_bot::fuzzing::Device;

static DEVICE: Mutex<Option<Device>> = Mutex::new(None);

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut device = DEVICE.lock().unwrap_or_else(|e| e.into_inner());
    logguard_xmpp_bot::fuzzing::stanza(device.get_or_insert_with(Device::new), data);
});
