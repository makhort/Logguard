//! The bot as a library: the binary (`main.rs`) only reads the settings, the tests in
//! `tests/` drive the same code against a fake homeserver with a fake admin device, and the
//! fuzz targets in `fuzz/` reach it through [`fuzzing`].

pub mod api;
pub mod bot;
pub mod crypto;
pub mod fuzzing;
pub mod logger;
pub mod login;
pub mod outbox;
pub mod redact;
pub mod seal;
pub mod servers;
pub mod state;
