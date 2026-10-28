//! The bot as a library: the binary (`main.rs`) only reads the settings and starts
//! signal-cli, the tests in `tests/` drive the same code against a fake signal-cli, and the
//! fuzz targets in `fuzz/` reach it through [`fuzzing`].

pub mod bot;
pub mod cli;
pub mod fuzzing;
pub mod logger;
pub mod outbox;
pub mod redact;
pub mod rpc;
pub mod seal;
pub mod servers;
pub mod state;
