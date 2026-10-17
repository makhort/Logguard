//! The bot as a library: the binary (`main.rs`) only reads the settings, the tests in
//! `tests/` drive the same code against a fake mail server and GnuPG, and the fuzz targets in
//! `fuzz/` reach it through [`fuzzing`].

pub mod bot;
pub mod fuzzing;
pub mod logger;
pub mod mime;
pub mod outbox;
pub mod redact;
pub mod seal;
pub mod servers;
pub mod smtp;
