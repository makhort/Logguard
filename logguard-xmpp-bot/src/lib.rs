//! The bot's self-contained parts as a library: OMEMO, the outbox, the state files and the
//! OpenPGP fallback of client mode. The
//! binary uses them from here, and so do the fuzz targets in `fuzz/` (see [`fuzzing`]).

pub mod fuzzing;
pub mod omemo;
pub mod outbox;
pub mod seal;
pub mod state;
