//! The bot's self-contained parts as a library: OMEMO, the outbox and the state files. The
//! binary uses them from here, and so do the fuzz targets in `fuzz/` (see [`fuzzing`]).

pub mod fuzzing;
pub mod omemo;
pub mod outbox;
pub mod state;
