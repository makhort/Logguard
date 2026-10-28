//! The few libc constants logguard declares itself (it has no libc crate). Their values are
//! per architecture; these are those of the release targets: x86_64, aarch64 and 32-bit ARM
//! (Linux, and macOS for development). Another architecture must check them before it builds:
//! MIPS, SPARC and Alpha number signals differently, s390x has its own `POSIX_FADV_DONTNEED`.

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
compile_error!("logguard declares libc constants for x86_64, aarch64 and arm only: check src/sys.rs for this architecture");

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
mod consts {
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    /// Linux only (`posix_fadvise`).
    pub const POSIX_FADV_DONTNEED: i32 = 4;
}

pub use consts::*;
