//! Embeds the git commit into `logguard --version`, so a server's binary can be traced
//! back to its source (and rolled back to the previous commit if needed).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let version = match git(&["rev-parse", "--short=10", "HEAD"]) {
        Some(hash) => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no", "--", "."]).is_some_and(|s| !s.is_empty());
            format!("{} ({hash}{})", env!("CARGO_PKG_VERSION"), if dirty { ", modified" } else { "" })
        }
        None => env!("CARGO_PKG_VERSION").to_string(),
    };
    println!("cargo:rustc-env=LOGGUARD_VERSION={version}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    println!("cargo:rerun-if-changed=src");
}
