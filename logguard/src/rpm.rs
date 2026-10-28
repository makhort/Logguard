//! rpm's package database (`package_manager = "dnf"`), through `rpm -q`. Unlike dpkg's, it isn't
//! text to read line by line (SQLite on current Fedora and RHEL, Berkeley DB before): every
//! query asks rpm, a few packages at a time, so its lock is held for moments only and an
//! upgrade is never kept waiting.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// One line per file of the queried packages: package, digest algorithm, file flags, digest, path.
const FILES: &str = "[%{=NAME}\t%{=FILEDIGESTALGO}\t%{FILEFLAGS:fflags}\t%{FILEDIGESTS}\t%{FILENAMES}\n]";

/// Packages per `rpm -q` call.
pub const BATCH: usize = 25;

/// A file digest algorithm (rpm's `PGPHASHALGO_*` numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Algo {
    /// `(none)`: packages older than rpm 4.6, whose digests are MD5. SHA-1 (2) isn't supported.
    fn from_rpm(n: &str) -> Option<Algo> {
        match n {
            "1" | "(none)" => Some(Algo::Md5),
            "8" => Some(Algo::Sha256),
            "9" => Some(Algo::Sha384),
            "10" => Some(Algo::Sha512),
            "11" => Some(Algo::Sha224),
            _ => None,
        }
    }
}

/// A packaged file, as rpm recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub package: String,
    pub algo: Option<Algo>,
    /// `%config`: the admin may edit it (dpkg's conffiles).
    pub config: bool,
    /// `%ghost`: owned, but never installed with content.
    pub ghost: bool,
    /// Lowercase hex; empty for directories and symlinks.
    pub digest: String,
    pub path: String,
}

pub fn parse_line(line: &str) -> Option<FileEntry> {
    let mut f = line.splitn(5, '\t');
    let (package, algo, flags, digest, path) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
    if package.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some(FileEntry {
        package: package.to_string(),
        algo: Algo::from_rpm(algo),
        config: flags.contains('c'),
        ghost: flags.contains('g'),
        digest: digest.to_ascii_lowercase(),
        path: path.to_string(),
    })
}

fn rpm(rpm: &Path) -> Command {
    let mut cmd = Command::new(rpm);
    cmd.env("LC_ALL", "C");
    cmd
}

/// Names of every installed package, sorted.
pub fn packages(rpm_path: &Path) -> Result<Vec<String>, String> {
    let mut cmd = rpm(rpm_path);
    cmd.args(["-qa", "--qf", "%{NAME}\n"]);
    let out = crate::proc::run(cmd, None, Duration::from_secs(120))?;
    if !out.status.success() {
        return Err(format!("rpm -qa: {}", crate::event::clean(&out.complaint(), 200)));
    }
    let names: BTreeSet<String> = String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.is_empty()).map(str::to_string).collect();
    Ok(names.into_iter().collect())
}

/// The files of these packages (all installed versions and architectures of each).
pub fn files(rpm_path: &Path, packages: &[String]) -> Result<Vec<FileEntry>, String> {
    let mut cmd = rpm(rpm_path);
    cmd.args(["-q", "--qf", FILES, "--"]).args(packages);
    let out = crate::proc::run(cmd, None, Duration::from_secs(120))?;
    // a package removed since it was listed only makes rpm say so and exit 1
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(parse_line).collect())
}

/// The packages owning these paths (paths nobody owns are left out).
pub fn owners(rpm_path: &Path, paths: &[String]) -> Result<Vec<String>, String> {
    let mut cmd = rpm(rpm_path);
    cmd.args(["-q", "--qf", "%{NAME}\n", "-f", "--"]).args(paths);
    let out = crate::proc::run(cmd, None, Duration::from_secs(120))?;
    // "file /x is not owned by any package" (exit 1) for the others; names have no spaces
    let names: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty() && !l.contains(char::is_whitespace))
        .map(str::to_string)
        .collect();
    Ok(names.into_iter().collect())
}

/// Lowercase hex digest of everything `r` yields.
pub fn hex_digest(algo: Algo, r: &mut impl Read) -> std::io::Result<String> {
    fn run<D: sha2::Digest>(r: &mut impl Read) -> std::io::Result<String> {
        let mut h = D::new();
        let mut buf = vec![0u8; 64 << 10];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }
    match algo {
        Algo::Md5 => run::<md5::Md5>(r),
        Algo::Sha224 => run::<sha2::Sha224>(r),
        Algo::Sha256 => run::<sha2::Sha256>(r),
        Algo::Sha384 => run::<sha2::Sha384>(r),
        Algo::Sha512 => run::<sha2::Sha512>(r),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn query_lines() {
        let e = parse_line("openssh-server\t8\t\tAB12\t/usr/sbin/sshd").unwrap();
        assert_eq!(
            (e.package.as_str(), e.algo, e.config, e.ghost, e.digest.as_str()),
            ("openssh-server", Some(Algo::Sha256), false, false, "ab12")
        );
        let c = parse_line("pam\t8\tcn\tcd34\t/etc/pam.d/sshd").unwrap();
        assert!(c.config && !c.ghost);
        let g = parse_line("systemd\t8\tg\t\t/var/log/btmp").unwrap();
        assert!(g.ghost && g.digest.is_empty());
        assert_eq!(parse_line("old\t(none)\t\tx\t/usr/bin/old").unwrap().algo, Some(Algo::Md5));
        assert_eq!(parse_line("weird\t2\t\tx\t/usr/bin/w").unwrap().algo, None, "SHA-1");
        assert_eq!(parse_line("package x is not installed"), None);
        assert_eq!(parse_line("a\t8\t\tx\t/path\twith tab").unwrap().path, "/path\twith tab");
    }

    #[test]
    fn digests() {
        let d = |a| hex_digest(a, &mut &b"abc"[..]).unwrap();
        assert_eq!(d(Algo::Md5), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(d(Algo::Sha256), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(d(Algo::Sha512).len(), 128);
    }

    /// Against a fake rpm: the arguments it is given, and what it prints.
    #[test]
    fn runs_rpm() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("logguard-rpm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("rpm");
        std::fs::write(
            &fake,
            "#!/bin/sh\ncase \"$*\" in\n\
             -qa*) printf 'zlib\\nbash\\nbash\\n' ;;\n\
             *' -f '*) echo bash; echo 'file /x is not owned by any package'; exit 1 ;;\n\
             *) printf 'bash\\t8\\t\\tabcd\\t/usr/bin/bash\\n'; echo 'package gone is not installed'; exit 1 ;;\n\
             esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(packages(&fake).unwrap(), ["bash", "zlib"]);
        assert_eq!(owners(&fake, &["/usr/bin/bash".into(), "/x".into()]).unwrap(), ["bash"]);
        let f = files(&fake, &["bash".into(), "gone".into()]).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "/usr/bin/bash");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fake `rpm` for tests elsewhere: it prints the files `names` (for `-qa`), `owners` (for
    /// `-qf`, exiting 1 as for a file nobody owns) and `files` (for `-q PACKAGE...`) in its directory.
    pub(crate) fn fake_rpm(dir: &Path, names: &str, owners: &str, files: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let fake = dir.join("rpm");
        std::fs::write(
        &fake,
        "#!/bin/sh\nd=$(dirname \"$0\")\ncase \"$*\" in\n-qa*) cat \"$d/names\" ;;\n*' -f '*) cat \"$d/owners\"; exit 1 ;;\n*) cat \"$d/files\" ;;\nesac\n",
    )
    .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (name, text) in [("names", names), ("owners", owners), ("files", files)] {
            std::fs::write(dir.join(name), text).unwrap();
        }
        fake
    }
}
