//! Running helper programs (nft, ufw, df, openssl, ejabberdctl) with a time limit.
//!
//! A program that hangs (nft waiting on a netlink lock, df on a stalled mount) is killed
//! when its time is up, instead of stalling the thread that called it. Input is written
//! and output read by their own threads, so neither side can block on a full pipe.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Most of a stream kept; the rest is read and dropped.
const MAX_OUTPUT: u64 = 16 << 20;

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    /// stderr, else stdout, trimmed: what a failed program had to say.
    pub fn complaint(&self) -> String {
        let text = if self.stderr.iter().any(|b| !b.is_ascii_whitespace()) { &self.stderr } else { &self.stdout };
        String::from_utf8_lossy(text).trim().to_string()
    }
}

fn reader(mut r: impl Read + Send + 'static, tx: mpsc::Sender<(bool, Vec<u8>)>, is_err: bool) {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.by_ref().take(MAX_OUTPUT).read_to_end(&mut buf);
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        let _ = tx.send((is_err, buf));
    });
}

/// Runs `cmd` with `input` on its stdin (or none), and kills it after `limit`. Err is
/// why it could not be run or finish; a program that ran and failed is Ok with its status.
pub fn run(mut cmd: Command, input: Option<&[u8]>, limit: Duration) -> Result<Output, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running {program}: {e}"))?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        let data = data.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let (tx, rx) = mpsc::channel();
    if let Some(out) = child.stdout.take() {
        reader(out, tx.clone(), false);
    }
    if let Some(err) = child.stderr.take() {
        reader(err, tx, true);
    }
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} did not finish within {} s; killed", limit.as_secs()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{program}: {e}")),
        }
    };
    // A program's own children may keep its pipes open: wait for the output a little only.
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok((true, b)) => stderr = b,
            Ok((false, b)) => stdout = b,
            Err(_) => break,
        }
    }
    Ok(Output { status, stdout, stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn output_input_and_status() {
        let out = run(sh("cat; echo oops >&2; exit 3"), Some(b"hello"), Duration::from_secs(5)).unwrap();
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice(), out.status.code()), (&b"hello"[..], &b"oops\n"[..], Some(3)));
        assert_eq!(out.complaint(), "oops");
        assert!(run(Command::new("/nonexistent/prog"), None, Duration::from_secs(1)).unwrap_err().contains("/nonexistent/prog"));
    }

    #[test]
    fn hanging_programs_are_killed() {
        let start = Instant::now();
        let err = run(sh("sleep 30"), None, Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("did not finish"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn big_input_and_output_do_not_block() {
        // more than a pipe holds, both ways, with the program not reading its input first
        let input = vec![b'x'; 1 << 20];
        let out = run(sh("head -c 1048576 /dev/zero; cat > /dev/null"), Some(&input), Duration::from_secs(10)).unwrap();
        assert_eq!(out.stdout.len(), 1 << 20);
        assert!(out.status.success());
    }
}
