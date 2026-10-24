//! `2026-10-13 12:00:00,123 - INFO - message` lines (logguard-xmpp-bot's format) to
//! `<log dir>/bot.log`, or to stderr when that can't be opened. Not to both: systemd's
//! journal would keep a copy beyond bot.log's retention (14 days, see the README).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// A log message as one line, without anything a terminal acts on: control characters
/// (line breaks, escape sequences) as visible escapes. Messages quote others' text: message
/// ids, device names, servers' replies.
fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    out
}

struct Logger {
    file: Option<Mutex<File>>,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        // dependencies only from warnings up; their info lines are per-stanza noise
        m.level() <= Level::Warn || m.target().starts_with(env!("CARGO_CRATE_NAME"))
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let level = match r.level() {
            Level::Warn => "WARNING",
            l => l.as_str(),
        };
        let line = format!("{} - {level} - {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"), one_line(&r.args().to_string()));
        match &self.file {
            Some(f) => {
                if let Ok(mut f) = f.lock() {
                    let _ = f.write_all(line.as_bytes());
                }
            }
            None => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
        }
    }

    fn flush(&self) {}
}

pub fn init(dir: &Path) {
    // owner only: it names the recipients and the mail server's answers
    let file = fs::create_dir_all(dir).and_then(|()| OpenOptions::new().create(true).append(true).mode(0o600).open(dir.join("bot.log")));
    let (file, err) = match file {
        Ok(f) => (Some(Mutex::new(f)), None),
        Err(e) => (None, Some(e)),
    };
    log::set_boxed_logger(Box::new(Logger { file })).expect("logger set twice");
    log::set_max_level(LevelFilter::Info);
    if let Some(e) = err {
        log::warn!("logging to stderr only: {}/bot.log: {e}", dir.display());
    }
}

/// For the one-off commands (`check`, `send-test`, `keygen`): stderr only.
pub fn init_stderr() {
    log::set_boxed_logger(Box::new(Logger { file: None })).expect("logger set twice");
    log::set_max_level(LevelFilter::Info);
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_lines_stay_one_line() {
        assert_eq!(super::one_line("id 1\nINFO - forged\u{1b}[2J\tend"), "id 1\\nINFO - forged\\u{1b}[2J\\tend");
        assert_eq!(super::one_line("plain → ✓"), "plain → ✓");
    }
}
