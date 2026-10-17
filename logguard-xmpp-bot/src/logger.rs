//! `2026-10-13 12:00:00,123 - INFO - message` lines (the Python bot's format) to
//! `<log dir>/bot.log`, or to stderr when that can't be opened. Not to both: systemd's
//! journal would keep a copy beyond bot.log's retention (14 days, see /privacy).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};

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
        let line = format!("{} - {level} - {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S,%3f"), r.args());
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
    // owner only: it names users and the commands they ran
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
