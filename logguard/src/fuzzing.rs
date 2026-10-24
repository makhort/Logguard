//! What the fuzz targets in `fuzz/` run (`cargo +nightly fuzz run records`). They feed
//! arbitrary input to the code that reads log lines: attackers shape those lines (the user
//! names they try, request paths, client banners, certificate names), so none of it may
//! panic, hang or grow without bound. `tests/fuzz_smoke.rs` runs the same functions on
//! stable over the sample logs and generated input, so `cargo test` keeps them working.

use std::sync::Arc;

use crate::config::Config;
use crate::pipeline::Pipeline;
use crate::record::{self, YearGuess};
use crate::time::SEC;

/// The configuration the targets use: every source on, so every parser is reached, and
/// patterns of your own on any line no built-in parser reads (journal exports and syslog
/// text carry no sender fields, so they apply).
pub fn config() -> Arc<Config> {
    let mut cfg = Config::from_toml(
        r#"
        [[patterns]]
        name = "auth"
        identifier = "fuzz"
        uid = 0
        regex = '(?:failed|refused) (?:login|auth)[^\[]*\[(?P<ip>[0-9A-Fa-f.:]+)\](?: user=(?P<user>\S+))?'
        [[patterns]]
        name = "probe"
        unit = "fuzz.service"
        kind = "probe"
        weight = 40
        regex = '^(?P<ip>\S+) .*"GET /\.(?:env|git)'
        [[patterns]]
        name = "login"
        identifier = "fuzz"
        uid = 0
        kind = "success"
        regex = 'accepted (?P<user>\S+) from (?P<ip>\S+)'
        "#,
    )
    .expect("valid fuzzing config");
    cfg.sources.nextcloud = true;
    cfg.sources.services = vec!["logguard-xmpp-bot.service".into(), "ejabberd.service".into()];
    Arc::new(cfg)
}

/// Lines in any format logguard reads (`journalctl -o json`, short syslog, Nextcloud's JSON
/// log), through the parsers and the decision engine, then a day of time for the
/// parsers' and the engine's timers.
pub fn records(cfg: &Arc<Config>, data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut pipe = Pipeline::new(Arc::clone(cfg), 0);
    let mut years = YearGuess::new(2026);
    let mut last = 0;
    for line in text.lines() {
        let rec = if line.starts_with('{') { record::parse_journal_json(line).0 } else { record::parse_syslog_line(line, &mut years) };
        let Some(rec) = rec.or_else(|| record::parse_nextcloud_line(line)) else { continue };
        pipe.tick(rec.ts);
        pipe.feed(&rec);
        last = last.max(rec.ts);
        // the pieces the pipeline calls only for some sources, on any message
        let _ = crate::parse::kernel::parse_oom(&rec.msg);
        let _ = crate::parse::systemd::parse(&rec.msg);
        let _ = crate::abuse::sanitize(&rec.msg);
        for ident in ["su", "sudo"] {
            let _ = crate::parse::privilege::parse(ident, &rec.msg);
        }
        let _ = crate::patches::parse_apt_simulation(&rec.msg);
        let _ = crate::procwatch::odd_exe(&rec.msg);
        let _ = crate::feeds::parse_asns(&rec.msg);
    }
    pipe.tick(last.saturating_add(86_400 * SEC));
    let _ = pipe.snapshot(10);
}
