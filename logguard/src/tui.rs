//! Terminal dashboard. Reads snapshots from the daemon's Unix socket (live), from a
//! JSON file written by `logguard replay --snapshot`, or builds the state at the end of a
//! decision log (`actions.jsonl`, fewer tabs). Snapshots load on a thread of their own, so a
//! busy daemon or a long log never holds up the keys, and the screen is redrawn only when a
//! key, a new snapshot or a resize changed something.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline, Table, TableState, Wrap,
};
use ratatui::{DefaultTerminal, Frame};

use crate::config::Mode;
use crate::engine::{AccountView, Action, ActionKind, Ban, IpView, PlaceStats, Severity, Snapshot, Topic};
use crate::event::Signal;
use crate::net::Net;
use crate::notify::topic_name;
use crate::record::Source as LogSource;
use crate::time::{fmt_duration, fmt_ts, Micros};

#[derive(Clone)]
pub enum DataSource {
    Socket(PathBuf),
    File(PathBuf),
    /// Decision logs (one server's, several servers', rotated copies), with the geo database
    /// to place their addresses (else the places named in the ban messages are used).
    Actions(Vec<PathBuf>, Option<std::sync::Arc<crate::geo::GeoDb>>),
}

impl DataSource {
    fn load(&self) -> Result<Snapshot> {
        let text = match self {
            DataSource::Socket(p) => crate::daemon::fetch_snapshot(p)?,
            DataSource::File(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            DataSource::Actions(p, geo) => return crate::actions_view::load(p, geo.as_deref()),
        };
        serde_json::from_str(&text).context("decoding snapshot (is the daemon still starting?)")
    }

    fn live(&self) -> bool {
        matches!(self, DataSource::Socket(_))
    }

    /// Why operator commands can't be sent from here.
    fn read_only(&self) -> Option<&'static str> {
        match self {
            DataSource::Socket(_) => None,
            DataSource::File(_) => Some("read-only: this is a saved snapshot"),
            DataSource::Actions(..) => Some("read-only: this is a decision log"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Overview,
    Offenders,
    Bans,
    Events,
    Accounts,
    Exposure,
    Countries,
    Map,
    /// Decision logs only: bans per day and per week.
    Trends,
    /// The latest alerts, however many bans came after them.
    Alerts,
    /// What each `[[patterns]]` entry found; only when some are configured.
    Patterns,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Offenders => "Offenders",
            Tab::Bans => "Bans",
            Tab::Events => "Events",
            Tab::Accounts => "Accounts",
            Tab::Exposure => "Exposure",
            Tab::Countries => "Countries",
            Tab::Map => "Map",
            Tab::Trends => "Trends",
            Tab::Alerts => "Alerts",
            Tab::Patterns => "Patterns",
        }
    }

    /// Whether `/` filters its rows.
    fn filtered(self) -> bool {
        matches!(self, Tab::Offenders | Tab::Bans | Tab::Events | Tab::Accounts | Tab::Exposure | Tab::Countries | Tab::Alerts)
    }

    /// Whether Enter opens the details of the selected row.
    fn details(self) -> bool {
        matches!(self, Tab::Offenders | Tab::Bans | Tab::Events | Tab::Alerts)
    }

    /// The orders `o` cycles through, the default first.
    fn orders(self) -> &'static [&'static str] {
        match self {
            Tab::Offenders => &["danger", "last seen", "address"],
            Tab::Bans => &["newest", "time left", "address"],
            _ => &[],
        }
    }
}

// Alerts last, so the other tabs keep their numbers.
const ALL_TABS: [Tab; 9] =
    [Tab::Overview, Tab::Offenders, Tab::Bans, Tab::Events, Tab::Accounts, Tab::Exposure, Tab::Countries, Tab::Map, Tab::Alerts];
/// With `[[patterns]]` configured: their tab after the others, on key 0.
const PATTERN_TABS: [Tab; 10] = [
    Tab::Overview,
    Tab::Offenders,
    Tab::Bans,
    Tab::Events,
    Tab::Accounts,
    Tab::Exposure,
    Tab::Countries,
    Tab::Map,
    Tab::Alerts,
    Tab::Patterns,
];
/// What a decision log can fill: no scores, accounts or exposure scan in it.
const LOG_TABS: [Tab; 7] = [Tab::Overview, Tab::Bans, Tab::Events, Tab::Countries, Tab::Map, Tab::Trends, Tab::Alerts];

/// How far back an alert counts as recent for the tab bar and the Overview.
const RECENT_ALERTS: Micros = 24 * 3600 * crate::time::SEC;

/// How often a live dashboard asks the daemon for a new snapshot.
const REFRESH: Duration = Duration::from_secs(2);
/// How long a command's result stays in the footer.
const FLASH_FOR: Duration = Duration::from_secs(6);
/// The daemon keeps an operator allowlist entry a year at most.
const MAX_ALLOW_DAYS: i64 = 365;

/// Work for the background thread: a snapshot to load, a command to send to the daemon.
enum Job {
    Load,
    Command(String),
}

enum Done {
    Loaded(Result<Box<Snapshot>>),
    Replied(String, Result<String>),
}

enum Modal {
    Confirm {
        cmd: String,
        text: String,
    },
    /// `fresh` while the default is shown: the first digit typed replaces it. `ban`: how
    /// long to ban, else how long to allowlist.
    Days {
        net: Net,
        buf: String,
        fresh: bool,
        ban: bool,
    },
}

struct Flash {
    text: String,
    error: bool,
    shown: Instant,
}

struct App {
    source: DataSource,
    snap: Option<Snapshot>,
    error: Option<String>,
    /// When the snapshot shown arrived.
    loaded: Option<Instant>,
    /// A load is under way; one is wanted now (`r`, after a command, at start).
    loading: bool,
    reload: bool,
    tabs: &'static [Tab],
    tab: usize,
    table: TableState,
    /// The row drawn last and its item's key. The lists are re-sorted on every refresh, so an
    /// unmoved cursor follows its item, not its row number.
    sel: (usize, Option<String>),
    /// Rows the list drawn last had room for (PgUp/PgDn).
    page: usize,
    /// The details pane under the list (Enter), and how far it's scrolled.
    detail: bool,
    detail_scroll: u16,
    help: bool,
    modal: Option<Modal>,
    /// Result of the last operator command or hint, shown in the footer for a while.
    flash: Option<Flash>,
    /// Operator commands for the background thread to send.
    outbox: Vec<String>,
    /// Text the rows of the list tabs must contain (any case); `editing` while it's typed.
    filter: String,
    editing: bool,
    /// The current tab's sort order, an index into `Tab::orders`.
    order: usize,
    paused: bool,
    /// Events and Alerts: the least severity shown.
    min_severity: Severity,
    /// Alerts: only this topic (`t` cycles through the topics there are).
    topic: Option<Topic>,
    /// Map tab: Europe instead of the whole world.
    europe: bool,
    /// Countries tab: first network row shown (PgUp/PgDn), clamped when drawn.
    net_offset: usize,
    /// Certificates expiring within this many days are flagged on the Overview.
    cert_warn_days: i64,
}

pub fn run(source: DataSource, cert_warn_days: i64) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "the dashboard needs an interactive terminal (over ssh use `ssh -t host ...`); \
             for plain-text output use `logguard status`"
        );
    }
    let mut app = App::new(source);
    app.cert_warn_days = cert_warn_days;
    let mut terminal = ratatui::init();
    // a paste arrives whole, so its letters can't act as keys (u, then y, unbanning)
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste);
    let result = event_loop(&mut terminal, &mut app);
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    // Snapshots load, and commands go to the daemon, on a thread of their own: a busy daemon
    // never freezes the screen.
    let (ask, asked) = mpsc::channel::<Job>();
    let (send, done) = mpsc::channel();
    let source = app.source.clone();
    std::thread::spawn(move || {
        for job in asked {
            let result = match (job, &source) {
                (Job::Load, _) => Done::Loaded(source.load().map(Box::new)),
                (Job::Command(cmd), DataSource::Socket(path)) => {
                    let reply = crate::daemon::control_command(path, &cmd);
                    Done::Replied(cmd, reply)
                }
                (Job::Command(_), _) => continue,
            };
            if send.send(result).is_err() {
                break;
            }
        }
    });
    let mut last_ask: Option<Instant> = None;
    let mut dirty = true;
    loop {
        for cmd in app.outbox.drain(..) {
            ask.send(Job::Command(cmd)).context("the background thread stopped")?;
        }
        let due = app.source.live() && !app.paused && last_ask.is_none_or(|t| t.elapsed() >= REFRESH);
        if !app.loading && (app.reload || due) {
            app.reload = false;
            app.loading = true;
            last_ask = Some(Instant::now());
            ask.send(Job::Load).context("the background thread stopped")?;
        }
        if dirty {
            terminal.draw(|f| draw(f, app))?;
            dirty = false;
        }
        // keys typed ahead (a held arrow) are all handled before the next frame
        let mut wait = Duration::from_millis(100);
        while event::poll(wait)? {
            wait = Duration::ZERO;
            match event::read()? {
                TermEvent::Key(k) if k.kind == KeyEventKind::Press => {
                    if app.key(k) {
                        return Ok(());
                    }
                    dirty = true;
                }
                TermEvent::Paste(text) => {
                    app.paste(&text);
                    dirty = true;
                }
                TermEvent::Resize(..) => dirty = true,
                _ => {}
            }
        }
        while let Ok(d) = done.try_recv() {
            match d {
                Done::Loaded(r) => app.apply(r.map(|s| *s)),
                Done::Replied(cmd, reply) => app.replied(&cmd, reply),
            }
            dirty = true;
        }
        if app.flash.as_ref().is_some_and(|f| f.shown.elapsed() >= FLASH_FOR) {
            app.flash = None;
            dirty = true;
        }
    }
}

impl App {
    fn new(source: DataSource) -> App {
        let tabs: &'static [Tab] = if matches!(source, DataSource::Actions(..)) { &LOG_TABS } else { &ALL_TABS };
        App {
            source,
            snap: None,
            error: None,
            loaded: None,
            loading: false,
            reload: true,
            tabs,
            tab: 0,
            table: TableState::default().with_selected(0),
            sel: (0, None),
            page: 10,
            detail: false,
            detail_scroll: 0,
            help: false,
            modal: None,
            flash: None,
            outbox: Vec::new(),
            filter: String::new(),
            editing: false,
            order: 0,
            paused: false,
            min_severity: Severity::Info,
            topic: None,
            europe: false,
            net_offset: 0,
            cert_warn_days: crate::digest::DigestCfg::default().cert_warn_days,
        }
    }

    fn apply(&mut self, loaded: Result<Snapshot>) {
        self.loading = false;
        match loaded {
            Ok(s) => {
                if s.actions_log.is_none() {
                    self.tabs = if s.patterns.is_empty() { &ALL_TABS } else { &PATTERN_TABS };
                }
                self.snap = Some(s);
                self.error = None;
                self.loaded = Some(Instant::now());
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    #[cfg(test)]
    fn refresh(&mut self) {
        let loaded = self.source.load();
        self.apply(loaded);
    }

    fn say(&mut self, text: impl Into<String>) {
        self.flash = Some(Flash { text: text.into(), error: false, shown: Instant::now() });
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.flash = Some(Flash { text: text.into(), error: true, shown: Instant::now() });
    }

    /// Handles a key press; true to quit.
    fn key(&mut self, k: KeyEvent) -> bool {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            return true;
        }
        if self.modal.is_some() {
            self.modal_key(k.code);
            return false;
        }
        if self.editing {
            self.filter_key(k);
            return false;
        }
        if self.help {
            self.help = false;
            return false;
        }
        let tab = self.current();
        let n = self.tabs.len();
        match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Esc if self.detail => self.detail = false,
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.move_to(0);
            }
            KeyCode::Esc => self.say("q quits"),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.switch((self.tab + 1) % n),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.switch((self.tab + n - 1) % n),
            KeyCode::Char(c @ '1'..='9') if (c as usize - '1' as usize) < n => self.switch(c as usize - '1' as usize),
            KeyCode::Char('0') if n >= 10 => self.switch(9),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1),
            KeyCode::PageDown if self.detail && tab.details() => self.detail_scroll = self.detail_scroll.saturating_add(5),
            KeyCode::PageUp if self.detail && tab.details() => self.detail_scroll = self.detail_scroll.saturating_sub(5),
            KeyCode::PageDown if tab == Tab::Countries => self.net_offset += 10,
            KeyCode::PageUp if tab == Tab::Countries => self.net_offset = self.net_offset.saturating_sub(10),
            KeyCode::PageDown => self.move_by(self.page as isize),
            KeyCode::PageUp => self.move_by(-(self.page as isize)),
            KeyCode::Home | KeyCode::Char('g') => self.move_to(0),
            KeyCode::End | KeyCode::Char('G') => self.move_to(usize::MAX),
            KeyCode::Enter if tab.details() => {
                self.detail = !self.detail;
                self.detail_scroll = 0;
            }
            KeyCode::Char('/') if tab.filtered() => self.editing = true,
            KeyCode::Char('/') => self.say("nothing to filter on this tab"),
            KeyCode::Char('o') if !tab.orders().is_empty() => {
                self.order = (self.order + 1) % tab.orders().len();
                self.move_to(0);
                self.say(format!("sorted by {}", tab.orders()[self.order]));
            }
            KeyCode::Char('s') if matches!(tab, Tab::Events | Tab::Alerts) => {
                self.min_severity = match self.min_severity {
                    Severity::Info => Severity::Warning,
                    Severity::Warning => Severity::High,
                    Severity::High => Severity::Critical,
                    Severity::Critical => Severity::Info,
                };
                self.move_to(0);
            }
            KeyCode::Char('t') if tab == Tab::Alerts => {
                let topics: std::collections::BTreeSet<Topic> = self.snap.iter().flat_map(|s| &s.alerts).filter_map(|a| a.topic).collect();
                self.topic = match self.topic {
                    None => topics.first().copied(),
                    Some(t) => topics.range((std::ops::Bound::Excluded(t), std::ops::Bound::Unbounded)).next().copied(),
                };
                self.move_to(0);
                self.say(format!("topic: {}", self.topic.map_or("all", topic_name)));
            }
            KeyCode::Char('z') if tab == Tab::Map => self.europe = !self.europe,
            KeyCode::Char('u') => self.start_unban(),
            KeyCode::Char('a') => self.start_allow(),
            KeyCode::Char('b') => self.start_ban(),
            KeyCode::Char('p') if self.source.live() => self.paused = !self.paused,
            KeyCode::Char('r') => self.reload = true,
            _ => {}
        }
        false
    }

    fn filter_key(&mut self, k: KeyEvent) {
        let modified = k.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match k.code {
            KeyCode::Enter => self.editing = false,
            KeyCode::Esc => {
                self.editing = false;
                self.filter.clear();
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            // as in a shell
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => self.filter.clear(),
            KeyCode::Char(c) if !modified && self.filter.chars().count() < 60 => self.filter.push(c),
            // the rows that match can be picked while the filter is typed
            KeyCode::Down => return self.move_by(1),
            KeyCode::Up => return self.move_by(-1),
            KeyCode::PageDown => return self.move_by(self.page as isize),
            KeyCode::PageUp => return self.move_by(-(self.page as isize)),
            KeyCode::Home => return self.move_to(0),
            KeyCode::End => return self.move_to(usize::MAX),
            _ => return,
        }
        // Enter keeps the row picked; a changed filter starts at the top
        if k.code != KeyCode::Enter {
            self.move_to(0);
        }
    }

    /// Pasted text goes into the filter being typed; anywhere else it is ignored.
    fn paste(&mut self, text: &str) {
        if !self.editing {
            self.say("paste ignored: / starts a filter");
            return;
        }
        let room = 60usize.saturating_sub(self.filter.chars().count());
        self.filter.extend(text.chars().filter(|c| !c.is_control()).take(room));
        self.move_to(0);
    }

    /// Moves the cursor; it no longer follows the item it was on.
    fn move_by(&mut self, rows: isize) {
        self.move_to(self.table.selected().unwrap_or(0).saturating_add_signed(rows));
    }

    /// Selects row `i` (clamped when drawn), not following the item selected before.
    fn move_to(&mut self, i: usize) {
        self.table.select(Some(i));
        self.sel = (i, None);
        self.net_offset = 0;
        self.detail_scroll = 0;
    }

    /// The selected row of `rows`, kept on the same item when a refresh re-sorted the list and
    /// the cursor wasn't moved since the last frame.
    fn follow<T>(&mut self, rows: &[T], key: impl Fn(&T) -> String) -> Option<usize> {
        let mut sel = self.table.selected().unwrap_or(0);
        if let (true, Some(k)) = (sel == self.sel.0, &self.sel.1) {
            if let Some(i) = rows.iter().position(|r| key(r) == *k) {
                sel = i;
            }
        }
        let sel = sel.min(rows.len().saturating_sub(1));
        self.table.select(Some(sel));
        self.sel = (sel, rows.get(sel).map(&key));
        rows.get(sel).map(|_| sel)
    }

    /// The address/network under the cursor on the Offenders, Bans, Events or Alerts tab,
    /// and whether it is banned.
    fn selected_target(&self) -> Option<(Net, bool)> {
        let s = self.snap.as_ref()?;
        // End, or keys typed ahead of the next frame, may have gone past the last row
        let selected = self.table.selected()?;
        let at = |len: usize| selected.min(len.saturating_sub(1));
        match self.current() {
            Tab::Offenders => {
                let rows = offender_rows(self, s);
                rows.get(at(rows.len())).map(|v| v.banned_by.map_or((Net::host(v.ip), false), |n| (n, true)))
            }
            Tab::Bans => {
                let rows = ban_rows(self, s);
                rows.get(at(rows.len())).map(|b| (b.net, true))
            }
            Tab::Events | Tab::Alerts => {
                let rows = if self.current() == Tab::Events { event_rows(self, s) } else { alert_rows(self, s) };
                let net = rows.get(at(rows.len()))?.target?;
                Some((net, s.bans.iter().any(|b| b.net == net)))
            }
            _ => None,
        }
    }

    fn start_unban(&mut self) {
        if let Some(why) = self.source.read_only() {
            self.warn(why);
            return;
        }
        match self.selected_target() {
            Some((net, true)) => {
                self.modal =
                    Some(Modal::Confirm { cmd: format!("unban {net}"), text: format!("Unban {net} and forget its offence history?") })
            }
            Some((net, false)) => self.warn(format!("{net} is not banned")),
            None => self.warn("select an address on the Offenders, Bans, Events or Alerts tab"),
        }
    }

    fn start_allow(&mut self) {
        if let Some(why) = self.source.read_only() {
            self.warn(why);
            return;
        }
        match self.selected_target() {
            Some((net, _)) => self.modal = Some(Modal::Days { net, buf: "7".into(), fresh: true, ban: false }),
            None => self.warn("select an address on the Offenders, Bans, Events or Alerts tab"),
        }
    }

    fn start_ban(&mut self) {
        if let Some(why) = self.source.read_only() {
            self.warn(why);
            return;
        }
        match self.selected_target() {
            Some((net, true)) => self.warn(format!("{net} is banned already")),
            Some((net, false)) => self.modal = Some(Modal::Days { net, buf: "1".into(), fresh: true, ban: true }),
            None => self.warn("select an address on the Offenders, Events or Alerts tab"),
        }
    }

    fn modal_key(&mut self, key: KeyCode) {
        match (self.modal.take(), key) {
            (Some(Modal::Confirm { cmd, .. }), KeyCode::Char('y' | 'Y')) => self.command(&cmd),
            (Some(Modal::Days { net, mut buf, fresh, ban }), k) => match k {
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    if fresh {
                        buf.clear();
                    }
                    if buf.len() < 4 {
                        buf.push(c);
                    }
                    if buf.parse::<i64>().unwrap_or(0) > MAX_ALLOW_DAYS {
                        buf = MAX_ALLOW_DAYS.to_string();
                        self.warn(format!("{MAX_ALLOW_DAYS} days at most"));
                    }
                    self.modal = Some(Modal::Days { net, buf, fresh: false, ban });
                }
                KeyCode::Backspace => {
                    buf.pop();
                    self.modal = Some(Modal::Days { net, buf, fresh: false, ban });
                }
                KeyCode::Enter => match buf.parse::<i64>() {
                    Ok(days) if days > 0 && ban => self.command(&format!("ban {net} {} banned from the TUI", days * 86_400)),
                    Ok(days) if days > 0 => self.command(&format!("allow {net} {} allowlisted from the TUI", days * 86_400)),
                    _ => {
                        self.warn("enter a number of days");
                        self.modal = Some(Modal::Days { net, buf, fresh, ban });
                    }
                },
                KeyCode::Esc => self.say("cancelled"),
                _ => self.modal = Some(Modal::Days { net, buf, fresh, ban }),
            },
            _ => self.say("cancelled"),
        }
    }

    /// Queues an operator command for the daemon; its answer shows in the footer.
    fn command(&mut self, cmd: &str) {
        if let Some(why) = self.source.read_only() {
            self.warn(why);
            return;
        }
        self.outbox.push(cmd.to_string());
        self.say(format!("sent: {cmd}"));
    }

    /// The daemon's answer to a command; a snapshot with its effect is loaded next.
    fn replied(&mut self, cmd: &str, reply: Result<String>) {
        match reply {
            Ok(reply) => {
                let text = reply.lines().filter(|l| *l != "ok").collect::<Vec<_>>().join(" | ");
                match text {
                    t if t.starts_with("error") => self.warn(t),
                    t if t.is_empty() => self.say(format!("done: {cmd}")),
                    t => self.say(t),
                }
            }
            Err(e) => self.warn(format!("error: {e:#}")),
        }
        self.reload = true;
    }

    fn current(&self) -> Tab {
        self.tabs[self.tab.min(self.tabs.len() - 1)]
    }

    fn switch(&mut self, tab: usize) {
        self.tab = tab;
        self.detail = false;
        self.order = 0;
        self.move_to(0);
    }
}

// --- rows of the list tabs, filtered and sorted the same way for drawing and for commands

/// The filter in lower case, None when there is none.
fn needle(app: &App) -> Option<String> {
    (!app.filter.is_empty()).then(|| app.filter.to_lowercase())
}

/// Whether one of `fields` contains `needle` (lower case), ignoring case.
fn has(needle: &str, fields: &[&str]) -> bool {
    fields.iter().any(|f| f.to_lowercase().contains(needle))
}

fn offender_rows<'a>(app: &App, s: &'a Snapshot) -> Vec<&'a IpView> {
    let needle = needle(app);
    let mut rows: Vec<&IpView> = s
        .offenders
        .iter()
        .filter(|v| {
            needle.as_deref().is_none_or(|n| {
                let net = v.banned_by.map(|b| format!("banned {b}")).unwrap_or_default();
                has(n, &[&v.ip.to_string(), v.geo.as_deref().unwrap_or(""), v.protected.as_deref().unwrap_or(""), &net])
                    || v.counts.keys().any(|sig| sig.name().contains(n))
            })
        })
        .collect();
    match app.order {
        1 => rows.sort_by_key(|v| std::cmp::Reverse(v.last_seen)),
        2 => rows.sort_by_key(|v| v.ip),
        // the daemon ranks them by danger
        _ => {}
    }
    rows
}

fn ban_rows<'a>(app: &App, s: &'a Snapshot) -> Vec<&'a Ban> {
    let needle = needle(app);
    let mut rows: Vec<&Ban> =
        s.bans.iter().filter(|b| needle.as_deref().is_none_or(|n| has(n, &[&b.net.to_string(), &ban_reason(b)]))).collect();
    match app.order {
        1 => rows.sort_by_key(|b| b.until),
        2 => rows.sort_by_key(|b| b.net),
        _ => rows.sort_by_key(|b| std::cmp::Reverse(b.since)),
    }
    rows
}

fn event_rows<'a>(app: &App, s: &'a Snapshot) -> Vec<&'a Action> {
    let needle = needle(app);
    s.recent
        .iter()
        .filter(|a| a.severity >= app.min_severity)
        .filter(|a| {
            needle.as_deref().is_none_or(|n| {
                has(n, &[&a.message, kind_name(a.kind), &a.target.map(|t| t.to_string()).unwrap_or_default(), &a.accounts.join(" ")])
            })
        })
        .collect()
}

fn alert_rows<'a>(app: &App, s: &'a Snapshot) -> Vec<&'a Action> {
    let needle = needle(app);
    s.alerts
        .iter()
        .filter(|a| a.severity >= app.min_severity && app.topic.is_none_or(|t| a.topic == Some(t)))
        .filter(|a| {
            needle.as_deref().is_none_or(|n| {
                let target = a.target.map(|t| t.to_string()).unwrap_or_default();
                has(n, &[&a.message, a.topic.map_or("", topic_name), &target, &a.accounts.join(" ")])
            })
        })
        .collect()
}

/// High and critical alerts in the day before the snapshot.
fn serious_alerts(s: &Snapshot) -> usize {
    s.alerts.iter().filter(|a| a.severity >= Severity::High && s.generated - a.ts <= RECENT_ALERTS).count()
}

fn account_rows<'a>(app: &App, s: &'a Snapshot) -> Vec<&'a AccountView> {
    let needle = needle(app);
    s.accounts.iter().filter(|a| needle.as_deref().is_none_or(|n| has(n, &[&a.account]))).collect()
}

fn kind_name(k: ActionKind) -> &'static str {
    match k {
        ActionKind::Ban => "ban",
        ActionKind::Unban => "unban",
        ActionKind::Alert => "alert",
        ActionKind::Allow => "allow",
        ActionKind::Disallow => "disallow",
    }
}

// --- small formatting helpers

fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::new().fg(Color::LightRed),
        Severity::Warning => Style::new().fg(Color::Yellow),
        Severity::Info => Style::new().fg(Color::Gray),
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn danger_style(d: f64) -> Style {
    match d {
        d if d >= 100.0 => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        d if d >= 50.0 => Style::new().fg(Color::LightRed),
        d if d >= 20.0 => Style::new().fg(Color::Yellow),
        _ => Style::new(),
    }
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

fn block(title: impl Into<String>) -> Block<'static> {
    Block::bordered().border_type(BorderType::Rounded).title(Span::styled(format!(" {} ", title.into()), Style::new().bold()))
}

/// "1 country", "3 countries", "1,200 addresses"
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", grouped(n), if n == 1 { one } else { many })
}

/// 12345 -> "12,345"
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "12m03s ago", counted back from the snapshot (a saved one's "now" is when it was taken).
fn ago(now: Micros, ts: Micros) -> String {
    format!("{} ago", fmt_duration(now - ts))
}

/// "United Kingdom / DigitalOcean, LLC (AS14061)" -> "GB DigitalOcean, LLC", for a column.
fn short_place(geo: &str) -> String {
    let org = |n: &str| n.rsplit_once(" (AS").map_or(n, |(o, _)| o).to_string();
    match geo.split_once(" / ") {
        Some((country, net)) => match crate::geo::country_code(country) {
            Some(cc) => format!("{} {}", String::from_utf8_lossy(&cc), org(net)),
            None => format!("{country} / {}", org(net)),
        },
        None => org(geo),
    }
}

/// "banned 4h05m", "banned 5d08h in /24" (the network is in the details), the protection,
/// or nothing.
fn offender_status(v: &IpView, now: Micros) -> (String, Style) {
    match (&v.banned_by, &v.protected) {
        (Some(n), _) => {
            let left = v.banned_until.map(|u| fmt_duration(u - now)).unwrap_or_default();
            let text = if n.is_host() { format!("banned {left}") } else { format!("banned {left} in /{}", n.prefix) };
            (text, Style::new().fg(Color::Red))
        }
        (None, Some(p)) => (p.clone(), Style::new().fg(Color::Green)),
        _ => (String::new(), Style::new()),
    }
}

/// The ban's reason, naming the peer it came from (the daemon's text does; a log's doesn't).
fn ban_reason(b: &Ban) -> String {
    match &b.origin {
        Some(o) if !b.reason.starts_with("peer ") => format!("peer {o}: {}", b.reason),
        _ => b.reason.clone(),
    }
}

/// "BAN", or "~BAN" when it wasn't applied, coloured by severity.
fn action_cell(a: &Action) -> Cell<'static> {
    let tag = if a.applied || a.kind == ActionKind::Alert { "" } else { "~" };
    Cell::from(format!("{tag}{}", kind_name(a.kind).to_uppercase())).style(severity_style(a.severity))
}

fn top_signals(counts: &std::collections::BTreeMap<Signal, u64>, n: usize) -> String {
    let mut v: Vec<(&Signal, &u64)> = counts.iter().filter(|(s, _)| !s.is_success()).collect();
    v.sort_by(|a, b| b.1.cmp(a.1));
    v.iter().take(n).map(|(s, c)| format!("{c}×{}", s.name())).collect::<Vec<_>>().join(" ")
}

// --- building blocks of the tabs

/// Which columns fit in `width`, one cell apart: (width, drop) each, the highest `drop` left
/// out first, 0 never; a column 0 wide is never shown.
fn fit(width: u16, cols: &[(u16, u8)], spacing: u16) -> Vec<bool> {
    let mut show: Vec<bool> = cols.iter().map(|c| c.0 > 0).collect();
    let used = |show: &[bool]| cols.iter().zip(show).filter(|(_, s)| **s).map(|(c, _)| c.0 + spacing).sum::<u16>();
    let mut levels: Vec<u8> = cols.iter().map(|c| c.1).filter(|d| *d > 0).collect();
    levels.sort_unstable_by(|a, b| b.cmp(a));
    levels.dedup();
    for level in levels {
        if used(&show) <= width + spacing {
            break;
        }
        for (s, c) in show.iter_mut().zip(cols) {
            if c.1 == level {
                *s = false;
            }
        }
    }
    show
}

/// A table with the columns that fit in `area`: (header, width, drop) each, see `fit`; the
/// last column shown takes the room left. `rows` hold a cell for every column.
fn fitted_table<'a>(area: Rect, cols: &[(&'static str, u16, u8)], rows: Vec<Vec<Cell<'a>>>) -> Table<'a> {
    fitted_table_spaced(area, cols, rows, 1)
}

/// `fitted_table` with `spacing` columns between two columns.
fn fitted_table_spaced<'a>(area: Rect, cols: &[(&'static str, u16, u8)], rows: Vec<Vec<Cell<'a>>>, spacing: u16) -> Table<'a> {
    let show = fit(area.width.saturating_sub(2), &cols.iter().map(|c| (c.1, c.2)).collect::<Vec<_>>(), spacing);
    let last = show.iter().rposition(|s| *s);
    let widths: Vec<Constraint> = cols
        .iter()
        .enumerate()
        .filter(|(i, _)| show[*i])
        .map(|(i, c)| if Some(i) == last { Constraint::Min(c.1) } else { Constraint::Length(c.1) })
        .collect();
    let pick = |cells: Vec<Cell<'a>>| cells.into_iter().zip(&show).filter(|(_, s)| **s).map(|(c, _)| c).collect::<Vec<_>>();
    let header = cols.iter().zip(&show).filter(|(_, s)| **s).map(|(c, _)| c.0).collect::<Vec<_>>();
    Table::new(rows.into_iter().map(|r| Row::new(pick(r))), widths)
        .header(Row::new(header).bold())
        .column_spacing(spacing)
        .row_highlight_style(Style::new().reversed())
}

/// "Offenders (203)", or "Offenders (12 of 203 match "68.1")", then the sort order if not
/// the default.
fn list_title(app: &App, name: &str, shown: usize, total: usize) -> String {
    let mut t = match (app.filter.is_empty(), shown == total) {
        (true, true) => format!("{name} ({total})"),
        (true, false) => format!("{name} ({shown} of {total})"),
        (false, _) => format!("{name} ({shown} of {total} match \"{}\")", app.filter),
    };
    if app.order > 0 {
        if let Some(o) = app.current().orders().get(app.order) {
            t += &format!(" · by {o}");
        }
    }
    t
}

/// A list's border: its title, and the selected row's position at the bottom right.
fn list_block(title: String, sel: Option<usize>, n: usize) -> Block<'static> {
    match sel {
        Some(i) if n > 1 => block(title).title_bottom(Line::from(format!(" {}/{n} ", i + 1)).right_aligned()),
        _ => block(title),
    }
}

/// A scrollbar on the right border of a bordered table with a header, beside its rows, when
/// they don't fit.
fn scrollbar(f: &mut Frame, area: Rect, n: usize, sel: usize) {
    let fit = area.height.saturating_sub(3);
    if n > usize::from(fit) {
        let mut state = ScrollbarState::new(n).position(sel).viewport_content_length(usize::from(fit));
        let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("┃")
            .thumb_style(Style::new().fg(Color::Cyan));
        f.render_stateful_widget(bar, Rect { y: area.y + 2, height: fit, ..area }, &mut state);
    }
}

/// What an empty list says: `none`, or that nothing matches the filter.
fn empty_list(f: &mut Frame, area: Rect, app: &App, title: String, none: &str) {
    let text = if app.filter.is_empty() { none.to_string() } else { format!("Nothing matches \"{}\". Esc clears the filter.", app.filter) };
    f.render_widget(Paragraph::new(Line::styled(text, dim())).wrap(Wrap { trim: true }).block(block(title)), area);
}

/// Rows `lines` take wrapped at `width` cells as a Paragraph wraps them, word by word (at
/// most `u16::MAX`).
fn wrapped_height(lines: &[Line], width: u16) -> u16 {
    let rows = Paragraph::new(lines.to_vec()).wrap(Wrap { trim: false }).line_count(width.max(1));
    u16::try_from(rows).unwrap_or(u16::MAX)
}

/// An address's evidence lines, or why there are none: they aren't kept in the state file,
/// so an address last seen before the daemon (re)started has its score but no evidence.
fn evidence_lines(v: &IpView, s: &Snapshot) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("evidence (latest last):".bold())];
    if v.evidence.is_empty() {
        let why = if s.started > 0 && v.last_seen < s.started {
            format!("  none: last seen before logguard started ({}), and evidence isn't kept across restarts", fmt_ts(s.started))
        } else {
            "  none".into()
        };
        lines.push(Line::styled(why, dim()));
    }
    lines.extend(v.evidence.iter().map(|e| Line::from(format!("  {e}"))));
    lines
}

/// A box with `lines`, centred in `area`, at most `width` wide.
fn popup(f: &mut Frame, area: Rect, title: &str, lines: Vec<Line<'static>>, width: u16) {
    let w = width.min(area.width);
    let h = wrapped_height(&lines, w.saturating_sub(2)).saturating_add(2).min(area.height);
    let r = Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h };
    f.render_widget(Clear, r);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block(title)), r);
}

/// Draws the details pane under the list when it's open, and returns the area left for the
/// list (at least a few rows of it).
fn detail_pane(f: &mut Frame, area: Rect, app: &mut App, lines: Option<Vec<Line<'static>>>) -> Rect {
    let Some(lines) = lines else { return area };
    let need = wrapped_height(&lines, area.width.saturating_sub(2)).saturating_add(2);
    let h = need.min(area.height / 5 * 3).min(area.height.saturating_sub(5));
    if h < 3 {
        return area;
    }
    let [list, pane] = Layout::vertical([Constraint::Min(0), Constraint::Length(h)]).areas(area);
    let hidden = need.saturating_sub(h);
    app.detail_scroll = app.detail_scroll.min(hidden);
    let mut b = block("Details");
    if hidden > 0 {
        b = b.title_bottom(Line::from(" PgUp/PgDn scroll ").right_aligned());
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((app.detail_scroll, 0)).block(b), pane);
    list
}

// --- the frame

fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).areas(f.area());
    draw_tabs(f, header, app);
    draw_footer(f, footer, app);

    // Borrow the snapshot out of `app` instead of cloning it on every frame.
    let Some(snap) = app.snap.take() else {
        draw_waiting(f, body, app);
        if app.help {
            popup(f, f.area(), "Keys", help_lines(app), 82);
        }
        return;
    };
    let s = &snap;
    match app.current() {
        Tab::Overview => match &s.actions_log {
            Some(log) => draw_log_overview(f, body, s, log),
            None => draw_overview(f, body, s, app.cert_warn_days),
        },
        Tab::Offenders => {
            let rows = offender_rows(app, s);
            let sel = app.follow(&rows, |v| v.ip.to_string());
            let detail = sel.filter(|_| app.detail).map(|i| offender_detail(rows[i], s));
            let area = detail_pane(f, body, app, detail);
            draw_offenders(f, area, app, s, &rows);
        }
        Tab::Bans => {
            let rows = ban_rows(app, s);
            let sel = app.follow(&rows, |b| b.net.to_string());
            let detail = sel.filter(|_| app.detail).map(|i| ban_detail(rows[i], s));
            let area = detail_pane(f, body, app, detail);
            draw_bans(f, area, app, s, &rows);
        }
        Tab::Events => {
            let rows = event_rows(app, s);
            let sel = app.follow(&rows, |a| format!("{} {}", a.ts, a.message));
            let detail = sel.filter(|_| app.detail).map(|i| event_detail(rows[i], s));
            let area = detail_pane(f, body, app, detail);
            draw_events(f, area, app, s, &rows);
        }
        Tab::Alerts => {
            let rows = alert_rows(app, s);
            let sel = app.follow(&rows, |a| format!("{} {}", a.ts, a.message));
            let detail = sel.filter(|_| app.detail).map(|i| event_detail(rows[i], s));
            let area = detail_pane(f, body, app, detail);
            draw_alerts(f, area, app, s, &rows);
        }
        Tab::Accounts => draw_accounts(f, body, app, s),
        Tab::Exposure => draw_exposure(f, body, app, s),
        Tab::Countries => draw_countries(f, body, app, s),
        Tab::Map => draw_map(f, body, s, app.europe),
        Tab::Patterns => draw_patterns(f, body, app, s),
        Tab::Trends => {
            if let Some(log) = &s.actions_log {
                draw_trends(f, body, app, log);
            }
        }
    }
    if let Some(m) = &app.modal {
        draw_modal(f, body, m);
    }
    if app.help {
        popup(f, f.area(), "Keys", help_lines(app), 82);
    }
    app.snap = Some(snap);
}

/// The tab bar: names and counts if they fit, else names, else names closer together, else
/// only the current tab's name.
fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let current = app.tab.min(app.tabs.len() - 1);
    // counts, and alerts (red) that stay, shortened to "!", when the bar gets short
    let red = Style::new().fg(Color::Red).bold();
    let badge = |t: Tab| -> Option<(String, Style, bool)> {
        let s = app.snap.as_ref()?;
        match t {
            Tab::Offenders => Some((s.offenders.len().to_string(), dim(), false)),
            Tab::Bans => Some((s.bans.len().to_string(), dim(), false)),
            Tab::Accounts => match s.accounts.iter().filter(|a| a.under_attack).count() {
                0 => None,
                n => Some((n.to_string(), red, true)),
            },
            Tab::Exposure => {
                let absent =
                    |r: &&crate::exposure::ExposureReport| r.firewall() == crate::exposure::Firewall::Absent && r.firewall_checked();
                s.exposure.as_ref().filter(absent).map(|_| ("no firewall".into(), red, true))
            }
            Tab::Alerts => match serious_alerts(s) {
                0 => None,
                n => Some((n.to_string(), red, true)),
            },
            _ => None,
        }
    };
    let line = |level: u8| {
        let mut spans = Vec::new();
        for (i, t) in app.tabs.iter().enumerate() {
            let on = i == current;
            let style = if on { Style::new().fg(Color::Cyan).bold().reversed() } else { Style::new() };
            match (i, level) {
                (_, 2) => spans.push(" ".into()),
                (0, _) => {}
                _ => spans.push(Span::styled("│", dim())),
            }
            // level 2: "4Events", the number set apart by its colour
            let (pad, gap) = if level == 2 { ("", "") } else { (" ", " ") };
            let number = if level == 2 && !on { Style::new().fg(Color::Cyan) } else { style };
            // the tenth tab is on key 0
            spans.push(Span::styled(format!("{pad}{}", (i + 1) % 10), number));
            if level < 3 || on {
                spans.push(Span::styled(format!("{gap}{}", t.title()), style));
            }
            match badge(*t) {
                Some((n, badge_style, _)) if level == 0 => spans.push(Span::styled(format!(" {n}"), if on { style } else { badge_style })),
                Some((_, badge_style, true)) => spans.push(Span::styled(if level == 3 && !on { "!" } else { " !" }, badge_style)),
                _ => {}
            }
            spans.push(Span::styled(pad, style));
        }
        Line::from(spans)
    };
    let fits = (0..4).map(line).find(|l| l.width() <= usize::from(area.width)).unwrap_or_else(|| line(3));
    f.render_widget(Paragraph::new(fits), area);
}

/// Key hints (or the filter being typed, a command's result, the last error) on the left; the
/// node, mode and how fresh the data is on the right.
fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let status = Line::from(status_spans(app));
    let w = (status.width() as u16).min(area.width);
    let [left, right] = Layout::horizontal([Constraint::Min(0), Constraint::Length(w)]).areas(area);
    f.render_widget(Paragraph::new(status), right);
    let line = if app.editing {
        Line::from(vec![
            Span::styled(" filter: ", Style::new().fg(Color::Cyan).bold()),
            Span::raw(app.filter.clone()),
            Span::styled("▏", Style::new().fg(Color::Cyan)),
            Span::styled("  ↑↓ pick a row, enter keeps the filter, esc clears it", dim()),
        ])
    } else if let Some(fl) = &app.flash {
        Line::styled(format!(" {}", fl.text), Style::new().fg(if fl.error { Color::Red } else { Color::Yellow }))
    } else if let (Some(e), Some(_)) = (&app.error, &app.snap) {
        Line::styled(format!(" {e}"), Style::new().fg(Color::Red))
    } else {
        hint_line(app, left.width)
    };
    f.render_widget(Paragraph::new(line), left);
}

fn status_spans(app: &App) -> Vec<Span<'static>> {
    let Some(s) = &app.snap else {
        return vec![Span::styled(if app.error.is_some() { "no data " } else { "loading… " }, dim())];
    };
    let mut v = Vec::new();
    if let Some(c) = &s.cluster {
        v.push(Span::styled(format!("{} ", c.node_id), Style::new().bold()));
    }
    v.push(match s.mode {
        Mode::Enforce => Span::styled("ENFORCE", Style::new().fg(Color::Green).bold()),
        Mode::Shadow => Span::styled("SHADOW", Style::new().fg(Color::Yellow).bold()),
    });
    v.push(Span::styled(" │ ", dim()));
    match &app.source {
        DataSource::Socket(_) if app.error.is_some() => {
            let stale = app.loaded.map_or(0, |t| t.elapsed().as_micros() as Micros);
            v.push(Span::styled(format!("no update for {}", fmt_duration(stale)), Style::new().fg(Color::Red).bold()));
        }
        DataSource::Socket(_) => {
            if app.paused {
                v.push(Span::styled("PAUSED", Style::new().fg(Color::Yellow).reversed()));
                v.push(" ".into());
            } else {
                v.push(Span::styled("live ", dim()));
            }
            v.push(fmt_ts(s.generated)[11..].to_string().into());
        }
        DataSource::File(_) => {
            v.push(Span::styled("file ", dim()));
            v.push(fmt_ts(s.generated)[..16].to_string().into());
        }
        DataSource::Actions(..) => v.push(Span::styled("decision log, read-only", dim())),
    }
    v.push(" ".into());
    v
}

/// The keys that do something here, as many as fit, then help and quit.
fn hint_line(app: &App, width: u16) -> Line<'static> {
    let tab = app.current();
    let live = app.source.live();
    let mut hints: Vec<(&str, &str)> = Vec::new();
    if app.detail && tab.details() {
        hints.extend([("esc", "close"), ("↑↓", "next"), ("PgUp/PgDn", "scroll")]);
    } else if !app.filter.is_empty() {
        hints.push(("esc", "clear filter"));
    }
    match tab {
        Tab::Overview => hints.push(("←→", "tabs")),
        Tab::Offenders | Tab::Bans | Tab::Events | Tab::Alerts => {
            if !app.detail {
                hints.extend([("↑↓", "select"), ("enter", "details")]);
            }
            hints.push(("/", "filter"));
            match tab {
                Tab::Events => hints.push(("s", "severity")),
                Tab::Alerts => hints.extend([("s", "severity"), ("t", "topic")]),
                _ => hints.push(("o", "sort")),
            }
            if live {
                hints.extend([("u", "unban"), ("a", "allow"), ("b", "ban")]);
            }
        }
        Tab::Accounts | Tab::Exposure => hints.push(("/", "filter")),
        Tab::Countries => hints.extend([("↑↓", "country"), ("PgUp/PgDn", "networks"), ("/", "filter")]),
        Tab::Map => hints.push(("z", if app.europe { "world" } else { "Europe" })),
        Tab::Trends => hints.push(("↑↓", "weeks")),
        Tab::Patterns => hints.push(("↑↓", "pattern")),
    }
    if live {
        hints.push(("p", if app.paused { "resume" } else { "pause" }));
    }
    hints.push(("r", if live { "refresh" } else { "reload" }));

    let tail = [("?", "help"), ("q", "quit")];
    let width_of = |(k, l): &(&str, &str)| k.chars().count() + l.chars().count() + 3;
    let mut room = usize::from(width).saturating_sub(1 + tail.iter().map(width_of).sum::<usize>());
    let mut spans = vec![Span::raw(" ")];
    let shown = hints.iter().take_while(|h| room.checked_sub(width_of(h)).map(|r| room = r).is_some());
    for (k, l) in shown.chain(tail.iter()) {
        spans.push(Span::styled(k.to_string(), Style::new().bold()));
        spans.push(Span::styled(format!(" {l}  "), dim()));
    }
    Line::from(spans)
}

fn help_lines(app: &App) -> Vec<Line<'static>> {
    let row = |k: &str, what: &str| Line::from(vec![Span::styled(format!(" {k:<18}"), Style::new().bold()), Span::raw(what.to_string())]);
    let live = app.source.live();
    let mut v = vec![
        row("Tab ⇧Tab ← → 1-9", "switch tabs (0: Patterns, with [[patterns]] configured)"),
        row("↑ ↓  j k", "select a row (with the details open: the next one)"),
        row("PgUp PgDn", "a page; on Countries the networks; the details when open"),
        row("Home End  g G", "first, last row"),
        row("Enter", "details of the selected row (Offenders, Bans, Events, Alerts)"),
        row("/", "filter the rows by any text in them (↑↓ pick a row meanwhile); Esc clears it"),
        row("o", "sort order (Offenders, Bans)"),
        row("s", "minimum severity (Events, Alerts)"),
        row("t", "topic (Alerts)"),
        row("z", "map of Europe or the world"),
    ];
    if live {
        v.push(row("u", "unban the selected address or network (asks first)"));
        v.push(row("a", "allowlist it for some days"));
        v.push(row("b", "ban it for some days (shared with the peers)"));
        v.push(row("p", "pause or resume the updates"));
    }
    v.push(row("r", if live { "refresh now" } else { "read the file again" }));
    v.push(row("Esc", "close the details, clear the filter"));
    v.push(row("q  Ctrl-C", "quit"));
    v.push(Line::from(""));
    v.push(Line::from(vec![
        Span::styled(" red", Style::new().fg(Color::Red)),
        " banned, high  ".into(),
        Span::styled("yellow", Style::new().fg(Color::Yellow)),
        " warning  ".into(),
        Span::styled("green", Style::new().fg(Color::Green)),
        " protected, allowed  ".into(),
        Span::styled("magenta", Style::new().fg(Color::Magenta)),
        " subnet".into(),
    ]));
    v.push(Line::from(" ~BAN: not applied (failed, since expired, or decided in shadow mode). Times are UTC."));
    v.push(Line::styled(" Any key closes this.", dim()));
    v
}

/// No snapshot yet: loading, or why it can't be read.
fn draw_waiting(f: &mut Frame, area: Rect, app: &App) {
    let lines = match &app.error {
        None => vec![Line::styled("Loading the snapshot…", dim())],
        Some(e) => {
            let hint = match &app.source {
                DataSource::Socket(p) => format!(
                    "Is logguard running (systemctl status logguard)? Only root can open {}. Trying again every {} s; q quits.",
                    p.display(),
                    REFRESH.as_secs()
                ),
                _ => "r tries again; q quits.".to_string(),
            };
            vec![Line::styled(e.clone(), Style::new().fg(Color::Red)), Line::from(""), Line::from(hint)]
        }
    };
    popup(f, area, "logguard", lines, 76);
}

fn draw_modal(f: &mut Frame, area: Rect, m: &Modal) {
    let key = |k: &str| Span::styled(k.to_string(), Style::new().fg(Color::Cyan).bold());
    let (title, lines) = match m {
        Modal::Confirm { text, .. } => (
            "Confirm",
            vec![
                Line::from(text.clone()),
                Line::from(""),
                Line::from(vec![key("y"), " yes   ".into(), key("any other key"), " no".into()]),
            ],
        ),
        Modal::Days { net, buf, ban, .. } => {
            let until = buf
                .parse::<i64>()
                .ok()
                .filter(|d| *d > 0)
                .map(|d| format!(", until {} UTC", &fmt_ts(crate::time::now() + d * 86_400 * crate::time::SEC)[..16]))
                .unwrap_or_default();
            let (title, question, verb) = if *ban {
                ("Ban", format!("Ban {net} for how many days? ({MAX_ALLOW_DAYS} at most)"), " ban   ")
            } else {
                ("Allowlist", format!("Never ban {net} for how many days? ({MAX_ALLOW_DAYS} at most)"), " allowlist   ")
            };
            (
                title,
                vec![
                    Line::from(question),
                    Line::from(vec![Span::styled(format!(" {buf}▏"), Style::new().bold()), format!(" days{until}").into()]),
                    Line::from(""),
                    Line::from(vec![key("enter"), verb.into(), key("esc"), " cancel".into()]),
                ],
            )
        }
    };
    popup(f, area, title, lines, 64);
}

// --- Overview

fn draw_overview(f: &mut Frame, area: Rect, s: &Snapshot, cert_warn_days: i64) {
    let status = status_lines(s);
    let health = health_lines(s, cert_warn_days);
    let st = &s.stats;
    // log sources that sent anything; the others are off on this server
    let sources: Vec<(LogSource, u64, Option<Micros>)> = LogSource::ALL
        .iter()
        .filter_map(|src| {
            let recs = st.records.get(src).copied().unwrap_or(0);
            let last = s.last_lines.get(src).copied();
            (recs > 0 || last.is_some()).then_some((*src, recs, last))
        })
        .collect();
    let health = if health.is_empty() {
        vec![Line::styled("No cluster, feeds, certificate, disk or antivirus checks in this snapshot.", dim())]
    } else {
        health
    };
    // long lines wrap in a narrow terminal: room for all of them
    let inner = (area.width / 2).saturating_sub(2);
    let top_h = wrapped_height(&status, inner).max(wrapped_height(&health, inner)).saturating_add(2);
    let mid_h = (sources.len() as u16 + 3).clamp(6, 10);
    let [top, mid, bottom] = Layout::vertical([Constraint::Length(top_h), Constraint::Length(mid_h), Constraint::Min(3)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    f.render_widget(Paragraph::new(status).wrap(Wrap { trim: false }).block(block("Status")), left);
    f.render_widget(Paragraph::new(health).wrap(Wrap { trim: false }).block(block("Health")), right);

    let [src_area, spark] = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(mid);
    let rows: Vec<Vec<Cell>> = sources
        .iter()
        .map(|(src, recs, last)| {
            let evs: u64 = st.events.iter().filter(|(sig, _)| sig.source() == *src).map(|(_, n)| n).sum();
            let top = st
                .events
                .iter()
                .filter(|(sig, _)| sig.source() == *src && !sig.is_success())
                .max_by_key(|(_, n)| **n)
                .map(|(sig, n)| format!("{} ({})", sig.name(), grouped(*n)))
                .unwrap_or_default();
            vec![
                Cell::from(src.name()),
                Cell::from(grouped(*recs)),
                Cell::from(grouped(evs)),
                Cell::from(last.map(|t| ago(s.generated, t)).unwrap_or_default()),
                Cell::from(top),
            ]
        })
        .collect();
    if rows.is_empty() {
        f.render_widget(Paragraph::new(Line::styled("No log lines read yet.", dim())).block(block("Sources")), src_area);
    } else {
        let last_w = if s.last_lines.is_empty() { 0 } else { 10 };
        let cols = [("source", 9, 0), ("records", 8, 0), ("events", 8, 2), ("last line", last_w, 1), ("most frequent", 13, 3)];
        f.render_widget(fitted_table(src_area, &cols, rows).block(block("Sources")), src_area);
    }

    let width = spark.width.saturating_sub(2) as usize;
    let hist: Vec<u64> = st.history.iter().map(|b| u64::from(b.events.iter().sum::<u32>())).collect();
    let data: Vec<u64> = hist[hist.len().saturating_sub(width)..].to_vec();
    let peak = data.iter().max().copied().unwrap_or(0);
    let b = block(format!("Events per minute, peak {peak}")).title_bottom(Line::from(format!(" last {} min ", data.len())).right_aligned());
    f.render_widget(Sparkline::default().data(&data).style(Style::new().fg(Color::Cyan)).block(b), spark);

    draw_latest(f, bottom, s);
}

fn status_lines(s: &Snapshot) -> Vec<Line<'static>> {
    let st = &s.stats;
    let label = |l: &str| Span::styled(format!("{l:<9}"), dim());
    let mode = match s.mode {
        Mode::Enforce => vec![label("Mode"), Span::styled("enforce", Style::new().fg(Color::Green).bold())],
        Mode::Shadow => vec![label("Mode"), Span::styled("shadow", Style::new().fg(Color::Yellow).bold()), " - logged, not applied".into()],
    };
    let cover = crate::engine::subnet_coverage(&s.bans);
    let subnets = match (cover.subnets, cover.widest_v4) {
        (0, _) => String::new(),
        (n, Some(w)) => {
            format!(" ({}: {}, widest /{w})", count(n as u64, "subnet", "subnets"), count(cover.v4_addresses, "address", "addresses"))
        }
        (n, None) => format!(" ({})", count(n as u64, "subnet", "subnets")),
    };
    let pending = if s.tracked_connections > 0 { format!(", {} XMPP logins pending", s.tracked_connections) } else { String::new() };
    let mut lines = vec![
        Line::from(mode),
        Line::from(vec![
            label("Bans"),
            Span::styled(grouped(s.bans.len() as u64), Style::new().fg(Color::Red).bold()),
            format!(" active{subnets}").into(),
        ]),
        Line::from(vec![label("In all"), format!("{}, {}", count(st.bans, "ban", "bans"), count(st.alerts, "alert", "alerts")).into()]),
        match serious_alerts(s) {
            0 => Line::from(vec![label("Alerts"), Span::styled("none high or critical in 24 h", dim())]),
            n => Line::from(vec![
                label("Alerts"),
                Span::styled(format!("{n} high or critical in 24 h"), Style::new().fg(Color::Red).bold()),
                " (tab 9)".into(),
            ]),
        },
        Line::from(vec![label("Tracked"), format!("{}{pending}", count(s.tracked_ips as u64, "address", "addresses")).into()]),
        Line::from(vec![label("Trusted"), format!("{} logged in lately", count(s.trusted.len() as u64, "address", "addresses")).into()]),
    ];
    // a replayed snapshot has no start
    if s.started > 0 {
        lines.push(Line::from(vec![label("Uptime"), fmt_duration(s.generated - s.started).into()]));
    }
    if st.unattributed > 0 {
        lines.push(Line::from(vec![label("Lines"), format!("{} not tied to an address", grouped(st.unattributed)).into()]));
    }
    lines
}

/// One line per check the daemon runs, coloured by how it went.
fn health_lines(s: &Snapshot, cert_warn_days: i64) -> Vec<Line<'static>> {
    let now = s.generated;
    let (ok, warn, bad) = (Style::new().fg(Color::Green), Style::new().fg(Color::Yellow), Style::new().fg(Color::Red));
    let mut v = Vec::new();
    let mut add = |label: &str, style: Style, text: String| {
        v.push(Line::from(vec![Span::styled(format!("{label:<10}"), dim()), Span::styled(text, style)]));
    };
    if let Some(r) = &s.exposure {
        use crate::exposure::Firewall;
        match r.firewall() {
            Firewall::Absent if !r.firewall_checked() => add("Firewall", warn, r.firewall_summary()),
            Firewall::Absent => add("Firewall", bad.bold(), format!("{}: every public listener is reachable", r.firewall_summary())),
            Firewall::Nftables => add("Firewall", Style::new(), r.firewall_summary()),
            Firewall::Ufw | Firewall::Iptables => add("Firewall", ok, r.firewall_summary()),
        }
    }
    if let Some(c) = &s.cluster {
        let good = c.peers.iter().filter(|p| p.last_error.is_none() && p.last_ok.is_some()).count();
        let failing: Vec<&str> = c.peers.iter().filter(|p| p.last_error.is_some()).map(|p| p.addr.as_str()).collect();
        let style = if !failing.is_empty() {
            warn
        } else if good == c.peers.len() {
            ok
        } else {
            Style::new()
        };
        let failing = if failing.is_empty() { String::new() } else { format!(", failing: {}", failing.join(", ")) };
        add("Cluster", style, format!("{}: {good}/{} peers ok, heard from {}{failing}", c.node_id, c.peers.len(), c.heard_from.len()));
    }
    if let Some(fd) = &s.feeds {
        match (&fd.error, fd.refreshed) {
            (Some(e), _) => add("Feeds", bad, format!("error: {e}")),
            (None, 0) => add("Feeds", Style::new(), "not loaded yet".into()),
            (None, t) => {
                let applied = if fd.applied { "" } else { ", not applied" };
                add("Feeds", ok, format!("{} networks, refreshed {}{applied}", grouped((fd.v4 + fd.v6) as u64), ago(now, t)));
            }
        }
    }
    if !s.certs.is_empty() {
        let mut concerns: Vec<(Severity, String)> = s
            .certs
            .iter()
            .filter_map(|c| c.concern(now, cert_warn_days).map(|(sev, what)| (sev, format!("{} {what}", c.target))))
            .collect();
        concerns.sort_by_key(|c| std::cmp::Reverse(c.0));
        match concerns.first() {
            Some((sev, what)) => {
                let more = if concerns.len() > 1 { format!(" (+{} more)", concerns.len() - 1) } else { String::new() };
                add("Certs", severity_style(*sev), format!("{what}{more}"));
            }
            None => {
                let next = s.certs.iter().filter_map(|c| c.days_left(now)).min();
                let next = next.map(|d| format!(", the first expires in {}", count(d.max(0) as u64, "day", "days"))).unwrap_or_default();
                add("Certs", ok, format!("{} fine{next}", count(s.certs.len() as u64, "certificate", "certificates")));
            }
        }
    }
    let low = |free: f64| {
        if free < 10.0 {
            bad
        } else if free < 20.0 {
            warn
        } else {
            Style::new()
        }
    };
    if let Some(r) = &s.resources {
        if let Some(d) = r.disks.iter().min_by(|a, b| a.free_percent().total_cmp(&b.free_percent())) {
            let others = if r.disks.len() > 1 { format!(" (the fullest of {})", r.disks.len()) } else { String::new() };
            add("Disk", low(d.free_percent()), format!("{} {:.0}% free{others}", d.mount, d.free_percent()));
        }
        if let Some(m) = &r.memory {
            add("Memory", low(m.avail_percent()), format!("{:.0}% available", m.avail_percent()));
        }
        if let Some(e) = r.errors.first() {
            add("Resources", warn, e.clone());
        }
    }
    if let Some(av) = &s.av {
        match &av.last {
            Some(scan) => {
                let found = scan.infections();
                let what = if found > 0 { format!("{found} infected") } else { "clean".to_string() };
                let old = if scan.db_outdated { ", signatures outdated" } else { "" };
                let style = if found > 0 {
                    bad
                } else if scan.db_outdated {
                    warn
                } else {
                    ok
                };
                add("Antivirus", style, format!("{what}, last scan {}{old}", ago(now, scan.end)));
            }
            None => add("Antivirus", warn, "no finished scan seen yet".into()),
        }
    }
    if let Some(p) = &s.patches {
        let style = if p.security_count > 0 || p.kernel_pending().is_some() {
            warn
        } else if p.concerns().is_empty() {
            ok
        } else {
            Style::new()
        };
        add("Patches", style, p.summary());
    }
    if let Some(v) = &s.verify {
        let style = if v.mismatched > 0 { warn } else { ok };
        add("Packages", style, format!("{} differ from dpkg, {} set-uid; checked {}", v.mismatched, v.suid, ago(now, v.last_run)));
    }
    if let Some(p) = &s.procwatch {
        let text = if p.learning_until > now {
            format!("learning outbound connections until {}", &fmt_ts(p.learning_until)[..16])
        } else {
            format!("{} outbound (program, port) pairs known", p.pairs)
        };
        add("Processes", Style::new(), text);
    }
    if let Some(c) = &s.cron {
        match c.errors.first() {
            Some(e) => add("Cron", warn, format!("cannot read {e}")),
            None if c.learning_until > now => add("Cron", Style::new(), format!("learning until {}", &fmt_ts(c.learning_until)[..16])),
            None => add(
                "Cron",
                ok,
                format!(
                    "watching {}, {}",
                    count(c.lines as u64, "crontab line", "crontab lines"),
                    count(c.tasks as u64, "task file", "task files")
                ),
            ),
        }
    }
    v
}

fn draw_latest(f: &mut Frame, area: Rect, s: &Snapshot) {
    let rows: Vec<Row> = s
        .recent
        .iter()
        .filter(|a| a.kind != ActionKind::Unban)
        .take(area.height as usize)
        .map(|a| Row::new(vec![Cell::from(fmt_ts(a.ts)[5..].to_string()), action_cell(a), Cell::from(a.message.clone())]))
        .collect();
    if rows.is_empty() {
        f.render_widget(Paragraph::new(Line::styled("No decisions yet.", dim())).block(block("Latest decisions")), area);
        return;
    }
    let t = Table::new(rows, [Constraint::Length(14), Constraint::Length(7), Constraint::Min(20)]).block(block("Latest decisions"));
    f.render_widget(t, area);
}

/// Overview of a decision log: what it covers, how many bans of which kind, bans per hour.
fn draw_log_overview(f: &mut Frame, area: Rect, s: &Snapshot, log: &crate::actions_view::LogSummary) {
    let label = |l: &str| Span::styled(format!("{l:<10}"), dim());
    let peers: u32 = log.bans_peer.values().sum();
    let names: Vec<&str> = log.file.split(", ").map(|p| p.rsplit('/').next().unwrap_or(p)).collect();
    let mut lines = vec![
        Line::from(vec![label(if log.files > 1 { "Files" } else { "File" }), names.join(", ").into()]),
        Line::from(vec![
            label("Period"),
            format!("{} - {} ({})", &fmt_ts(log.from)[..16], &fmt_ts(log.to)[..16], fmt_duration(log.to - log.from)).into(),
        ]),
        Line::from(vec![
            label("Decisions"),
            format!(
                "{}: {}, {}, {}",
                grouped(log.decisions),
                count(s.stats.bans, "ban", "bans"),
                count(u64::from(log.unbans), "unban", "unbans"),
                count(u64::from(log.alerts), "alert", "alerts")
            )
            .into(),
        ]),
        Line::from(vec![
            label("At end"),
            Span::styled(grouped(s.bans.len() as u64), Style::new().fg(Color::Red).bold()),
            format!(" active, {} banned in the period", count(s.tracked_ips as u64, "source", "sources")).into(),
        ]),
        Line::from(vec![
            label("Places"),
            if log.geo_db { "from the geo database" } else { "from the ban messages (no geo database)" }.into(),
        ]),
    ];
    if log.duplicates > 0 {
        lines.push(Line::from(vec![
            label("Merged"),
            format!("{} counted once (peer copies, repeated lines)", count(log.duplicates, "duplicate", "duplicates")).into(),
        ]));
    }
    if log.unreadable > 0 {
        lines.push(Line::from(vec![
            label("Skipped"),
            Span::styled(
                format!("{} that aren't decisions of this version", count(log.unreadable, "line", "lines")),
                Style::new().fg(Color::Yellow),
            ),
        ]));
    }
    // long lines wrap in a narrow terminal: room for all of them
    let top_h = wrapped_height(&lines, (area.width / 2).saturating_sub(2)).saturating_add(2).max(9);
    let [top, spark, bottom] = Layout::vertical([Constraint::Length(top_h), Constraint::Length(8), Constraint::Min(4)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block("Decision log")), left);

    let here = if log.files > 1 { "decided by these servers" } else { "decided here" };
    let mut rows: Vec<Row> = vec![Row::new(vec![here.to_string(), grouped(u64::from(log.bans_local))]).bold()];
    let mut cats: Vec<(&String, &u32)> = log.categories.iter().collect();
    cats.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    rows.extend(cats.iter().map(|(c, n)| Row::new(vec![format!("  {c}"), grouped(u64::from(**n))])));
    rows.extend(log.bans_peer.iter().map(|(p, n)| Row::new(vec![format!("from peer {p}"), grouped(u64::from(*n))])));
    if log.reinstated > 0 {
        rows.push(Row::new(vec!["reinstated".to_string(), grouped(u64::from(log.reinstated))]));
    }
    let t = Table::new(rows, [Constraint::Min(20), Constraint::Length(8)])
        .header(Row::new(["bans", "count"]).bold())
        .block(block(format!("Bans: {} here, {peers} from peers", grouped(u64::from(log.bans_local)))));
    f.render_widget(t, right);

    let width = spark.width.saturating_sub(2) as usize;
    let data: Vec<u64> = log.bans_per_hour[log.bans_per_hour.len().saturating_sub(width)..].to_vec();
    let peak = data.iter().max().copied().unwrap_or(0);
    let b = block(format!("Bans per hour, peak {peak}")).title_bottom(Line::from(format!(" last {} h ", data.len())).right_aligned());
    f.render_widget(Sparkline::default().data(&data).style(Style::new().fg(Color::Cyan)).block(b), spark);

    draw_latest(f, bottom, s);
}

/// Bans per day (as many recent days as fit) and a table of weeks, newest first, with
/// the change from the week before and the top countries and networks.
fn draw_trends(f: &mut Frame, area: Rect, app: &mut App, log: &crate::actions_view::LogSummary) {
    use ratatui::widgets::{Bar, BarChart, BarGroup};
    let [chart_area, table_area] = Layout::vertical([Constraint::Length(12), Constraint::Min(4)]).areas(area);
    let date = |day: i64| {
        let (y, m, d) = crate::time::civil_from_days(day);
        format!("{y:04}-{m:02}-{d:02}")
    };
    let inner = usize::from(chart_area.width.saturating_sub(2));
    let (bar_width, gap) = if inner / 4 >= log.bans_per_day.len() { (3u16, 1u16) } else { (2, 1) };
    let fit = inner / usize::from(bar_width + gap);
    let days = &log.bans_per_day[log.bans_per_day.len().saturating_sub(fit)..];
    let bars: Vec<Bar> = days
        .iter()
        .map(|d| {
            let n = u64::from(d.local + d.peer);
            let (_, _, dom) = crate::time::civil_from_days(d.day);
            Bar::default().value(n).label(Line::from(format!("{dom:02}"))).text_value(if bar_width >= 3 {
                n.to_string()
            } else {
                String::new()
            })
        })
        .collect();
    let peak = days.iter().map(|d| d.local + d.peer).max().unwrap_or(0);
    let total: u32 = days.iter().map(|d| d.local + d.peer).sum();
    let title = match (days.first(), days.last()) {
        (Some(a), Some(b)) => format!(
            "Bans per day, {} - {} ({}, peak {peak}, average {:.0})",
            date(a.day),
            date(b.day),
            count(days.len() as u64, "day", "days"),
            f64::from(total) / days.len() as f64
        ),
        _ => "Bans per day".into(),
    };
    let chart = BarChart::default()
        .bar_width(bar_width)
        .bar_gap(gap)
        .bar_style(Style::new().fg(Color::Red))
        .data(BarGroup::default().bars(&bars))
        .block(block(title));
    f.render_widget(chart, chart_area);

    let list = |v: &[(String, u32)]| v.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ");
    let rows: Vec<Row> = log
        .weeks
        .iter()
        .enumerate()
        .rev()
        .map(|(i, w)| {
            let change = match i.checked_sub(1).map(|p| &log.weeks[p]) {
                Some(prev) if prev.bans > 0 => {
                    let pct = (f64::from(w.bans) - f64::from(prev.bans)) * 100.0 / f64::from(prev.bans);
                    let style = Style::new().fg(if pct > 0.0 { Color::Red } else { Color::Green });
                    Cell::from(format!("{pct:+.0}%")).style(style)
                }
                _ => Cell::from(""),
            };
            Row::new(vec![
                Cell::from(date(w.start_day)),
                Cell::from(w.bans.to_string()),
                change,
                Cell::from(w.sources.to_string()),
                Cell::from(list(&w.countries)),
                Cell::from(list(&w.networks)),
            ])
        })
        .collect();
    let n = rows.len();
    let sel = app.table.selected().unwrap_or(0).min(n.saturating_sub(1));
    app.table.select(Some(sel));
    app.page = usize::from(table_area.height.saturating_sub(3)).max(1);
    let t = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Percentage(35),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(["week of", "bans", "change", "sources", "top countries", "top networks"]).bold())
    .row_highlight_style(Style::new().reversed())
    .block(list_block("Weeks, newest first (the first and last may be partial)".into(), Some(sel), n));
    f.render_stateful_widget(t, table_area, &mut app.table);
    scrollbar(f, table_area, n, sel);
}

// --- the list tabs

fn draw_offenders(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot, rows: &[&IpView]) {
    let title = list_title(app, "Offenders", rows.len(), s.offenders.len());
    if rows.is_empty() {
        return empty_list(f, area, app, title, "No address has a score right now.");
    }
    let now = s.generated;
    let (mut w_addr, mut w_status, mut w_where) = (7, 6, 5);
    // The address column is as wide as the addresses on screen: one long IPv6 address
    // somewhere in hundreds of rows mustn't push the other columns out.
    // (where the table will scroll to, as ratatui does: just enough to show the selection)
    let page = usize::from(area.height.saturating_sub(3)).max(1);
    let sel = app.table.selected().unwrap_or(0).min(rows.len() - 1);
    let first = match app.table.offset() {
        o if sel < o => sel,
        o if sel >= o + page => sel + 1 - page,
        o => o,
    };
    let on_screen = first..first + page;
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let ip = v.ip.to_string();
            let (status, style) = offender_status(v, now);
            let place = v.geo.as_deref().map(short_place).unwrap_or_default();
            if on_screen.contains(&i) {
                w_addr = w_addr.max(ip.len());
            }
            w_status = w_status.max(status.chars().count());
            w_where = w_where.max(place.chars().count());
            vec![
                Cell::from(ip),
                Cell::from(format!("{:>5.0}%", v.danger)).style(danger_style(v.danger)),
                Cell::from(format!("{:>5.0}", v.fast)),
                Cell::from(format!("{:>5.0}", v.slow)),
                Cell::from(ago(now, v.last_seen)),
                Cell::from(status).style(style),
                Cell::from(place),
                Cell::from(top_signals(&v.counts, 3)),
            ]
        })
        .collect();
    let geo = rows.iter().any(|v| v.geo.is_some());
    let cols = [
        ("address", w_addr as u16, 0),
        ("danger", 6, 0),
        ("fast", 5, 5),
        ("slow", 5, 5),
        ("last seen", 10, 2),
        ("status", w_status.min(32) as u16, 0),
        ("where", if geo { w_where.min(28) as u16 } else { 0 }, 4),
        ("signals", 12, 3),
    ];
    let sel = app.table.selected();
    let t = fitted_table_spaced(area, &cols, cells, 2).block(list_block(title, sel, rows.len()));
    f.render_stateful_widget(t, area, &mut app.table);
    scrollbar(f, area, rows.len(), sel.unwrap_or(0));
    app.page = page;
}

fn offender_detail(v: &IpView, s: &Snapshot) -> Vec<Line<'static>> {
    let now = s.generated;
    let mut lines = vec![Line::from(vec![
        Span::styled(v.ip.to_string(), Style::new().bold()),
        Span::styled(format!("   danger {:.0}%", v.danger), danger_style(v.danger)),
        format!("  peak {:.0}  fast {:.0}  slow {:.0}", v.peak, v.fast, v.slow).into(),
    ])];
    if let Some(g) = &v.geo {
        lines.push(Line::from(g.clone()));
    }
    match (&v.banned_by, v.banned_until, &v.protected) {
        (Some(n), Some(u), _) => {
            let what = if n.is_host() { String::new() } else { format!(" as part of {n}") };
            lines.push(Line::styled(
                format!("banned{what} until {} ({} left)", fmt_ts(u), fmt_duration(u - now)),
                Style::new().fg(Color::Red),
            ));
        }
        (None, _, Some(p)) => lines.push(Line::styled(format!("protected: {p}"), Style::new().fg(Color::Green))),
        _ => {}
    }
    lines.push(Line::from(format!("first seen {}   last seen {} ({})", fmt_ts(v.first_seen), fmt_ts(v.last_seen), ago(now, v.last_seen))));
    lines.push(Line::from(format!("signals: {}", top_signals(&v.counts, 10))));
    lines.extend(evidence_lines(v, s));
    lines
}

fn draw_bans(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot, rows: &[&Ban]) {
    let extra = if s.allowed.is_empty() { 0 } else { s.allowed.len().min(8) as u16 + 2 };
    let [area, allow_area] = Layout::vertical([Constraint::Min(5), Constraint::Length(extra)]).areas(area);
    if extra > 0 {
        let lines: Vec<Line> = s
            .allowed
            .iter()
            .map(|a| Line::from(format!("{:<22} {:>9} left  {}", a.net.to_string(), fmt_duration(a.until - s.generated), a.note)))
            .collect();
        f.render_widget(
            Paragraph::new(lines)
                .style(Style::new().fg(Color::Green))
                .block(block("Operator allowlist (logguard disallow <net> to remove)")),
            allow_area,
        );
    }
    let name = if s.actions_log.is_some() { "Active bans at the end of the log" } else { "Active bans" };
    let title = list_title(app, name, rows.len(), s.bans.len());
    if rows.is_empty() {
        return empty_list(f, area, app, title, "No active bans.");
    }
    let now = s.generated;
    let mut w_target = 6;
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .map(|b| {
            let target = b.net.to_string();
            w_target = w_target.max(target.len());
            vec![
                Cell::from(target).style(if b.net.is_host() { Style::new() } else { Style::new().fg(Color::Magenta) }),
                Cell::from(if b.offence > 0 { format!("#{}", b.offence) } else { String::new() }),
                Cell::from(ago(now, b.since)),
                Cell::from(fmt_duration(b.until - now)),
                Cell::from(ban_reason(b)),
            ]
        })
        .collect();
    let cols = [("target", w_target as u16, 0), ("#", 3, 3), ("banned", 10, 2), ("left", 6, 0), ("reason", 12, 0)];
    let sel = app.table.selected();
    let t = fitted_table(area, &cols, cells).block(list_block(title, sel, rows.len()));
    f.render_stateful_widget(t, area, &mut app.table);
    scrollbar(f, area, rows.len(), sel.unwrap_or(0));
    app.page = usize::from(area.height.saturating_sub(3)).max(1);
}

fn ban_detail(b: &Ban, s: &Snapshot) -> Vec<Line<'static>> {
    let now = s.generated;
    let by = match &b.origin {
        Some(o) => format!("from peer {o}"),
        None => format!("decided here, offence #{}", b.offence),
    };
    let mut lines = vec![
        Line::from(vec![Span::styled(b.net.to_string(), Style::new().bold()), format!("   {by}").into()]),
        Line::from(format!(
            "banned {} ({}), until {} ({} left)",
            fmt_ts(b.since),
            ago(now, b.since),
            fmt_ts(b.until),
            fmt_duration(b.until - now)
        )),
        Line::from(format!("reason: {}", ban_reason(b))),
    ];
    if !b.inner.is_empty() {
        let inner: Vec<String> = b.inner.iter().map(|i| i.net.to_string()).collect();
        lines.push(Line::from(format!("set aside while it lasts, then back: {}", inner.join(", "))));
    }
    let members: Vec<&IpView> = s.offenders.iter().filter(|v| b.net.contains(v.ip)).collect();
    match members.as_slice() {
        [] => {}
        [v] if b.net.is_host() => {
            if let Some(g) = &v.geo {
                lines.push(Line::from(g.clone()));
            }
            lines.push(Line::from(format!("signals: {}", top_signals(&v.counts, 10))));
            lines.extend(evidence_lines(v, s));
        }
        _ => {
            lines.push(Line::from(format!("tracked addresses in it ({}):", members.len()).bold()));
            lines.extend(members.iter().take(12).map(|v| {
                let place = v.geo.as_deref().map(short_place).unwrap_or_default();
                Line::from(format!("  {:<16} danger {:>4.0}%  last seen {:<11} {place}", v.ip.to_string(), v.danger, ago(now, v.last_seen)))
            }));
        }
    }
    lines
}

fn draw_events(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot, rows: &[&Action]) {
    let severity =
        if app.min_severity > Severity::Info { format!(" · severity ≥ {}", severity_name(app.min_severity)) } else { String::new() };
    let title = list_title(app, "Decisions", rows.len(), s.recent.len()) + &severity;
    if rows.is_empty() {
        let none = format!("No decisions at severity {} or higher; s changes it.", severity_name(app.min_severity));
        return empty_list(f, area, app, title, if s.recent.is_empty() { "No decisions yet." } else { &none });
    }
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .map(|a| {
            vec![
                Cell::from(fmt_ts(a.ts)[5..].to_string()),
                action_cell(a),
                Cell::from(severity_name(a.severity)).style(severity_style(a.severity)),
                Cell::from(a.message.clone()),
            ]
        })
        .collect();
    let legend = if s.mode == Mode::Shadow { " ~ shadow, not applied " } else { " ~ not applied: failed, since expired, or shadow " };
    let cols = [("time", 14, 0), ("action", 7, 0), ("severity", 8, 3), ("message", 12, 0)];
    let sel = app.table.selected();
    let t = fitted_table(area, &cols, cells).block(list_block(title, sel, rows.len()).title_bottom(Line::styled(legend, dim())));
    f.render_stateful_widget(t, area, &mut app.table);
    scrollbar(f, area, rows.len(), sel.unwrap_or(0));
    app.page = usize::from(area.height.saturating_sub(3)).max(1);
}

fn event_detail(a: &Action, s: &Snapshot) -> Vec<Line<'static>> {
    let now = s.generated;
    let style = severity_style(a.severity);
    let applied = match (a.kind, a.applied) {
        (ActionKind::Alert, _) => "",
        (_, true) => "  applied",
        _ if s.mode == Mode::Shadow => "  not applied (shadow mode)",
        _ => "  not applied: failed, since expired, or decided in shadow mode",
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(fmt_ts(a.ts), Style::new().bold()),
        "  ".into(),
        Span::styled(kind_name(a.kind).to_uppercase(), style),
        "  ".into(),
        Span::styled(severity_name(a.severity), style),
        Span::styled(applied, dim()),
    ])];
    let mut facts = Vec::new();
    if let Some(t) = a.target {
        let banned = if s.bans.iter().any(|b| b.net == t) { " (banned now)" } else { "" };
        facts.push(format!("target {t}{banned}"));
    }
    if let Some(t) = a.topic {
        facts.push(format!("topic: {}", topic_name(t)));
    }
    if let Some(u) = a.until {
        let left = if u > now { format!("{} left", fmt_duration(u - now)) } else { "over".into() };
        facts.push(format!("until {} ({left})", fmt_ts(u)));
    }
    if let Some(c) = &a.category {
        facts.push(format!("cause {c}"));
    }
    if !facts.is_empty() {
        lines.push(Line::from(facts.join("   ")));
    }
    if !a.accounts.is_empty() {
        lines.push(Line::from(format!("accounts: {}", a.accounts.join(", "))));
    }
    lines.push(Line::from(a.message.clone()));
    if let Some(n) = &a.user_note {
        lines.push(Line::styled(format!("note for the user: {n}"), dim()));
    }
    if !a.evidence.is_empty() {
        lines.push(Line::from("evidence:".bold()));
        lines.extend(a.evidence.iter().map(|e| Line::from(format!("  {e}"))));
    }
    lines
}

/// The latest alerts, newest first, with the topic and the accounts they concern.
fn draw_alerts(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot, rows: &[&Action]) {
    let mut title = list_title(app, "Alerts", rows.len(), s.alerts.len());
    if app.min_severity > Severity::Info {
        title += &format!(" · severity ≥ {}", severity_name(app.min_severity));
    }
    if let Some(t) = app.topic {
        title += &format!(" · {}", topic_name(t));
    }
    if rows.is_empty() {
        let none = if s.alerts.is_empty() { "No alerts yet." } else { "No alerts of this severity and topic; s and t change them." };
        return empty_list(f, area, app, title, none);
    }
    let (mut w_topic, mut w_accounts) = (5, 0);
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .map(|a| {
            let style = severity_style(a.severity);
            let topic = a.topic.map_or("", topic_name);
            let accounts = a.accounts.join(", ");
            w_topic = w_topic.max(topic.chars().count());
            w_accounts = w_accounts.max(accounts.chars().count());
            vec![
                Cell::from(fmt_ts(a.ts)[5..].to_string()),
                Cell::from(severity_name(a.severity)).style(style),
                Cell::from(topic).style(style),
                Cell::from(accounts),
                Cell::from(a.message.clone()),
            ]
        })
        .collect();
    let serious = match serious_alerts(s) {
        0 => Line::styled(" none high or critical in the last 24 h ", dim()),
        n => Line::styled(format!(" {n} high or critical in the last 24 h "), Style::new().fg(Color::Red).bold()),
    };
    let cols = [
        ("time", 14, 0),
        ("severity", 8, 2),
        ("topic", w_topic.min(24) as u16, 3),
        ("accounts", if w_accounts > 0 { w_accounts.clamp(8, 28) as u16 } else { 0 }, 4),
        ("message", 12, 0),
    ];
    let sel = app.table.selected();
    let t = fitted_table(area, &cols, cells).block(list_block(title, sel, rows.len()).title_bottom(serious));
    f.render_stateful_widget(t, area, &mut app.table);
    scrollbar(f, area, rows.len(), sel.unwrap_or(0));
    app.page = usize::from(area.height.saturating_sub(3)).max(1);
}

fn draw_accounts(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let rows = account_rows(app, s);
    let sel = app.follow(&rows, |a| a.account.clone());
    let title = list_title(app, "Accounts with recent authentication failures", rows.len(), s.accounts.len());
    if rows.is_empty() {
        return empty_list(f, area, app, title, "No account has had authentication failures lately.");
    }
    let w = rows.iter().map(|a| a.account.chars().count()).max().unwrap_or(0).max(7) as u16;
    let cells: Vec<Vec<Cell>> = rows
        .iter()
        .map(|a| {
            let style = if a.under_attack { Style::new().fg(Color::Red).bold() } else { Style::new() };
            vec![
                Cell::from(a.account.clone()).style(style),
                Cell::from(format!("{:>8.1}", a.failures)),
                Cell::from(format!("{:>9}", a.ips)),
                Cell::from(if a.under_attack { "UNDER ATTACK" } else { "" }).style(style),
            ]
        })
        .collect();
    let cols = [("account", w.min(60), 0), ("failures", 8, 0), ("addresses", 9, 2), ("", 12, 0)];
    let t = fitted_table(area, &cols, cells).block(list_block(title, sel, rows.len()));
    f.render_stateful_widget(t, area, &mut app.table);
    scrollbar(f, area, rows.len(), sel.unwrap_or(0));
    app.page = usize::from(area.height.saturating_sub(3)).max(1);
}

/// The `[[patterns]]` entries with their counts, and for the selected one its busiest
/// addresses and the latest lines it matched without finding an address.
fn draw_patterns(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let now = s.generated;
    let pats = &s.patterns;
    let sel = app.follow(pats, |p| p.stats.name.clone()).unwrap_or(0);
    let yellow = Style::new().fg(Color::Yellow);
    let list_h = (pats.len() as u16 + 3).clamp(4, (area.height / 2).max(4));
    let [list, rest] = Layout::vertical([Constraint::Length(list_h), Constraint::Min(0)]).areas(area);
    let rows: Vec<Vec<Cell>> = pats
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let st = &p.stats;
            let kind = match p.kind {
                crate::parse::custom::PatternKind::Failure => "failure",
                crate::parse::custom::PatternKind::Probe => "probe",
                crate::parse::custom::PatternKind::Success => "success",
            };
            let port = p.port.map(|n| n.to_string()).unwrap_or_default();
            let last = st.last.map_or_else(|| "never".to_string(), |t| ago(now, t));
            let no_addr = Cell::from(grouped(st.no_address)).style(if st.no_address > 0 { yellow } else { Style::new() });
            // grey on the selected row's reversed colours is hard to read
            let from_style = if i == sel { Style::new() } else { dim() };
            vec![
                Cell::from(st.name.clone()).bold(),
                Cell::from(kind),
                Cell::from(grouped(st.lines)).style(if st.lines == 0 { yellow } else { Style::new() }),
                Cell::from(grouped(st.matches)),
                Cell::from(last),
                Cell::from(grouped(p.addresses as u64)),
                no_addr,
                Cell::from(port),
                Cell::from(p.from.clone()).style(from_style),
            ]
        })
        .collect();
    let cols = [
        ("pattern", pats.iter().map(|p| p.stats.name.len() as u16).max().unwrap_or(7).max(7), 0),
        ("kind", 7, 4),
        ("lines read", 10, 2),
        ("matches", 9, 0),
        ("last match", 14, 1),
        ("addresses", 9, 2),
        ("no address", 10, 0),
        ("port", 5, 5),
        ("lines from", 20, 3),
    ];
    app.page = usize::from(list.height.saturating_sub(3)).max(1);
    let t = fitted_table_spaced(list, &cols, rows, 2).block(list_block(format!("Patterns ({})", pats.len()), Some(sel), pats.len()));
    f.render_stateful_widget(t, list, &mut app.table);
    let Some(p) = pats.get(sel) else { return };
    let st = &p.stats;

    let [left, right] = if rest.width >= 110 {
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(rest)
    } else {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(rest)
    };
    // the busiest addresses, with what logguard does about them now
    let status = |ip: std::net::IpAddr| -> (String, Style) {
        if let Some(v) = s.offenders.iter().find(|v| v.ip == ip) {
            let (text, style) = offender_status(v, now);
            return if text.is_empty() { (format!("danger {:.0}%", v.danger), Style::new()) } else { (text, style) };
        }
        match s.bans.iter().find(|b| b.net.contains(ip)) {
            Some(b) => (format!("banned {}", fmt_duration(b.until - now)), Style::new().fg(Color::Red)),
            None => (String::new(), Style::new()),
        }
    };
    let ip_rows: Vec<Vec<Cell>> = st
        .ips
        .iter()
        .map(|h| {
            let (text, style) = status(h.ip);
            vec![Cell::from(h.ip.to_string()), Cell::from(grouped(h.lines)), Cell::from(ago(now, h.last)), Cell::from(text).style(style)]
        })
        .collect();
    let ip_w = st.ips.iter().map(|h| h.ip.to_string().len() as u16).max().unwrap_or(15).max(7);
    let shown = if p.addresses > st.ips.len() { format!("busiest {} of {}", st.ips.len(), p.addresses) } else { p.addresses.to_string() };
    let since = if st.since > 0 { format!(" counted since {} ", fmt_ts(st.since)) } else { " no line read yet ".to_string() };
    let b = block(format!("Addresses {} found ({shown})", st.name)).title_bottom(Line::styled(since, dim()).right_aligned());
    if ip_rows.is_empty() {
        let (text, style) = if st.lines == 0 {
            let check = if p.from.starts_with("file ") {
                "does the file exist, and is it the one the service writes"
            } else {
                "is the service installed, and is the unit name right (systemctl list-units)"
            };
            (format!("No line from {} since logguard started counting: {check}?", p.from), yellow)
        } else if st.matches == 0 {
            let latest = st.last_line.map_or_else(String::new, |t| format!(" (the latest {})", ago(now, t)));
            let read = count(st.lines, "line", "lines");
            (
                format!(
                    "{read} read from {}{latest}, none matched. `logguard test-pattern -v` shows what the pattern finds in a log file.",
                    p.from
                ),
                dim(),
            )
        } else {
            ("No address in the last 30 days.".to_string(), dim())
        };
        f.render_widget(Paragraph::new(Line::styled(text, style)).wrap(Wrap { trim: true }).block(b), left);
    } else {
        let cols = [("address", ip_w, 0), ("lines", 7, 0), ("last seen", 14, 1), ("status", 16, 2)];
        f.render_widget(fitted_table_spaced(left, &cols, ip_rows, 2).block(b), left);
    }

    // lines the regex matched with no address in group ip: the pattern needs a look
    let mut lines: Vec<Line> = Vec::new();
    if st.no_address == 0 {
        lines.push(Line::styled("None: every line the pattern matched named an address in group ip.", dim()));
    } else {
        lines.push(Line::styled(
            "The regex matched these, but group ip held no address: they score nothing. Check the pattern with logguard test-pattern -v.",
            yellow,
        ));
        for (t, text) in st.no_address_lines.iter().rev() {
            lines.push(Line::default());
            lines.push(Line::styled(ago(now, *t), dim()));
            lines.push(Line::from(text.clone()));
        }
    }
    let title = format!("Lines without an address ({})", grouped(st.no_address));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block(title)), right);
}

fn draw_exposure(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    use crate::exposure::{Exposure, Firewall};
    let Some(r) = &s.exposure else {
        f.render_widget(
            Paragraph::new("No exposure scan yet (enabled in [exposure], runs every minute on Linux).").block(block("Exposure")),
            area,
        );
        return;
    };
    let (fw, checked) = (r.firewall(), r.firewall_checked());
    let red = Style::new().fg(Color::Red).bold();
    let yellow = Style::new().fg(Color::Yellow);
    // what no firewall, or one whose rules aren't read, means for the list
    let warning = match fw {
        Firewall::Absent if !checked => Some((
            yellow,
            "FIREWALL NOT CHECKED",
            vec![
                "This report comes from a logguard that reads only ufw, which isn't active here: restart the daemon with this version to have iptables and nftables rules checked too.",
            ],
        )),
        Firewall::Absent => Some((
            red,
            "NO FIREWALL",
            vec![
                "Nothing filters incoming traffic: every listener on a public address below is reachable from the internet.",
                if r.ufw_active == Some(false) {
                    "ufw is installed but inactive: allow the ports you need (ufw allow 22/tcp), then ufw enable."
                } else {
                    "Install ufw, or load iptables or nftables rules, and allow only the ports you need."
                },
            ],
        )),
        Firewall::Nftables => Some((
            yellow,
            "nftables",
            vec!["nftables filters incoming traffic with rules of its own, which logguard doesn't read: listeners on public addresses are shown as reachable."],
        )),
        Firewall::Ufw | Firewall::Iptables => None,
    };
    let warning = warning.map(|(style, title, text)| (style, title, text.into_iter().map(Line::from).collect::<Vec<Line>>()));
    let warning_h = warning.as_ref().map_or(0, |(_, _, lines)| wrapped_height(lines, area.width.saturating_sub(2)).saturating_add(2));
    let dead = r.dead_rules.len() as u16;
    let [warning_area, table_area, dead_area] =
        Layout::vertical([Constraint::Length(warning_h), Constraint::Min(5), Constraint::Length(if dead > 0 { dead + 2 } else { 0 })])
            .areas(area);
    if let Some((style, title, lines)) = warning {
        let b =
            Block::bordered().border_type(BorderType::Rounded).border_style(style).title(Span::styled(format!(" {title} "), style.bold()));
        f.render_widget(Paragraph::new(lines).style(style).wrap(Wrap { trim: true }).block(b), warning_area);
    }
    if dead > 0 {
        let lines: Vec<Line> =
            r.dead_rules.iter().map(|d| Line::from(format!("ufw allows {d} from anywhere, but nothing listens there"))).collect();
        f.render_widget(Paragraph::new(lines).style(Style::new().fg(Color::Yellow)).block(block("Dead firewall rules")), dead_area);
    }
    let mut listeners = crate::exposure::for_display(&r.listeners);
    // exposed services, then logguard's honeypots, then blocked ones, then local ones
    let rank = |l: &crate::exposure::Listener| match (l.honeypot, l.exposure.is_exposed(), l.exposure) {
        (false, true, _) => 0,
        (true, ..) => 1,
        (_, _, Exposure::Local) => 3,
        _ => 2,
    };
    listeners.sort_by_key(|(_, l)| (rank(l), l.key));
    let total = listeners.len();
    let exposed = listeners.iter().filter(|(_, l)| l.exposure.is_exposed() && !l.honeypot).count();
    let honeypots = listeners.iter().filter(|(_, l)| l.honeypot).count();
    let needle = needle(app);
    listeners
        .retain(|(name, l)| needle.as_deref().is_none_or(|n| has(n, &[name, &l.process, &r.describe(l), l.rule.as_deref().unwrap_or("")])));
    let sel = app.follow(&listeners, |(name, _)| name.clone());
    let traps = if honeypots > 0 { format!(", {honeypots} honeypots") } else { String::new() };
    let title = format!(
        "{}: {exposed} exposed{traps} · {} · scanned {}",
        list_title(app, "Listeners", listeners.len(), total),
        r.firewall_summary(),
        fmt_ts(r.scanned)
    );
    if listeners.is_empty() {
        return empty_list(f, table_area, app, title, "No listening sockets found.");
    }
    let (mut w_name, mut w_proc, mut w_rule) = (8, 7, 0);
    let cells: Vec<Vec<Cell>> = listeners
        .iter()
        .map(|(name, l)| {
            let style = match (l.exposure, fw) {
                // a honeypot the firewall blocks catches nothing
                _ if l.honeypot && l.exposure == Exposure::Firewalled => Style::new().fg(Color::LightRed),
                _ if l.honeypot => Style::new().fg(Color::Magenta),
                (Exposure::Unfiltered, Firewall::Absent) if checked => red,
                // published, though no ufw rule says it is meant to be
                (Exposure::Docker, Firewall::Ufw) if l.rule.is_none() => Style::new().fg(Color::LightRed),
                (Exposure::Docker | Exposure::Unfiltered, _) => Style::new().fg(Color::Yellow),
                (Exposure::Allowed, _) if l.limited => Style::new().fg(Color::Cyan),
                (Exposure::Allowed, _) => Style::new().fg(Color::Green),
                // closed to the internet, open to some sources
                (Exposure::Firewalled, _) if l.rule.is_some() => Style::new(),
                _ => dim(),
            };
            let how = if l.dynamic { format!("{} (dynamic range)", r.describe(l)) } else { r.describe(l) };
            let rule = l.rule_text(fw).unwrap_or_default();
            w_name = w_name.max(name.chars().count());
            w_proc = w_proc.max(l.process.chars().count());
            w_rule = w_rule.max(rule.chars().count());
            vec![Cell::from(name.clone()), Cell::from(l.process.clone()), Cell::from(rule).style(style), Cell::from(how).style(style)]
        })
        .collect();
    let cols = [
        ("listener", w_name.min(46) as u16, 0),
        ("process", w_proc.min(18) as u16, 2),
        ("firewall rule", if w_rule > 0 { w_rule.clamp(13, 32) as u16 } else { 0 }, 3),
        ("reachable from the internet?", 14, 0),
    ];
    let t = fitted_table(table_area, &cols, cells).block(list_block(title, sel, listeners.len()));
    f.render_stateful_widget(t, table_area, &mut app.table);
    scrollbar(f, table_area, listeners.len(), sel.unwrap_or(0));
    app.page = usize::from(table_area.height.saturating_sub(3)).max(1);
}

const NO_GEO: &str = "No geo database loaded: set [geo] enabled = true to see countries and networks.";

/// Countries, most offenders first, under an "All countries" row; the port histogram and
/// the network list show whichever row is selected.
fn draw_countries(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let w = &s.world;
    let [top, bottom] = Layout::vertical([Constraint::Percentage(55), Constraint::Min(5)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    let num = |n: u64| Cell::from(if n == 0 { String::new() } else { grouped(n) });
    let place_row = |p: &PlaceStats, first: String| {
        let style = if p.bans > 0 { Style::new().fg(Color::LightRed) } else { Style::new() };
        Row::new(vec![Cell::from(first), num(u64::from(p.bans)).style(style), num(u64::from(p.offenders)), num(p.events)])
    };

    // Row 0 is "All countries", always there; the filter picks among the rest.
    let needle = needle(app);
    let listed: Vec<Option<&PlaceStats>> = std::iter::once(None)
        .chain(w.countries.iter().filter(|c| needle.as_deref().is_none_or(|n| has(n, &[&c.key, &c.name]))).map(Some))
        .collect();
    let sel = app.follow(&listed, |c| c.map_or(String::new(), |c| c.key.clone())).unwrap_or(0);
    let country = listed[sel];
    let detail = country.and_then(|c| w.by_country.get(&c.key));
    let empty = crate::engine::CountryDetail::default();
    // the port chart names the country by its code: the list beside it has the name
    let (scope, code, isps, ports) = match country {
        Some(c) => (c.name.as_str(), c.key.as_str(), &detail.unwrap_or(&empty).isps, &detail.unwrap_or(&empty).ports),
        None => ("all countries", "all countries", &w.isps, &w.ports),
    };

    if w.geo {
        let total = PlaceStats {
            bans: w.countries.iter().map(|c| c.bans).sum(),
            offenders: w.countries.iter().map(|c| c.offenders).sum(),
            events: w.countries.iter().map(|c| c.events).sum(),
            ..Default::default()
        };
        let rows: Vec<Row> = listed
            .iter()
            .map(|c| match c {
                None => place_row(&total, "All countries".into()).bold(),
                Some(c) => place_row(c, format!("{} {}", c.key, c.name)),
            })
            .collect();
        let unlocated = if w.unlocated > 0 { format!(", {} unlocated", grouped(u64::from(w.unlocated))) } else { String::new() };
        let title = format!(
            "{}: {}{unlocated}",
            list_title(app, "Countries", listed.len() - 1, w.countries.len()),
            count(u64::from(total.bans), "active ban", "active bans")
        );
        let t = Table::new(rows, [Constraint::Min(16), Constraint::Length(6), Constraint::Length(9), Constraint::Length(9)])
            .header(Row::new(["country", "bans", "offenders", "events"]).bold())
            .row_highlight_style(Style::new().reversed())
            .block(block(title));
        f.render_stateful_widget(t, left, &mut app.table);
        scrollbar(f, left, listed.len(), sel);

        // Rows that fit below the border and header; PgUp/PgDn scroll the rest.
        let fit = usize::from(bottom.height.saturating_sub(3)).max(1);
        app.net_offset = app.net_offset.min(isps.len().saturating_sub(fit));
        let shown = isps.iter().skip(app.net_offset).take(fit);
        let rows: Vec<Row> = shown.map(|i| place_row(i, format!("{:<9} {:<2}  {}", i.key, i.country, i.name))).collect();
        let title = if isps.len() > fit {
            format!("Networks in {scope} {}-{} of {} (PgUp/PgDn)", app.net_offset + 1, app.net_offset + rows.len(), isps.len())
        } else {
            format!("Networks in {scope} ({})", isps.len())
        };
        let t = Table::new(rows, [Constraint::Min(30), Constraint::Length(6), Constraint::Length(9), Constraint::Length(9)])
            .header(Row::new(["network", "bans", "offenders", "events"]).bold())
            .block(block(title));
        f.render_widget(t, bottom);
        scrollbar(f, bottom, isps.len(), app.net_offset);
    } else {
        f.render_widget(Paragraph::new(NO_GEO).wrap(Wrap { trim: true }).block(block("Countries")), left);
        f.render_widget(Paragraph::new(NO_GEO).wrap(Wrap { trim: true }).block(block("Networks")), bottom);
    }

    use ratatui::widgets::{Bar, BarChart, BarGroup};
    let fit = usize::from(right.height.saturating_sub(2));
    // The count goes into the label: drawn inside the bar, the digits past a short bar's end
    // took the bar's colour.
    let count_w = ports.iter().take(fit).map(|(_, n)| grouped(*n).len()).max().unwrap_or(1);
    let bars: Vec<Bar> = ports
        .iter()
        .take(fit)
        .map(|(port, n)| {
            let svc = s
                .port_names
                .iter()
                .find(|(p, _)| p == port)
                .map(|(_, n)| n.as_str())
                .or_else(|| crate::abuse::service_of("TCP", *port))
                .or_else(|| crate::abuse::service_of("UDP", *port))
                .unwrap_or("");
            let count = grouped(*n);
            Bar::default().value(*n).label(Line::from(format!("{port:>5} {svc:<10} {count:>count_w$}"))).text_value(String::new())
        })
        .collect();
    // Live counters are halved daily (kept across restarts); a log's counts cover its whole period.
    let span = if s.actions_log.is_some() { " TCP+UDP, over the whole log " } else { " TCP+UDP, halved daily " };
    let b = block(format!("Top {} ports probed from {code}", bars.len())).title_bottom(Line::styled(span, dim()).right_aligned());
    if bars.is_empty() {
        let text = format!("No probed ports from {code} recently.");
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(b), right);
        return;
    }
    let chart = BarChart::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .bar_width(1)
        .bar_gap(0)
        .bar_style(Style::new().fg(Color::Red))
        .value_style(Style::new().fg(Color::White).bold())
        .data(BarGroup::default().bars(&bars))
        .block(b);
    f.render_widget(chart, right);
}

/// Active bans (red triangles) and addresses that logged in during the last hour (green
/// circles), drawn at each country's capital; marker size grows with the count.
fn draw_map(f: &mut Frame, area: Rect, s: &Snapshot, europe: bool) {
    use ratatui::symbols::Marker;
    use ratatui::widgets::canvas::{Canvas, Map, MapResolution, Points};
    let w = &s.world;
    if !w.geo {
        f.render_widget(Paragraph::new(NO_GEO).wrap(Wrap { trim: true }).block(block("Map")), area);
        return;
    }
    let [map_area, legend_area] = Layout::vertical([Constraint::Min(5), Constraint::Length(3)]).areas(area);
    // Europe is where capitals sit a few dots apart at world scale.
    let ([west, east], [south, north]) = if europe { ([-25.0, 50.0], [34.0, 71.0]) } else { ([-180.0, 180.0], [-58.0, 84.0]) };
    // Degrees per braille dot (2 x 4 per cell), so markers are sized in screen dots.
    let inner = map_area.inner(Margin::new(1, 1));
    let (cols, lines) = (f64::from(inner.width.max(1)), f64::from(inner.height.max(1)));
    let dx = (east - west) / (cols * 2.0);
    let dy = (north - south) / (lines * 4.0);

    let mut banned: Vec<(&PlaceStats, (f64, f64))> =
        w.countries.iter().filter(|c| c.bans > 0).filter_map(|c| Some((c, crate::capitals::capital(&c.key)?))).collect();
    // The country list is ordered by offenders; labels and the legend go to the most bans.
    banned.sort_by(|a, b| b.0.bans.cmp(&a.0.bans).then(a.0.key.cmp(&b.0.key)));
    let mut triangles = Vec::new();
    for (c, (lat, lon)) in &banned {
        let h = (3.0 + 3.0 * f64::from(c.bans).ln()).min(16.0).round() as i32;
        // apex up, centred on the capital
        for row in 0..=h {
            let half = row / 2;
            let y = lat + f64::from(h / 2 - row) * dy;
            for col in -half..=half {
                triangles.push((lon + f64::from(col) * dx, y));
            }
        }
    }
    let mut circles = Vec::new();
    let users: Vec<(&String, u32, (f64, f64))> =
        w.logged_in.iter().filter_map(|(cc, n)| Some((cc, *n, crate::capitals::capital(cc)?))).collect();
    for (_, n, (lat, lon)) in &users {
        let r = (1.5 + 1.5 * f64::from(*n).ln()).min(8.0);
        let ri = r.ceil() as i32;
        for i in -ri..=ri {
            for j in -ri..=ri {
                if f64::from(i * i + j * j) <= r * r {
                    circles.push((lon + f64::from(i) * dx, lat + f64::from(j) * dy));
                }
            }
        }
    }
    // Labels in screen cells (placed the way the canvas places them), most bans first: one
    // that would touch another moves a line up or down, else it's left out (Brussels and
    // Amsterdam share a cell at world scale).
    let line_h = (north - south) / (lines - 1.0).max(1.0);
    let mut taken: Vec<(i64, i64, i64)> = Vec::new();
    let mut labels: Vec<(f64, f64, String)> = Vec::new();
    let visible = banned.iter().filter(|(_, (lat, lon))| (west..=east).contains(lon) && (south..=north).contains(lat));
    for (c, (lat, lon)) in visible.take(if europe { 30 } else { 10 }) {
        let h = (3.0 + 3.0 * f64::from(c.bans).ln()).min(16.0);
        let x = lon + (h / 2.0 + 2.0) * dx;
        let col = ((x - west) * (cols - 1.0) / (east - west)) as i64;
        let len = c.key.chars().count() as i64;
        for y in [*lat, lat + line_h, lat - line_h] {
            let line = ((north - y) * (lines - 1.0) / (north - south)) as i64;
            if taken.iter().all(|&(l, from, to)| l != line || col + len < from || col > to) {
                taken.push((line, col, col + len));
                labels.push((x, y, c.key.clone()));
                break;
            }
        }
    }
    // Only what is drawn; bans in countries without a known capital are mentioned apart.
    let bans: u32 = banned.iter().map(|(c, _)| c.bans).sum();
    let off_map: u32 = w.countries.iter().map(|c| c.bans).sum::<u32>() - bans;
    let off_map = if off_map > 0 { format!(" (+{off_map} not on the map)") } else { String::new() };
    let logged: u32 = w.logged_in.values().sum();
    // a decision log has no logins
    let logins = if s.actions_log.is_some() {
        String::new()
    } else {
        format!("   ● {} logged in during the last hour", count(u64::from(logged), "address", "addresses"))
    };
    let canvas = Canvas::default()
        .block(block(format!(
            "{}: ▲ {} in {}{off_map}{logins}",
            if europe { "Europe" } else { "Map" },
            count(u64::from(bans), "active ban", "active bans"),
            count(banned.len() as u64, "country", "countries"),
        )))
        .marker(Marker::Braille)
        .x_bounds([west, east])
        .y_bounds([south, north])
        .paint(move |ctx| {
            ctx.draw(&Map { color: Color::DarkGray, resolution: MapResolution::High });
            ctx.layer();
            ctx.draw(&Points { coords: &triangles, color: Color::Red });
            ctx.layer();
            ctx.draw(&Points { coords: &circles, color: Color::Green });
            for (x, y, text) in &labels {
                ctx.print(*x, *y, Line::from(text.clone()).style(Style::new().fg(Color::LightRed).bold()));
            }
        });
    f.render_widget(canvas, map_area);

    let top: Vec<String> = banned.iter().take(12).map(|(c, _)| format!("{} {}", c.key, c.bans)).collect();
    let mut users: Vec<(&String, u32)> = w.logged_in.iter().map(|(c, n)| (c, *n)).collect();
    users.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let users: Vec<String> = users.iter().map(|(c, n)| format!("{c} {n}")).collect();
    let mut legend = vec![Line::from(vec![Span::styled("▲ bans  ", Style::new().fg(Color::Red).bold()), Span::raw(top.join("  "))])];
    if s.actions_log.is_none() {
        legend.push(Line::from(vec![Span::styled("● users ", Style::new().fg(Color::Green).bold()), Span::raw(users.join("  "))]));
    }
    f.render_widget(Paragraph::new(legend).block(Block::new().borders(ratatui::widgets::Borders::TOP)), legend_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::pipeline::Pipeline;
    use crate::record::{parse_syslog_line, YearGuess};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::Arc;

    fn screen(term: &Terminal<TestBackend>) -> String {
        term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    /// The screen's lines, for checks on one part of it.
    fn screen_lines(term: &Terminal<TestBackend>) -> Vec<String> {
        let buf = term.backend().buffer();
        (0..buf.area.height).map(|y| (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect()).collect()
    }

    fn sample() -> Snapshot {
        let mut pipe = Pipeline::new(Arc::new(Config::default()), 0);
        let mut years = YearGuess::new(2026);
        for (i, ip) in ["11.50.40.218", "11.50.40.218", "11.50.40.218", "9.9.9.9"].iter().enumerate() {
            let pid = format!("0.{i}.0");
            for line in [
                format!("Aug 16 21:53:5{i} h ejabberdctl[1]: 2026-08-16 21:53:5{i}.000 [info] (#PID<{pid}>) Accepted connection [::ffff:{ip}]:1 -> [::ffff:11.25.39.236]:5223"),
                format!("Aug 16 21:53:5{i} h ejabberdctl[1]: 2026-08-16 21:53:5{i}.100 [info] (tls|<{pid}>) Failed to secure c2s connection: TLS failed: SSL_do_handshake failed: error:0A000102:SSL routines::unsupported protocol"),
            ] {
                pipe.feed(&parse_syslog_line(&line, &mut years).unwrap());
            }
        }
        pipe.snapshot(50)
    }

    fn app_with(snap: Snapshot) -> App {
        let mut app = App::new(DataSource::File("unused".into()));
        app.snap = Some(snap);
        app
    }

    fn press(app: &mut App, keys: &str) {
        for c in keys.chars() {
            app.key(KeyEvent::from(KeyCode::Char(c)));
        }
    }

    #[test]
    fn patterns_tab_when_configured() {
        assert_eq!(app_with(sample()).tabs.len(), 9, "no patterns: no tab");
        let cfg = Config::from_toml(
            "[[patterns]]\nname = \"web\"\nidentifier = \"nginx\"\nuid = 33\nkind = \"probe\"\nport = 443\nregex = '^(?P<ip>\\S+) .*GET /\\.env'\n\
             [[patterns]]\nname = \"mail\"\nunit = \"postfix@-.service\"\nidentifier = \"postfix/smtpd\"\nregex = 'from \\S+\\[(?P<ip>[^]]+)\\]'",
        )
        .unwrap();
        let mut pipe = Pipeline::new(Arc::new(cfg), 0);
        let mut years = YearGuess::new(2026);
        for line in [
            "Oct 24 11:00:01 h nginx[5]: 198.51.100.7 - - \"GET /.env HTTP/1.1\" 404",
            "Oct 24 11:00:02 h nginx[5]: 203.0.113.50 - - \"GET /.env HTTP/1.1\" 404",
            "Oct 24 11:00:03 h nginx[5]: 198.51.100.7 - - \"GET /.env.bak HTTP/1.1\" 404",
            "Oct 24 11:00:04 h nginx[5]: unknown - - \"GET /.env HTTP/1.1\" 404",
        ] {
            pipe.feed(&parse_syslog_line(line, &mut years).unwrap());
        }
        let mut app = App::new(DataSource::File("unused".into()));
        app.apply(Ok(pipe.snapshot(50)));
        assert_eq!(app.tabs.len(), 10);
        press(&mut app, "0");
        assert_eq!(app.current(), Tab::Patterns);
        let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        for want in [
            "Patterns (2)",
            "web",
            "probe",
            "identifier nginx, uid 33",
            "Addresses web found (2)",
            "198.51.100.7",
            "Lines without an address (1)",
            "unknown - - ",
        ] {
            assert!(text.contains(want), "{want}: {}", screen_lines(&term).join("\n"));
        }
        let lines = screen_lines(&term);
        let busiest = lines.iter().position(|l| l.contains("198.51.100.7")).unwrap();
        assert!(lines.iter().position(|l| l.contains("203.0.113.50")).unwrap() > busiest, "busiest first");
        assert!(lines[0].contains("0 Patterns"), "the tenth tab is on key 0: {}", lines[0]);
        // a pattern whose service sends nothing says so
        press(&mut app, "j");
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("No line from unit postfix@-.service") && text.contains("is the service installed"), "{text}");
        for (w, h) in [(80, 24), (60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &mut app)).unwrap();
        }
    }

    #[test]
    fn every_tab_renders() {
        let mut snap = sample();
        assert!(!snap.bans.is_empty());
        let key = |port| crate::exposure::ListenerKey { proto: crate::event::Proto::Tcp, addr: "0.0.0.0".parse().unwrap(), port };
        let owners = [(1u64, "sshd".to_string()), (2, "docker-proxy".to_string())].into();
        let ufw = "Status: active\n\nTo  Action  From\n--  ------  ----\n22/tcp                     LIMIT       Anywhere\n53/udp                     ALLOW       Anywhere\n5222/tcp                   ALLOW       Anywhere\n";
        let fw = crate::exposure::FirewallView { ufw: Some(ufw), ..Default::default() };
        snap.exposure = Some(crate::exposure::build_report(0, vec![(key(22), 1), (key(51821), 2), (key(5222), 1)], &owners, &fw, &[]));
        snap.cluster = Some(crate::cluster::ClusterView { node_id: "xmpp".into(), ..Default::default() });
        let mut app = app_with(snap);
        for (w, h) in [(140, 40), (60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in 0..app.tabs.len() {
                app.switch(tab);
                app.detail = tab == 1;
                app.help = tab == 2;
                term.draw(|f| draw(f, &mut app)).unwrap();
            }
        }
        app.help = false;
        app.switch(1);
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("11.50.40.218") && text.contains("banned "), "{text}");
        assert!(!text.contains("banned 11.50.40.218"), "a host ban doesn't repeat the address");
        assert!(text.contains("xmpp ENFORCE") || text.contains("xmpp SHADOW"), "node and mode in the footer");

        // commands need the daemon; a saved snapshot says so before asking anything
        app.switch(2);
        app.start_unban();
        assert!(app.modal.is_none());
        assert_eq!(app.flash.as_ref().map(|f| f.text.as_str()), Some("read-only: this is a saved snapshot"));
        app.source = DataSource::Socket(std::env::temp_dir().join("logguard-no-such-socket"));
        app.start_unban();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Unban 11.50.40.218") && text.contains("Active bans"), "confirm dialog over the list");
        app.modal_key(KeyCode::Char('y'));
        assert_eq!(app.outbox, ["unban 11.50.40.218"], "sent from the background thread, not the key handler");
        assert_eq!(app.flash.as_ref().map(|f| f.text.as_str()), Some("sent: unban 11.50.40.218"));
        let cmd = app.outbox.remove(0);
        let socket = std::env::temp_dir().join("logguard-no-such-socket");
        app.replied(&cmd, crate::daemon::control_command(&socket, &cmd));
        let flash = app.flash.as_ref().unwrap();
        assert!(flash.error && flash.text.starts_with("error: connecting") && app.reload, "{}", flash.text);
        app.start_allow();
        app.modal_key(KeyCode::Char('3'));
        assert!(matches!(&app.modal, Some(Modal::Days { buf, .. }) if buf == "3"), "the first digit replaces the default");
        app.modal_key(KeyCode::Char('0'));
        assert!(matches!(&app.modal, Some(Modal::Days { buf, .. }) if buf == "30"));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("30▏ days, until "), "the end date is shown");
        app.modal_key(KeyCode::Esc);
        assert!(app.modal.is_none());
        app.flash = None;

        app.switch(5);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("published by docker, bypasses ufw") && text.contains("none: containers blocked"), "exposure tab");
        assert!(text.contains("ufw allows 53/udp"), "dead rule shown");
        assert!(text.contains("LIMIT 22/tcp") && text.contains("allowed by ufw, rate-limited"), "a LIMIT rule says so: {text}");
        assert!(text.contains("ALLOW 5222/tcp"), "{text}");

        let place = |key: &str, name: &str, bans, offenders| PlaceStats {
            key: key.into(),
            name: name.into(),
            bans,
            offenders,
            events: 7,
            ..Default::default()
        };
        if let Some(snap) = app.snap.as_mut() {
            snap.world = crate::engine::WorldView {
                geo: true,
                countries: vec![place("CN", "China", 120, 300), place("DE", "Germany", 3, 9), place("ZZ", "Nowhere", 1, 1)],
                isps: vec![place("AS4134", "Chinanet", 80, 200)],
                ports: vec![(23, 900), (3389, 40)],
                logged_in: [("UA".to_string(), 3)].into(),
                unlocated: 2,
                by_country: [(
                    "DE".to_string(),
                    crate::engine::CountryDetail { isps: vec![place("AS24940", "Hetzner Online GmbH", 3, 9)], ports: vec![(3389, 5)] },
                )]
                .into(),
            };
        }
        for (w, h) in [(160, 50), (60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in [6, 7] {
                app.switch(tab);
                term.draw(|f| draw(f, &mut app)).unwrap();
            }
        }
        let mut term = Terminal::new(TestBackend::new(160, 50)).unwrap();
        app.switch(6);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("CN China") && text.contains("Chinanet") && text.contains("Telnet"), "countries tab");
        assert!(text.contains("All countries") && text.contains("Networks in all countries"), "all countries first");
        app.table.select(Some(2)); // CN, DE, ZZ after "All countries"
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Networks in Germany (1)") && text.contains("Hetzner") && !text.contains("Chinanet"), "networks follow");
        assert!(text.contains("ports probed from DE") && text.contains("RDP") && !text.contains("Telnet"), "ports follow");
        app.table.select(Some(1)); // CN: no detail sent
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("No probed ports from CN") && text.contains("Networks in China (0)"));
        // a refresh re-sorts the countries: the cursor stays on Germany, not on row 2
        app.table.select(Some(2));
        term.draw(|f| draw(f, &mut app)).unwrap();
        if let Some(snap) = app.snap.as_mut() {
            snap.world.countries.swap(0, 1);
        }
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.table.selected(), Some(1));
        assert!(screen(&term).contains("Networks in Germany"), "selection follows the country");
        // the filter picks countries; "All countries" stays on top
        press(&mut app, "/germ");
        app.key(KeyEvent::from(KeyCode::Enter));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(
            text.contains("Countries (1 of 3 match \"germ\")") && text.contains("All countries") && !text.contains("CN China"),
            "{text}"
        );
        // a filtered list's rows can be picked, while the filter is typed and after
        app.key(KeyEvent::from(KeyCode::Esc));
        press(&mut app, "/germ");
        app.key(KeyEvent::from(KeyCode::Down));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(app.editing && screen(&term).contains("Networks in Germany"), "Down while typing");
        app.key(KeyEvent::from(KeyCode::Enter));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(!app.editing && screen(&term).contains("Networks in Germany"), "Enter keeps the row");
        app.key(KeyEvent::from(KeyCode::Up));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("Networks in all countries"));
        app.key(KeyEvent::from(KeyCode::Down));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("Networks in Germany"), "Down after Enter");
        app.key(KeyEvent::from(KeyCode::Esc));
        assert!(app.filter.is_empty());
        app.move_to(0);
        if let Some(snap) = app.snap.as_mut() {
            snap.world.isps = (1..=40).map(|i| place(&format!("AS{i}"), &format!("Net{i}"), 0, 1)).collect();
        }
        let mut small = Terminal::new(TestBackend::new(120, 30)).unwrap();
        small.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&small);
        assert!(text.contains("Networks in all countries 1-") && text.contains("of 40 (PgUp/PgDn)"), "partial list says so");
        app.net_offset = 1000;
        small.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&small);
        assert!(text.contains("-40 of 40") && text.contains("Net40 "), "clamped to the last page");
        app.switch(7);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("123 active bans in 2 countries (+1 not on the map)"), "unknown capitals aren't drawn");
        assert!(text.contains("UA 3") && text.contains("CN 120") && text.contains("3 addresses logged in"), "legend");
        assert!(text.contains("z Europe"), "the key is in the footer");
        app.key(KeyEvent::from(KeyCode::Char('z')));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Europe: ▲") && text.contains("DE"), "zoomed on Europe, German label shown");
        assert!(!text.contains("CN▲") && text.contains("z world"));
    }

    #[test]
    fn narrow_terminal_keeps_what_matters() {
        let mut app = app_with(sample());
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let lines = screen_lines(&term);
        assert!(["1Overview", "7Countries", "8Map", "9Alerts"].iter().all(|t| lines[0].contains(t)), "every tab named: {}", lines[0]);
        assert!(lines[23].contains("? help") && lines[23].contains("q quit"), "{}", lines[23]);
        app.switch(1);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("11.50.40.218 ") && text.contains("9.9.9.9"), "whole addresses: {text}");
        assert!(text.contains("2Offenders"), "current tab named");
        let ips = |app: &App| offender_rows(app, app.snap.as_ref().unwrap()).iter().map(|v| v.ip.to_string()).collect::<Vec<_>>();
        let by_danger = ips(&app);
        press(&mut app, "oo");
        assert_eq!(ips(&app), ["9.9.9.9", "11.50.40.218"], "sorted by address");
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("· by address"));
        press(&mut app, "o");
        assert_eq!(ips(&app), by_danger);

        // narrow columns: drop "fast"/"slow" before the address is cut
        let show = fit(40, &[(15, 0), (6, 0), (5, 5), (5, 5), (10, 2), (12, 3)], 1);
        assert_eq!(show, [true, true, false, false, true, false]);
        assert_eq!(fit(200, &[(15, 0), (0, 4), (12, 3)], 1), [true, false, true], "an empty column is never shown");
        assert_eq!(fit(39, &[(15, 0), (10, 2), (12, 3)], 2), [true, true, false], "wider gaps leave less room");
    }

    #[test]
    fn filter_details_and_follow() {
        let mut app = app_with(sample());
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        app.switch(1);
        // the filter is typed in the footer, and narrows the list as it's typed
        press(&mut app, "/9.9");
        assert!(app.editing);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("filter: 9.9") && text.contains("(1 of 2 match \"9.9\")") && !text.contains("11.50.40.218"), "{text}");
        app.key(KeyEvent::from(KeyCode::Enter));
        assert!(!app.editing && app.filter == "9.9");
        assert!(app.key(KeyEvent::from(KeyCode::Char('q'))), "q quits once the filter is typed");
        app.key(KeyEvent::from(KeyCode::Esc));
        assert!(app.filter.is_empty(), "esc clears it");
        assert!(!app.key(KeyEvent::from(KeyCode::Esc)), "esc doesn't quit");
        assert!(app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), "ctrl-c quits");
        app.flash = None;

        // details open under the list and follow the selection
        app.key(KeyEvent::from(KeyCode::Enter));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let first = app.sel.1.clone().unwrap();
        let text = screen(&term);
        assert!(text.contains("Details") && text.contains("evidence (latest last)") && text.contains("Offenders (2)"), "{text}");
        app.key(KeyEvent::from(KeyCode::Down));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let second = app.sel.1.clone().unwrap();
        assert_ne!(first, second);
        // a refresh that re-sorts the list keeps the cursor (and the details) on the same address
        if let Some(s) = app.snap.as_mut() {
            s.offenders.reverse();
        }
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.sel.1.as_deref(), Some(second.as_str()));
        assert_eq!(app.table.selected(), Some(0));
        app.key(KeyEvent::from(KeyCode::Esc));
        assert!(!app.detail);

        // event details show the whole message and the evidence
        app.switch(3);
        app.key(KeyEvent::from(KeyCode::Enter));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Details") && text.contains("target ") && text.contains("evidence:"), "{text}");
        // u on a ban decision targets its address
        let snap = app.snap.as_ref().unwrap();
        let rows = event_rows(&app, snap);
        let ban = rows.iter().position(|a| a.kind == ActionKind::Ban).unwrap();
        let target = rows[ban].target.unwrap();
        app.table.select(Some(ban));
        assert_eq!(app.selected_target(), Some((target, true)));

        app.switch(4);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("No account has had authentication failures lately."), "empty lists say so");
        press(&mut app, "?");
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("switch tabs"), "help");
        press(&mut app, "x");
        assert!(!app.help, "any key closes the help");
    }

    #[test]
    fn exposure_names_the_firewall() {
        use crate::exposure::FirewallView;
        let key = |addr: &str, port| crate::exposure::ListenerKey { proto: crate::event::Proto::Tcp, addr: addr.parse().unwrap(), port };
        let owners = [(1u64, "sshd".to_string()), (2, "app".to_string())].into();
        let sockets = vec![(key("0.0.0.0", 22), 1), (key("0.0.0.0", 8080), 2)];
        let mut app = app_with(sample());
        let mut term = Terminal::new(TestBackend::new(140, 24)).unwrap();
        let mut show = |app: &mut App, fw: &FirewallView| {
            app.snap.as_mut().unwrap().exposure = Some(crate::exposure::build_report(0, sockets.clone(), &owners, fw, &[]));
            app.switch(5);
            term.draw(|f| draw(f, app)).unwrap();
            screen_lines(&term)
        };
        // plain iptables, no ufw: its rules decide
        let ipt = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 22 -m limit --limit 3/min -j ACCEPT\n";
        let lines = show(&mut app, &FirewallView { iptables: Some(ipt), ..Default::default() });
        let text = lines.join("\n");
        assert!(
            text.contains("· iptables ·") && text.contains("ACCEPT 22/tcp") && text.contains("allowed by iptables, rate-limited"),
            "{text}"
        );
        assert!(text.contains("blocked by iptables") && text.contains("firewall rule") && !text.contains("NO FIREWALL"));
        // nothing filters: said above the list, on the tab and on the Overview
        let lines =
            show(&mut app, &FirewallView { ufw: Some("Status: inactive\n"), iptables: Some("-P INPUT ACCEPT\n"), ..Default::default() });
        let text = lines.join("\n");
        assert!(lines[0].contains("6 Exposure no firewall"), "{}", lines[0]);
        assert!(text.contains(" NO FIREWALL ") && text.contains("every listener on a public address below is reachable"), "{text}");
        assert!(text.contains("ufw is installed but inactive") && text.contains("NO FIREWALL (ufw inactive)"));
        assert!(text.contains("no firewall") && !text.contains("blocked by"));
        app.switch(0);
        let mut overview = Terminal::new(TestBackend::new(160, 30)).unwrap();
        overview.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&overview).contains("Firewall  NO FIREWALL (ufw inactive): every public listener is reachable"));
        let mut narrow = Terminal::new(TestBackend::new(60, 15)).unwrap();
        narrow.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen_lines(&narrow)[0].contains(" 6! "), "the alert stays on a short tab bar: {}", screen_lines(&narrow)[0]);
        // a report from a daemon that read only ufw: not checked, rather than no firewall
        let mut old = crate::exposure::build_report(0, sockets.clone(), &owners, &FirewallView::default(), &[]);
        old.firewall = None;
        app.snap.as_mut().unwrap().exposure = Some(old);
        app.switch(5);
        let mut other = Terminal::new(TestBackend::new(140, 24)).unwrap();
        other.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&other);
        assert!(text.contains("FIREWALL NOT CHECKED") && text.contains("public, firewall not checked"), "{text}");
        assert!(!text.contains("NO FIREWALL") && !screen_lines(&other)[0].contains("no firewall"));
        // nftables rules of their own: a note, not an alarm
        let text = show(&mut app, &FirewallView { nft_input: true, ..Default::default() }).join("\n");
        assert!(
            text.contains("nftables, rules not read") && text.contains("public, nftables rules not read") && !text.contains("NO FIREWALL")
        );
    }

    #[test]
    fn alerts_tab() {
        let mut snap = sample();
        let now = snap.generated;
        let h = 3600 * crate::time::SEC;
        let target = snap.bans[0].net;
        let alert = |ago: i64, severity: &str, topic: &str, message: &str, extra: &str| -> Action {
            serde_json::from_str(&format!(
                r#"{{"ts":{},"kind":"alert","severity":"{severity}","topic":"{topic}","message":"{message}"{extra}}}"#,
                now - ago
            ))
            .unwrap()
        };
        snap.alerts = vec![
            alert(
                h,
                "critical",
                "compromise",
                "LOGGED IN to canary account guest",
                &format!(
                    r#","target":"{target}","accounts":["ssh:guest"],"user_note":"someone logged in as you","evidence":["sshd accepted guest"]"#
                ),
            ),
            alert(2 * h, "warning", "system", "cluster peer 10.0.0.9:7946 unreachable", ""),
            alert(30 * h, "high", "exposure", "new internet-facing listener 0.0.0.0:51821/tcp", ""),
        ];
        let mut app = app_with(snap);
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(screen_lines(&term)[0].contains("9 Alerts 1"), "one serious alert in 24 h: {}", screen_lines(&term)[0]);
        assert!(text.contains("Alerts   1 high or critical in 24 h (tab 9)"), "{text}");
        app.switch(8);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Alerts (3)") && text.contains("suspicious login") && text.contains("ssh:guest"), "{text}");
        assert!(text.contains("exposure change") && text.contains("1 high or critical in the last 24 h"), "the 30 h old one is not recent");
        let shown =
            |app: &App| alert_rows(app, app.snap.as_ref().unwrap()).iter().map(|a| a.topic.map_or("", topic_name)).collect::<Vec<_>>();
        // t: each topic there is, in turn, then all again
        press(&mut app, "t");
        assert_eq!(shown(&app), ["suspicious login"]);
        press(&mut app, "t");
        assert_eq!(shown(&app), ["system"]);
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("Alerts (1 of 3) · system"));
        press(&mut app, "tt");
        assert_eq!(shown(&app).len(), 3);
        // s: the least severity, shared with Events
        press(&mut app, "ss");
        assert_eq!(shown(&app), ["suspicious login", "exposure change"]);
        press(&mut app, "ss");
        assert_eq!(app.min_severity, Severity::Info);
        // details: the topic, whether the address is still banned, the note sent, the evidence
        app.key(KeyEvent::from(KeyCode::Enter));
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("topic: suspicious login") && text.contains("(banned now)"), "{text}");
        assert!(text.contains("note for the user: someone logged in as you") && text.contains("sshd accepted guest"));
        assert_eq!(app.selected_target(), Some((target, true)), "u and a act on its address");
        // filtered by any text in it
        app.key(KeyEvent::from(KeyCode::Esc));
        press(&mut app, "/canary");
        app.key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(shown(&app), ["suspicious login"]);
    }

    #[test]
    fn keys_cannot_misfire() {
        let mut app = app_with(sample());
        app.source = DataSource::Socket(std::env::temp_dir().join("logguard-no-such-socket"));
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        app.switch(1);
        term.draw(|f| draw(f, &mut app)).unwrap();
        // a paste is never read as keys: outside the filter it's ignored, inside it's text
        app.paste("uy");
        assert!(app.modal.is_none() && app.outbox.is_empty());
        press(&mut app, "/");
        app.paste("9.9\n.9");
        assert_eq!(app.filter, "9.9.9", "no control characters");
        // Ctrl-U clears the filter, other control keys type nothing
        app.key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL));
        assert_eq!(app.filter, "9.9.9");
        app.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(app.filter.is_empty());
        app.key(KeyEvent::from(KeyCode::Esc));

        // End, then u before the next frame: the last row, not "nothing selected"
        press(&mut app, "G");
        assert!(app.selected_target().is_some());
        // the allowlist takes a year at most, as the daemon does
        press(&mut app, "a");
        for c in "999".chars() {
            app.modal_key(KeyCode::Char(c));
        }
        assert!(matches!(&app.modal, Some(Modal::Days { buf, .. }) if buf == "365"));
        assert!(app.flash.as_ref().is_some_and(|f| f.error && f.text == "365 days at most"));
        app.modal_key(KeyCode::Esc);

        // a move stops following: Up on the top row stays there after a re-sort
        press(&mut app, "g");
        term.draw(|f| draw(f, &mut app)).unwrap();
        let top = app.sel.1.clone();
        if let Some(s) = app.snap.as_mut() {
            s.offenders.reverse();
        }
        app.key(KeyEvent::from(KeyCode::Up));
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.table.selected(), Some(0));
        assert_ne!(app.sel.1, top, "the row, not the address that moved down");

        // heights of huge text saturate instead of overflowing
        let long = Line::from("x".repeat(70_000));
        assert_eq!(wrapped_height(&[long.clone(), long], 1), u16::MAX);
        assert_eq!(wrapped_height(&[Line::from("abcdef")], 0), 6);
        // wrapped word by word, as drawn: seven 4-letter words in 6 cells take a row each, where
        // counting characters (34 / 6) would give 6 and cut the last line off
        assert_eq!(wrapped_height(&[Line::from("aaaa bbbb cccc dddd eeee ffff gggg")], 6), 7);

        // an address last seen before a restart has a score but no evidence: the details say why
        let mut s = app.snap.clone().unwrap();
        s.started = s.offenders[0].last_seen + 1;
        let v = &mut s.offenders[0];
        v.evidence.clear();
        let text: String = offender_detail(&s.offenders[0], &s).iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("none: last seen before logguard started") && text.contains("evidence isn't kept across restarts"), "{text}");
    }

    #[test]
    fn map_labels_dont_overlap() {
        let place = |key: &str, bans| PlaceStats { key: key.into(), name: key.into(), bans, offenders: bans, ..Default::default() };
        let mut snap = sample();
        snap.world =
            crate::engine::WorldView { geo: true, countries: vec![place("BE", 5), place("NL", 3), place("LU", 1)], ..Default::default() };
        let mut app = app_with(snap);
        app.switch(7);
        for europe in [false, true] {
            app.europe = europe;
            let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
            term.draw(|f| draw(f, &mut app)).unwrap();
            let map: String = screen_lines(&term)[2..25].join("\n");
            assert!(map.contains("BE") && map.contains("NL"), "both labels drawn (europe {europe}): {map}");
            assert!(!map.contains("BEL") && !map.contains("NLE") && !map.contains("NLU"), "none written over another");
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(12_345_678), "12,345,678");
        assert_eq!(count(1, "day", "days"), "1 day");
        assert_eq!(count(2, "day", "days"), "2 days");
        assert_eq!(short_place("United Kingdom / DigitalOcean, LLC (AS14061)"), "GB DigitalOcean, LLC");
        assert_eq!(short_place("Germany"), "Germany");
        assert_eq!(short_place("Akamai (AS63949)"), "Akamai");
        let ban = |origin: Option<&str>, reason: &str| Ban {
            net: "1.2.3.4".parse().unwrap(),
            since: 0,
            until: 0,
            offence: 0,
            reason: reason.into(),
            origin: origin.map(String::from),
            inner: vec![],
        };
        assert_eq!(ban_reason(&ban(Some("vpn"), "x")), "peer vpn: x", "a log's peer ban names the peer");
        assert_eq!(ban_reason(&ban(Some("vpn"), "peer vpn: x")), "peer vpn: x", "the daemon's text already does");
        assert_eq!(ban_reason(&ban(None, "x")), "x");
    }

    #[test]
    fn decision_log_tabs() {
        let path = std::env::temp_dir().join(format!("lg-actions-{}.jsonl", std::process::id()));
        let h = 3600 * crate::time::SEC;
        std::fs::write(
            &path,
            format!(
                "{}\nnot json\n{}\n{}\n",
                format_args!(r#"{{"ts":{h},"kind":"ban","severity":"high","target":"5.9.1.1","until":{},"message":"ban 5.9.1.1 [Germany / Hetzner Online GmbH (AS24940)] for 2h (offence #1): burst [1x fw_tripwire]","evidence":["10-12 10:00:00 tripwire block TCP/23"],"applied":true,"category":"tripwire"}}"#, 3 * h),
                format_args!(r#"{{"ts":{},"kind":"ban","severity":"high","target":"1.0.0.1","until":{},"message":"ban 1.0.0.1 for 59m (from peer vpn): x","applied":true,"category":"from peers"}}"#, h + 1, 2 * h),
                format_args!(r#"{{"ts":{},"kind":"alert","severity":"high","message":"new internet-facing listener 0.0.0.0:51821/tcp","topic":"exposure"}}"#, h + 5),
            ),
        )
        .unwrap();
        let mut app = App::new(DataSource::Actions(vec![path.clone()], None));
        app.refresh();
        let _ = std::fs::remove_file(&path);
        assert!(app.error.is_none() && app.snap.is_some());
        let mut term = Terminal::new(TestBackend::new(160, 45)).unwrap();
        let mut texts = vec![];
        for tab in 0..app.tabs.len() {
            app.switch(tab);
            term.draw(|f| draw(f, &mut app)).unwrap();
            texts.push(screen(&term));
        }
        let t = &texts[0];
        assert!(
            t.contains("1 Overview") && t.contains("5 Map") && !t.contains("Offenders") && !t.contains("Exposure"),
            "only what a log can show"
        );
        assert!(t.contains("Decision log") && t.contains("2 bans") && t.contains("Skipped   1 line that"), "{t}");
        assert!(t.contains("from peer vpn") && t.contains("tripwire") && t.contains("decision log, read-only"));
        assert!(texts[1].contains("Active bans at the end of the log (2)"), "both still active at the end (1h+1s)");
        assert!(texts[1].contains("peer vpn: x"), "a peer ban names the peer");
        assert!(texts[3].contains("DE Germany") && texts[3].contains("Telnet"), "countries from the ban message label");
        assert!(texts[3].contains("over the whole log"));
        assert!(texts[4].contains("▲ 1 active ban in 1 country") && !texts[4].contains("logged in"), "no login data in a log");
        assert!(!texts[4].contains("● users"));
        assert!(texts[5].contains("Bans per day, 1970-01-01 - 1970-01-01 (1 day, peak 2"), "{}", texts[5]);
        assert!(texts[5].contains("1970-01-01") && texts[5].contains("Germany 1") && texts[5].contains("Hetzner Online GmbH (AS24940) 1"));
        assert!(texts[6].contains("Alerts (1)") && texts[6].contains("exposure change") && texts[6].contains("0.0.0.0:51821/tcp"));
        assert!(texts[6].contains("1 high or critical in the last 24 h") && t.contains("7 Alerts 1"), "counted to the log's end");
        // read-only: commands are refused before anything is asked
        app.switch(1);
        press(&mut app, "u");
        assert!(app.modal.is_none() && app.flash.as_ref().is_some_and(|f| f.text == "read-only: this is a decision log"));
        // small terminals don't panic
        for (w, h) in [(60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &mut app)).unwrap();
        }
    }

    /// The address column fits the addresses on screen, and the counts beside the port bars
    /// keep one colour; logguard's honeypot listeners are listed, marked.
    #[test]
    fn offenders_columns_bars_and_honeypots() {
        let mut snap = sample();
        let view = |ip: &str| IpView {
            ip: ip.parse().unwrap(),
            fast: 50.0,
            slow: 60.0,
            danger: 50.0,
            peak: 50.0,
            first_seen: 0,
            last_seen: 0,
            counts: Default::default(),
            evidence: vec![],
            banned_by: None,
            banned_until: None,
            protected: None,
            geo: None,
        };
        snap.offenders = (1..=40).map(|i| view(&format!("198.51.100.{i}"))).collect();
        snap.offenders.push(view("2001:db8:1234:5678:9abc:def0:1234:5678"));
        snap.world.ports = vec![(80, 3358), (23, 99)];
        let key = |port| crate::exposure::ListenerKey { proto: crate::event::Proto::Tcp, addr: "::".parse().unwrap(), port };
        let owners = [(1u64, "logguard".to_string()), (2, "sshd".to_string())].into();
        let ufw = "Status: active\n\nTo  Action  From\n--  ------  ----\n2323/tcp                   ALLOW       Anywhere\n";
        let fw = crate::exposure::FirewallView { ufw: Some(ufw), ..Default::default() };
        let mut report = crate::exposure::build_report(0, vec![(key(2323), 1), (key(23), 1), (key(9845), 2)], &owners, &fw, &[]);
        crate::exposure::mark_honeypots(&mut report, &[23, 2323]);
        snap.exposure = Some(report);
        let mut app = app_with(snap);
        let mut term = Terminal::new(TestBackend::new(120, 20)).unwrap();

        app.switch(1);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let lines = screen_lines(&term);
        let header = lines.iter().find(|l| l.contains("address")).unwrap();
        assert!(header.contains("fast") && header.contains("slow"), "room for the scores: {header}");
        assert!(header.find("danger").unwrap() < 24, "the IPv6 address far below doesn't widen it: {header}");
        assert!(header.contains("danger  ") && header.contains("last seen  "), "two spaces between columns: {header}");
        press(&mut app, "G");
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("2001:db8:1234:5678:9abc:def0:1234:5678"), "whole once on screen");

        app.switch(6);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let buf = term.backend().buffer().clone();
        let y = (0..buf.area.height).find(|y| screen_lines(&term)[*y as usize].contains("23 Telnet")).unwrap();
        let line = &screen_lines(&term)[y as usize];
        // (cells, not bytes: the borders are multi-byte characters)
        let x = line[..line.find("99").unwrap()].chars().count() as u16;
        let (a, b) = (&buf[(x, y)], &buf[(x + 1, y)]);
        assert_eq!((a.symbol(), b.symbol()), ("9", "9"));
        assert_eq!(a.fg, b.fg, "both digits in one colour");
        assert_ne!(b.fg, Color::Red);
        assert!(screen_lines(&term).iter().any(|l| l.contains("3,358")));

        app.switch(5);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("Listeners (3): 0 exposed, 2 honeypots"), "{text}");
        assert!(text.contains("honeypot: logguard bans whoever connects"), "{text}");
        assert!(text.contains("honeypot, but blocked by ufw: open it (ufw allow 23/tcp)"), "{text}");
    }

    #[test]
    fn no_snapshot_yet() {
        let mut app = App::new(DataSource::Socket(std::env::temp_dir().join("logguard-no-such-socket")));
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&term).contains("Loading the snapshot"));
        app.refresh();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text = screen(&term);
        assert!(text.contains("connecting to") && text.contains("Is logguard running") && text.contains("no data"), "{text}");
    }
}
