//! Terminal dashboard. Reads snapshots from the daemon's Unix socket (live), from a
//! JSON file written by `logguard replay --snapshot`, or builds the state at the end of a
//! decision log (`actions.jsonl`, fewer tabs).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::engine::{ActionKind, Severity, Snapshot};
use crate::event::Signal;
use crate::record::Source as LogSource;
use crate::time::{fmt_duration, fmt_ts};

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
        }
    }
}

const ALL_TABS: [Tab; 8] = [Tab::Overview, Tab::Offenders, Tab::Bans, Tab::Events, Tab::Accounts, Tab::Exposure, Tab::Countries, Tab::Map];
/// What a decision log can fill: no scores, accounts or exposure scan in it.
const LOG_TABS: [Tab; 6] = [Tab::Overview, Tab::Bans, Tab::Events, Tab::Countries, Tab::Map, Tab::Trends];

enum Modal {
    Confirm { cmd: String, text: String },
    Days { net: crate::net::Net, buf: String },
}

struct App {
    modal: Option<Modal>,
    /// Result of the last operator command, shown in the footer.
    flash: Option<String>,
    source: DataSource,
    snap: Option<Snapshot>,
    error: Option<String>,
    tabs: &'static [Tab],
    tab: usize,
    table: TableState,
    detail: bool,
    paused: bool,
    min_severity: Severity,
    /// Map tab: Europe instead of the whole world.
    europe: bool,
    /// Countries tab: first network row shown (PgUp/PgDn), clamped when drawn.
    net_offset: usize,
    /// Countries tab: the row drawn last and its country code. The list is re-sorted on
    /// every refresh, so an unmoved cursor follows its country, not its row number.
    country_sel: (usize, Option<String>),
}

pub fn run(source: DataSource) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "the dashboard needs an interactive terminal (over ssh use `ssh -t host ...`); \
             for plain-text output use `logguard status`"
        );
    }
    let tabs: &'static [Tab] = if matches!(source, DataSource::Actions(..)) { &LOG_TABS } else { &ALL_TABS };
    let mut app = App {
        tabs,
        modal: None,
        flash: None,
        source,
        snap: None,
        error: None,
        tab: 0,
        table: TableState::default().with_selected(0),
        detail: false,
        paused: false,
        min_severity: Severity::Info,
        europe: false,
        net_offset: 0,
        country_sel: (0, None),
    };
    app.refresh();
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut last = Instant::now();
    loop {
        terminal.draw(|f| draw(f, app))?;
        if event::poll(Duration::from_millis(250))? {
            if let TermEvent::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                if app.modal.is_some() {
                    app.modal_key(k.code);
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc if app.detail => app.detail = false,
                    KeyCode::Esc => return Ok(()),
                    KeyCode::Tab | KeyCode::Right => app.switch((app.tab + 1) % app.tabs.len()),
                    KeyCode::BackTab | KeyCode::Left => app.switch((app.tab + app.tabs.len() - 1) % app.tabs.len()),
                    KeyCode::Char(c @ '1'..='9') if (c as usize - '1' as usize) < app.tabs.len() => app.switch(c as usize - '1' as usize),
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.table.select_next();
                        app.net_offset = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.table.select_previous();
                        app.net_offset = 0;
                    }
                    KeyCode::PageDown if app.current() == Tab::Countries => app.net_offset += 10,
                    KeyCode::PageUp if app.current() == Tab::Countries => app.net_offset = app.net_offset.saturating_sub(10),
                    KeyCode::PageDown => app.table.scroll_down_by(15),
                    KeyCode::PageUp => app.table.scroll_up_by(15),
                    KeyCode::Home | KeyCode::Char('g') => {
                        app.table.select_first();
                        app.net_offset = 0;
                    }
                    KeyCode::Enter => app.detail = !app.detail && app.current() == Tab::Offenders,
                    KeyCode::Char('u') => app.start_unban(),
                    KeyCode::Char('a') => app.start_allow(),
                    KeyCode::Char('p') => app.paused = !app.paused,
                    KeyCode::Char('z') if app.current() == Tab::Map => app.europe = !app.europe,
                    KeyCode::Char('r') => app.refresh(),
                    KeyCode::Char('s') => {
                        app.min_severity = match app.min_severity {
                            Severity::Info => Severity::Warning,
                            Severity::Warning => Severity::High,
                            Severity::High => Severity::Critical,
                            Severity::Critical => Severity::Info,
                        };
                        app.table.select(Some(0));
                    }
                    _ => {}
                }
            }
        }
        if app.source.live() && !app.paused && last.elapsed() >= Duration::from_secs(2) {
            last = Instant::now();
            app.refresh();
        }
    }
}

impl App {
    fn refresh(&mut self) {
        match self.source.load() {
            Ok(s) => {
                self.snap = Some(s);
                self.error = None;
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    /// The address/network under the cursor on the Offenders or Bans tab.
    fn selected_target(&self) -> Option<(crate::net::Net, bool)> {
        let snap = self.snap.as_ref()?;
        let i = self.table.selected()?;
        match self.current() {
            Tab::Offenders => snap.offenders.get(i).map(|v| v.banned_by.map_or((crate::net::Net::host(v.ip), false), |n| (n, true))),
            Tab::Bans => snap.bans.get(i).map(|b| (b.net, true)),
            _ => None,
        }
    }

    fn start_unban(&mut self) {
        match self.selected_target() {
            Some((net, true)) => {
                self.modal = Some(Modal::Confirm {
                    cmd: format!("unban {net}"),
                    text: format!("Unban {net} and forget its offence history?  y / n"),
                })
            }
            Some((net, false)) => self.flash = Some(format!("{net} is not banned")),
            None => self.flash = Some("select an address on the Offenders or Bans tab".into()),
        }
    }

    fn start_allow(&mut self) {
        match self.selected_target() {
            Some((net, _)) => self.modal = Some(Modal::Days { net, buf: "7".into() }),
            None => self.flash = Some("select an address on the Offenders or Bans tab".into()),
        }
    }

    fn modal_key(&mut self, key: KeyCode) {
        match (self.modal.take(), key) {
            (Some(Modal::Confirm { cmd, .. }), KeyCode::Char('y' | 'Y')) => self.run(&cmd),
            (Some(Modal::Days { net, mut buf }), k) => match k {
                KeyCode::Char(c) if c.is_ascii_digit() && buf.len() < 4 => {
                    buf.push(c);
                    self.modal = Some(Modal::Days { net, buf });
                }
                KeyCode::Backspace => {
                    buf.pop();
                    self.modal = Some(Modal::Days { net, buf });
                }
                KeyCode::Enter => match buf.parse::<i64>() {
                    Ok(days) if days > 0 => self.run(&format!("allow {net} {} allowlisted from the TUI", days * 86_400)),
                    _ => self.flash = Some("enter a number of days".into()),
                },
                KeyCode::Esc => {}
                _ => self.modal = Some(Modal::Days { net, buf }),
            },
            _ => self.flash = Some("cancelled".into()),
        }
    }

    fn run(&mut self, cmd: &str) {
        let DataSource::Socket(path) = &self.source else {
            self.flash = Some("read-only: this is a saved snapshot".into());
            return;
        };
        self.flash = Some(match crate::daemon::control_command(path, cmd) {
            Ok(reply) => reply.lines().filter(|l| *l != "ok").collect::<Vec<_>>().join(" | "),
            Err(e) => format!("error: {e:#}"),
        });
        self.refresh();
    }

    fn current(&self) -> Tab {
        self.tabs[self.tab.min(self.tabs.len() - 1)]
    }

    fn switch(&mut self, tab: usize) {
        self.tab = tab;
        self.detail = false;
        self.table.select(Some(0));
        self.net_offset = 0;
    }
}

fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::new().fg(Color::LightRed),
        Severity::Warning => Style::new().fg(Color::Yellow),
        Severity::Info => Style::new().fg(Color::Gray),
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

fn block(title: impl Into<String>) -> Block<'static> {
    Block::bordered().border_type(BorderType::Rounded).title(Span::styled(format!(" {} ", title.into()), Style::new().bold()))
}

fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([Constraint::Length(3), Constraint::Min(5), Constraint::Length(1)]).areas(f.area());

    let tabs = Tabs::new(app.tabs.iter().enumerate().map(|(i, t)| format!("{} {}", i + 1, t.title())))
        .select(app.tab)
        .highlight_style(Style::new().fg(Color::Cyan).bold().reversed())
        .block(block("logguard"));
    f.render_widget(tabs, header);

    let status = match (&app.snap, &app.error) {
        _ if app.flash.is_some() => {
            Line::from(Span::styled(format!(" {}", app.flash.clone().unwrap_or_default()), Style::new().fg(Color::Yellow)))
        }
        (_, Some(e)) => Line::from(Span::styled(format!(" error: {e}"), Style::new().fg(Color::Red))),
        (Some(s), None) => {
            let src = match (&app.source, app.paused) {
                (DataSource::Socket(_), false) => "live",
                (DataSource::Socket(_), true) => "live (paused)",
                (DataSource::File(_), _) => "file",
                (DataSource::Actions(..), _) => "decision log, read-only",
            };
            let keys = if matches!(app.source, DataSource::Actions(..)) {
                format!("q quit  1-{} tabs  ↑↓ select  s severity≥{:?}  r reload", app.tabs.len(), app.min_severity)
            } else {
                format!(
                    "q quit  1-{} tabs  ↑↓ select  enter details  u unban  a allow  s severity≥{:?}  p pause  r refresh",
                    app.tabs.len(),
                    app.min_severity
                )
            };
            Line::from(format!(" {src} | mode {:?} | at {} | {keys}", s.mode, fmt_ts(s.generated)))
        }
        (None, None) => Line::from(" loading…"),
    };
    f.render_widget(Paragraph::new(status).style(Style::new().fg(Color::DarkGray)), footer);

    if app.snap.is_none() {
        return;
    }
    if let Some(m) = &app.modal {
        let (title, text) = match m {
            Modal::Confirm { text, .. } => ("Confirm", text.clone()),
            Modal::Days { net, buf } => ("Allowlist", format!("Never ban {net} for how many days? {buf}_   (enter / esc)")),
        };
        let area = centered(f.area(), 60, 20);
        f.render_widget(Clear, area);
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(block(title)), area);
        return;
    }
    // Borrow the snapshot out of `app` instead of cloning it on every frame.
    let Some(snap) = app.snap.take() else { return };
    match app.current() {
        Tab::Overview => match &snap.actions_log {
            Some(log) => draw_log_overview(f, body, &snap, log),
            None => draw_overview(f, body, &snap),
        },
        Tab::Offenders => draw_offenders(f, body, app, &snap),
        Tab::Bans => draw_bans(f, body, app, &snap),
        Tab::Events => draw_events(f, body, app, &snap),
        Tab::Accounts => draw_accounts(f, body, app, &snap),
        Tab::Exposure => draw_exposure(f, body, app, &snap),
        Tab::Countries => draw_countries(f, body, app, &snap),
        Tab::Map => draw_map(f, body, &snap, app.europe),
        Tab::Trends => {
            if let Some(log) = &snap.actions_log {
                draw_trends(f, body, app, log);
            }
        }
    }
    app.snap = Some(snap);
}

fn draw_overview(f: &mut Frame, area: Rect, s: &Snapshot) {
    let [top, spark, bottom] = Layout::vertical([Constraint::Length(8), Constraint::Length(8), Constraint::Min(4)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

    let st = &s.stats;
    let uptime = if s.started > 0 { fmt_duration(s.generated - s.started) } else { "-".into() };
    let lines = vec![
        Line::from(vec!["Active bans:   ".into(), Span::styled(s.bans.len().to_string(), Style::new().fg(Color::Red).bold())]),
        Line::from(format!("Bans / alerts: {} / {} (total)", st.bans, st.alerts)),
        Line::from(format!("Tracked:       {} addresses, {} XMPP logins pending", s.tracked_ips, s.tracked_connections)),
        Line::from(format!("Trusted:       {} recently authenticated addresses", s.trusted.len())),
        Line::from(format!("Uptime:        {uptime}   unattributed lines: {}", st.unattributed)),
        match &s.cluster {
            Some(c) => {
                let ok = c.peers.iter().filter(|p| p.last_error.is_none() && p.last_ok.is_some()).count();
                let style = if ok == c.peers.len() { Style::new().fg(Color::Green) } else { Style::new().fg(Color::Yellow) };
                Line::from(vec![
                    "Cluster:       ".into(),
                    Span::styled(format!("{} - {ok}/{} peers ok", c.node_id, c.peers.len()), style),
                    format!(", {} facts, heard from {}", c.facts_known, c.heard_from.len()).into(),
                ])
            }
            None => Line::from("Cluster:       off"),
        },
    ];
    f.render_widget(Paragraph::new(lines).block(block("Status")), left);

    let rows: Vec<Row> = LogSource::ALL
        .iter()
        .map(|src| {
            let recs = st.records.get(src).copied().unwrap_or(0);
            let evs: u64 = st.events.iter().filter(|(sig, _)| sig.source() == *src).map(|(_, n)| n).sum();
            let top = st
                .events
                .iter()
                .filter(|(sig, _)| sig.source() == *src && !sig.is_success())
                .max_by_key(|(_, n)| **n)
                .map(|(sig, n)| format!("{} ({n})", sig.name()))
                .unwrap_or_default();
            Row::new(vec![src.name().to_string(), recs.to_string(), evs.to_string(), top])
        })
        .collect();
    let t = Table::new(rows, [Constraint::Length(9), Constraint::Length(9), Constraint::Length(8), Constraint::Min(10)])
        .header(Row::new(["source", "records", "events", "most frequent"]).bold())
        .block(block("Sources"));
    f.render_widget(t, right);

    let width = spark.width.saturating_sub(2) as usize;
    let hist: Vec<u64> = st.history.iter().map(|b| u64::from(b.events.iter().sum::<u32>())).collect();
    let data: Vec<u64> = hist[hist.len().saturating_sub(width)..].to_vec();
    let peak = data.iter().max().copied().unwrap_or(0);
    let title = format!("Events per minute (last {} min, peak {peak})", data.len());
    f.render_widget(Sparkline::default().data(&data).style(Style::new().fg(Color::Cyan)).block(block(&title)), spark);

    draw_latest(f, bottom, s);
}

fn draw_latest(f: &mut Frame, area: Rect, s: &Snapshot) {
    let rows: Vec<Row> = s
        .recent
        .iter()
        .filter(|a| a.kind != ActionKind::Unban)
        .take(area.height as usize)
        .map(|a| {
            Row::new(vec![
                Cell::from(fmt_ts(a.ts)),
                Cell::from(format!("{:?}", a.kind).to_uppercase()).style(severity_style(a.severity)),
                Cell::from(a.message.clone()),
            ])
        })
        .collect();
    let t = Table::new(rows, [Constraint::Length(19), Constraint::Length(6), Constraint::Min(20)]).block(block("Latest decisions"));
    f.render_widget(t, area);
}

/// Overview of a decision log: what it covers, how many bans of which kind, bans per hour.
fn draw_log_overview(f: &mut Frame, area: Rect, s: &Snapshot, log: &crate::actions_view::LogSummary) {
    let [top, spark, bottom] = Layout::vertical([Constraint::Length(9), Constraint::Length(8), Constraint::Min(4)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    let peers: u32 = log.bans_peer.values().sum();
    let places = if log.geo_db { "geo database" } else { "ban messages (no geo database)" };
    let mut lines = vec![
        Line::from(format!("{}{}", if log.files > 1 { "Files:         " } else { "File:          " }, log.file)),
        Line::from(format!("Period:        {} - {} ({})", fmt_ts(log.from), fmt_ts(log.to), fmt_duration(log.to - log.from))),
        Line::from(format!("Decisions:     {} ({} bans, {} unbans, {} alerts)", log.decisions, s.stats.bans, log.unbans, log.alerts)),
        Line::from(vec![
            "Active at end: ".into(),
            Span::styled(s.bans.len().to_string(), Style::new().fg(Color::Red).bold()),
            format!(" bans, {} sources banned in the period", s.tracked_ips).into(),
        ]),
        Line::from(format!("Places from:   {places}")),
    ];
    if log.duplicates > 0 {
        lines.push(Line::from(format!("Merged:        {} duplicate decisions counted once (peer copies, repeated lines)", log.duplicates)));
    }
    if log.unreadable > 0 {
        lines.push(Line::from(Span::styled(
            format!("Skipped:       {} lines that aren't decisions of this version", log.unreadable),
            Style::new().fg(Color::Yellow),
        )));
    }
    f.render_widget(Paragraph::new(lines).block(block("Decision log")), left);

    let here = if log.files > 1 { "decided by these servers" } else { "decided here" };
    let mut rows: Vec<Row> = vec![Row::new(vec![here.to_string(), log.bans_local.to_string()]).bold()];
    let mut cats: Vec<(&String, &u32)> = log.categories.iter().collect();
    cats.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    rows.extend(cats.iter().map(|(c, n)| Row::new(vec![format!("  {c}"), n.to_string()])));
    rows.extend(log.bans_peer.iter().map(|(p, n)| Row::new(vec![format!("from peer {p}"), n.to_string()])));
    if log.reinstated > 0 {
        rows.push(Row::new(vec!["reinstated".to_string(), log.reinstated.to_string()]));
    }
    let t = Table::new(rows, [Constraint::Min(20), Constraint::Length(8)])
        .header(Row::new(["bans", "count"]).bold())
        .block(block(format!("Bans: {} here, {peers} from peers", log.bans_local)));
    f.render_widget(t, right);

    let width = spark.width.saturating_sub(2) as usize;
    let data: Vec<u64> = log.bans_per_hour[log.bans_per_hour.len().saturating_sub(width)..].to_vec();
    let peak = data.iter().max().copied().unwrap_or(0);
    let title = format!("Bans per hour (last {} h, peak {peak})", data.len());
    f.render_widget(Sparkline::default().data(&data).style(Style::new().fg(Color::Cyan)).block(block(&title)), spark);

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
            "Bans per day, {} - {} ({} days, peak {peak}, average {:.0})",
            date(a.day),
            date(b.day),
            days.len(),
            f64::from(total) / days.len() as f64
        ),
        _ => "Bans per day".into(),
    };
    let chart = BarChart::default()
        .bar_width(bar_width)
        .bar_gap(gap)
        .bar_style(Style::new().fg(Color::Red))
        .value_style(Style::new().fg(Color::White).bold())
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
    let partial = "the first and last weeks may be partial";
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
    .block(block(format!("Weeks, newest first ({partial})")));
    f.render_stateful_widget(t, table_area, &mut app.table);
}

fn top_signals(counts: &std::collections::BTreeMap<Signal, u64>, n: usize) -> String {
    let mut v: Vec<(&Signal, &u64)> = counts.iter().filter(|(s, _)| !s.is_success()).collect();
    v.sort_by(|a, b| b.1.cmp(a.1));
    v.iter().take(n).map(|(s, c)| format!("{c}×{}", s.name())).collect::<Vec<_>>().join(" ")
}

fn draw_offenders(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let rows: Vec<Row> = s
        .offenders
        .iter()
        .map(|v| {
            let status = match (&v.banned_by, &v.protected) {
                (Some(n), _) => {
                    let left = v.banned_until.map(|u| fmt_duration(u - s.generated)).unwrap_or_default();
                    Cell::from(format!("banned {n} {left}")).style(Style::new().fg(Color::Red))
                }
                (None, Some(p)) => Cell::from(p.clone()).style(Style::new().fg(Color::Green)),
                _ => Cell::from(""),
            };
            Row::new(vec![
                Cell::from(v.ip.to_string()),
                Cell::from(format!("{:>5.0}%", v.danger)).style(danger_style(v.danger)),
                Cell::from(format!("{:>5.0}", v.fast)),
                Cell::from(format!("{:>5.0}", v.slow)),
                Cell::from(fmt_ts(v.last_seen)[5..].to_string()),
                status,
                Cell::from(v.geo.clone().unwrap_or_default()),
                Cell::from(top_signals(&v.counts, 3)),
            ])
        })
        .collect();
    let n = rows.len();
    let t = Table::new(
        rows,
        [
            Constraint::Length(26),
            Constraint::Length(7),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(15),
            Constraint::Length(30),
            Constraint::Length(if s.offenders.iter().any(|v| v.geo.is_some()) { 34 } else { 0 }),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(["address", "danger", "fast", "slow", "last seen", "status", "where", "signals"]).bold())
    .row_highlight_style(Style::new().reversed())
    .block(block(format!("Offenders ({n}) - enter evidence, u unban, a allowlist")));
    f.render_stateful_widget(t, area, &mut app.table);

    if app.detail {
        if let Some(v) = app.table.selected().and_then(|i| s.offenders.get(i)) {
            let popup = centered(area, 90, 70);
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(v.ip.to_string(), Style::new().bold()),
                    format!("   danger {:.0}%  peak {:.0}", v.danger, v.peak).into(),
                ]),
                Line::from(v.geo.clone().unwrap_or_default()),
                Line::from(format!("first seen {}   last seen {}", fmt_ts(v.first_seen), fmt_ts(v.last_seen))),
                Line::from(format!("signals: {}", top_signals(&v.counts, 10))),
                Line::from(""),
                Line::from("evidence (latest last):".bold()),
            ];
            lines.extend(v.evidence.iter().map(|e| Line::from(format!("  {e}"))));
            f.render_widget(Clear, popup);
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block("Details - esc to close")), popup);
        }
    }
}

fn draw_bans(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
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
    let rows: Vec<Row> = s
        .bans
        .iter()
        .map(|b| {
            Row::new(vec![
                Cell::from(b.net.to_string()).style(if b.net.is_host() { Style::new() } else { Style::new().fg(Color::Magenta) }),
                Cell::from(format!("#{}", b.offence)),
                Cell::from(fmt_ts(b.since)[5..].to_string()),
                Cell::from(fmt_duration(b.until - s.generated)),
                Cell::from(b.reason.clone()),
            ])
        })
        .collect();
    let n = rows.len();
    let t = Table::new(
        rows,
        [Constraint::Length(22), Constraint::Length(4), Constraint::Length(15), Constraint::Length(9), Constraint::Min(20)],
    )
    .header(Row::new(["target", "off.", "since", "left", "reason"]).bold())
    .row_highlight_style(Style::new().reversed())
    .block(block(if s.actions_log.is_some() {
        format!("Active bans at the end of the log ({n})")
    } else {
        format!("Active bans ({n}) - u unban, a allowlist")
    }));
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_events(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let rows: Vec<Row> = s
        .recent
        .iter()
        .filter(|a| a.severity >= app.min_severity)
        .map(|a| {
            let tag = if a.applied || a.kind == ActionKind::Alert { "" } else { "~" };
            Row::new(vec![
                Cell::from(fmt_ts(a.ts)),
                Cell::from(format!("{tag}{:?}", a.kind).to_uppercase()).style(severity_style(a.severity)),
                Cell::from(format!("{:?}", a.severity).to_lowercase()).style(severity_style(a.severity)),
                Cell::from(a.message.clone()),
            ])
        })
        .collect();
    let n = rows.len();
    let legend = if s.mode == crate::config::Mode::Shadow {
        "message  (~ = shadow, not applied)"
    } else {
        "message  (~ = not applied: failed, expired, or decided in shadow mode)"
    };
    let t = Table::new(rows, [Constraint::Length(19), Constraint::Length(7), Constraint::Length(8), Constraint::Min(20)])
        .header(Row::new(["time", "action", "severity", legend]).bold())
        .row_highlight_style(Style::new().reversed())
        .block(block(format!("Decisions ({n}, severity ≥ {:?})", app.min_severity)));
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_accounts(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    let rows: Vec<Row> = s
        .accounts
        .iter()
        .map(|a| {
            let style = if a.under_attack { Style::new().fg(Color::Red).bold() } else { Style::new() };
            Row::new(vec![
                Cell::from(a.account.clone()).style(style),
                Cell::from(format!("{:.1}", a.failures)),
                Cell::from(a.ips.to_string()),
                Cell::from(if a.under_attack { "UNDER ATTACK" } else { "" }).style(style),
            ])
        })
        .collect();
    let t = Table::new(rows, [Constraint::Min(30), Constraint::Length(10), Constraint::Length(10), Constraint::Length(14)])
        .header(Row::new(["account", "failures", "addresses", ""]).bold())
        .row_highlight_style(Style::new().reversed())
        .block(block("Accounts with recent authentication failures"));
    f.render_stateful_widget(t, area, &mut app.table);
}

fn draw_exposure(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    use crate::exposure::Exposure;
    let Some(r) = &s.exposure else {
        f.render_widget(
            Paragraph::new("No exposure scan yet (enabled in [exposure], runs every minute on Linux).").block(block("Exposure")),
            area,
        );
        return;
    };
    let dead = r.dead_rules.len() as u16;
    let [table_area, dead_area] =
        Layout::vertical([Constraint::Min(5), Constraint::Length(if dead > 0 { dead + 2 } else { 0 })]).areas(area);
    let mut listeners = crate::exposure::for_display(&r.listeners);
    listeners.sort_by_key(|(_, l)| (!l.exposure.is_exposed(), l.exposure == Exposure::Local, l.key));
    let rows: Vec<Row> = listeners
        .iter()
        .map(|(name, l)| {
            let style = match l.exposure {
                Exposure::Docker | Exposure::Unfiltered => Style::new().fg(Color::Yellow),
                Exposure::Allowed => Style::new().fg(Color::Green),
                _ => Style::new().fg(Color::DarkGray),
            };
            let how = if l.dynamic { format!("{} (dynamic range)", l.exposure.describe()) } else { l.exposure.describe().to_string() };
            Row::new(vec![Cell::from(name.clone()), Cell::from(l.process.clone()), Cell::from(how).style(style)])
        })
        .collect();
    let ufw = match r.ufw_active {
        Some(true) => "ufw active",
        Some(false) => "ufw INACTIVE",
        None => "ufw not found",
    };
    let exposed = listeners.iter().filter(|(_, l)| l.exposure.is_exposed()).count();
    let t = Table::new(rows, [Constraint::Length(46), Constraint::Length(18), Constraint::Min(20)])
        .header(Row::new(["listener", "process", "reachable from the internet?"]).bold())
        .row_highlight_style(Style::new().reversed())
        .block(block(format!("Listeners: {exposed} exposed, {} total - {ufw} - scanned {}", listeners.len(), fmt_ts(r.scanned))));
    f.render_stateful_widget(t, table_area, &mut app.table);
    if dead > 0 {
        let lines: Vec<Line> =
            r.dead_rules.iter().map(|d| Line::from(format!("ufw allows {d} from anywhere, but nothing listens there"))).collect();
        f.render_widget(Paragraph::new(lines).style(Style::new().fg(Color::Yellow)).block(block("Dead firewall rules")), dead_area);
    }
}

const NO_GEO: &str = "No geo database loaded: set [geo] enabled = true to see countries and networks.";

/// Countries, most offenders first, under an "All countries" row; the port histogram and
/// the network list show whichever row is selected.
fn draw_countries(f: &mut Frame, area: Rect, app: &mut App, s: &Snapshot) {
    use crate::engine::PlaceStats;
    let w = &s.world;
    let [top, bottom] = Layout::vertical([Constraint::Percentage(55), Constraint::Min(5)]).areas(area);
    let [left, right] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
    let num = |n: u64| Cell::from(if n == 0 { String::new() } else { n.to_string() });
    let place_row = |p: &PlaceStats, first: String| {
        let style = if p.bans > 0 { Style::new().fg(Color::LightRed) } else { Style::new() };
        Row::new(vec![Cell::from(first), num(u64::from(p.bans)).style(style), num(u64::from(p.offenders)), num(p.events)])
    };

    // Row 0 is "All countries", row i the country i - 1.
    let mut sel = app.table.selected().unwrap_or(0);
    if let (true, Some(key)) = (sel == app.country_sel.0, &app.country_sel.1) {
        // cursor not moved since the last frame: keep showing the same country
        if let Some(i) = w.countries.iter().position(|c| &c.key == key) {
            sel = i + 1;
        }
    }
    let sel = sel.min(w.countries.len());
    app.table.select(Some(sel));
    app.country_sel = (sel, sel.checked_sub(1).and_then(|i| w.countries.get(i)).map(|c| c.key.clone()));
    let country = sel.checked_sub(1).and_then(|i| w.countries.get(i));
    let detail = country.and_then(|c| w.by_country.get(&c.key));
    let empty = crate::engine::CountryDetail::default();
    let (scope, isps, ports) = match country {
        Some(c) => (c.name.as_str(), &detail.unwrap_or(&empty).isps, &detail.unwrap_or(&empty).ports),
        None => ("all countries", &w.isps, &w.ports),
    };

    if w.geo {
        let total = PlaceStats {
            bans: w.countries.iter().map(|c| c.bans).sum(),
            offenders: w.countries.iter().map(|c| c.offenders).sum(),
            events: w.countries.iter().map(|c| c.events).sum(),
            ..Default::default()
        };
        let rows: Vec<Row> = std::iter::once(place_row(&total, "All countries".into()).bold())
            .chain(w.countries.iter().map(|c| place_row(c, format!("{} {}", c.key, c.name))))
            .collect();
        let unlocated = if w.unlocated > 0 { format!(", {} sources without location", w.unlocated) } else { String::new() };
        let t = Table::new(rows, [Constraint::Min(16), Constraint::Length(6), Constraint::Length(9), Constraint::Length(9)])
            .header(Row::new(["country", "bans", "offenders", "events"]).bold())
            .row_highlight_style(Style::new().reversed())
            .block(block(format!("Countries ({}): {} active bans{unlocated} - ↑↓ select", w.countries.len(), total.bans)));
        f.render_stateful_widget(t, left, &mut app.table);

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
    } else {
        f.render_widget(Paragraph::new(NO_GEO).wrap(Wrap { trim: true }).block(block("Countries")), left);
        f.render_widget(Paragraph::new(NO_GEO).wrap(Wrap { trim: true }).block(block("Networks")), bottom);
    }

    use ratatui::widgets::{Bar, BarChart, BarGroup};
    let fit = usize::from(right.height.saturating_sub(2));
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
            Bar::default().value(*n).label(Line::from(format!("{port:>5} {svc:<10}"))).text_value(n.to_string())
        })
        .collect();
    // Live counters are halved daily (kept across restarts); a log's counts cover its whole period.
    let span = if s.actions_log.is_some() { "over the log" } else { "halved daily" };
    let title = format!("Top {} ports probed from {scope} (TCP+UDP, {span})", bars.len());
    if bars.is_empty() {
        let text = format!("No probed ports from {scope} recently.");
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).block(block(title)), right);
        return;
    }
    let chart = BarChart::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .bar_width(1)
        .bar_gap(0)
        .bar_style(Style::new().fg(Color::Red))
        .value_style(Style::new().fg(Color::White).bold())
        .data(BarGroup::default().bars(&bars))
        .block(block(title));
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
    let inner = map_area.inner(ratatui::layout::Margin::new(1, 1));
    let dx = (east - west) / (f64::from(inner.width.max(1)) * 2.0);
    let dy = (north - south) / (f64::from(inner.height.max(1)) * 4.0);

    let mut banned: Vec<(&crate::engine::PlaceStats, (f64, f64))> =
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
    let labels: Vec<(f64, f64, String)> = banned
        .iter()
        .filter(|(_, (lat, lon))| (west..=east).contains(lon) && (south..=north).contains(lat))
        .take(if europe { 30 } else { 10 })
        .map(|(c, (lat, lon))| {
            let h = (3.0 + 3.0 * f64::from(c.bans).ln()).min(16.0);
            (lon + (h / 2.0 + 2.0) * dx, *lat, c.key.clone())
        })
        .collect();
    // Only what is drawn; bans in countries without a known capital are mentioned apart.
    let bans: u32 = banned.iter().map(|(c, _)| c.bans).sum();
    let off_map: u32 = w.countries.iter().map(|c| c.bans).sum::<u32>() - bans;
    let off_map = if off_map > 0 { format!(" (+{off_map} not on the map)") } else { String::new() };
    let logged: u32 = w.logged_in.values().sum();
    // a decision log has no logins
    let logins = if s.actions_log.is_some() { String::new() } else { format!("   ● {logged} addresses logged in during the last hour") };
    let canvas = Canvas::default()
        .block(block(format!(
            "{}: ▲ {bans} active bans in {} countries{off_map}{logins}   (z: {})",
            if europe { "Europe" } else { "Map" },
            banned.len(),
            if europe { "world" } else { "zoom on Europe" }
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

fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let [_, v, _] = Layout::vertical([
        Constraint::Percentage((100 - pct_y) / 2),
        Constraint::Percentage(pct_y),
        Constraint::Percentage((100 - pct_y) / 2),
    ])
    .areas(area);
    let [_, h, _] = Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .areas(v);
    h
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

    #[test]
    fn every_tab_renders() {
        let mut pipe = Pipeline::new(Arc::new(Config::default()), 0);
        let mut years = YearGuess::new(2026);
        for (i, ip) in ["11.42.40.218", "11.42.40.218", "11.42.40.218", "9.9.9.9"].iter().enumerate() {
            let pid = format!("0.{i}.0");
            for line in [
                format!("Aug 16 21:53:5{i} h ejabberdctl[1]: 2026-08-16 21:53:5{i}.000 [info] (#PID<{pid}>) Accepted connection [::ffff:{ip}]:1 -> [::ffff:11.17.39.236]:5223"),
                format!("Aug 16 21:53:5{i} h ejabberdctl[1]: 2026-08-16 21:53:5{i}.100 [info] (tls|<{pid}>) Failed to secure c2s connection: TLS failed: SSL_do_handshake failed: error:0A000102:SSL routines::unsupported protocol"),
            ] {
                pipe.feed(&parse_syslog_line(&line, &mut years).unwrap());
            }
        }
        let mut snap = pipe.snapshot(50);
        assert!(!snap.bans.is_empty());
        let key = |port| crate::exposure::ListenerKey { proto: crate::event::Proto::Tcp, addr: "0.0.0.0".parse().unwrap(), port };
        let owners = [(1u64, "sshd".to_string()), (2, "docker-proxy".to_string())].into();
        snap.exposure = Some(crate::exposure::build_report(0, vec![(key(22), 1), (key(51821), 2)], &owners, Some("Status: active\n\nTo  Action  From\n--  ------  ----\n22/tcp                     ALLOW       Anywhere\n53/udp                     ALLOW       Anywhere\n"), &[]));
        snap.cluster = Some(crate::cluster::ClusterView { node_id: "xmpp".into(), ..Default::default() });
        let mut app = App {
            tabs: &ALL_TABS,
            modal: None,
            flash: None,
            source: DataSource::File("unused".into()),
            snap: Some(snap),
            error: None,
            tab: 0,
            table: TableState::default().with_selected(0),
            detail: false,
            paused: false,
            min_severity: Severity::Info,
            europe: false,
            net_offset: 0,
            country_sel: (0, None),
        };
        for (w, h) in [(140, 40), (60, 15)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in 0..app.tabs.len() {
                app.switch(tab);
                app.detail = tab == 1;
                term.draw(|f| draw(f, &mut app)).unwrap();
            }
        }
        app.switch(1);
        let mut term = Terminal::new(TestBackend::new(140, 30)).unwrap();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("11.42.40.218"));
        assert!(text.contains("banned"));
        app.switch(2);
        app.start_unban();
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Unban 11.42.40.218"), "confirm dialog");
        app.modal_key(KeyCode::Char('y'));
        assert_eq!(app.flash.as_deref(), Some("read-only: this is a saved snapshot"));
        app.start_allow();
        app.modal_key(KeyCode::Backspace);
        app.modal_key(KeyCode::Char('3'));
        assert!(matches!(&app.modal, Some(Modal::Days { buf, .. }) if buf == "3"));
        app.modal_key(KeyCode::Esc);
        assert!(app.modal.is_none());
        app.flash = None;

        app.switch(5);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("published by docker, bypasses ufw"), "exposure tab");
        assert!(text.contains("ufw allows 53/udp"), "dead rule shown");

        let place = |key: &str, name: &str, bans, offenders| crate::engine::PlaceStats {
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
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("CN China") && text.contains("Chinanet") && text.contains("Telnet"), "countries tab");
        assert!(text.contains("All countries") && text.contains("Networks in all countries"), "all countries first");
        app.table.select(Some(2)); // CN, DE, ZZ after "All countries"
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Networks in Germany (1)") && text.contains("Hetzner") && !text.contains("Chinanet"), "networks follow");
        assert!(text.contains("ports probed from Germany") && text.contains("RDP") && !text.contains("Telnet"), "ports follow");
        app.table.select(Some(1)); // CN: no detail sent
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("No probed ports from China") && text.contains("Networks in China (0)"));
        // a refresh re-sorts the countries: the cursor stays on Germany, not on row 2
        app.table.select(Some(2));
        term.draw(|f| draw(f, &mut app)).unwrap();
        if let Some(snap) = app.snap.as_mut() {
            snap.world.countries.swap(0, 1);
        }
        term.draw(|f| draw(f, &mut app)).unwrap();
        assert_eq!(app.table.selected(), Some(1));
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Networks in Germany"), "selection follows the country");
        app.table.select(Some(0));
        if let Some(snap) = app.snap.as_mut() {
            snap.world.isps = (1..=40).map(|i| place(&format!("AS{i}"), &format!("Net{i}"), 0, 1)).collect();
        }
        let mut small = Terminal::new(TestBackend::new(120, 30)).unwrap();
        small.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = small.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Networks in all countries 1-") && text.contains("of 40 (PgUp/PgDn)"), "partial list says so");
        app.net_offset = 1000;
        small.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = small.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("-40 of 40") && text.contains("Net40 "), "clamped to the last page");
        app.switch(7);
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("123 active bans in 2 countries (+1 not on the map)"), "unknown capitals aren't drawn");
        assert!(text.contains("UA 3") && text.contains("CN 120"), "legend");
        app.europe = true;
        term.draw(|f| draw(f, &mut app)).unwrap();
        let text: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Europe: ▲") && text.contains("DE"), "zoomed on Europe, German label shown");
        assert!(!text.contains("CN▲") && text.contains("(z: world)"));
    }

    #[test]
    fn decision_log_tabs() {
        let path = std::env::temp_dir().join(format!("lg-actions-{}.jsonl", std::process::id()));
        let h = 3600 * crate::time::SEC;
        std::fs::write(
            &path,
            format!(
                "{}\nnot json\n{}\n",
                format_args!(r#"{{"ts":{h},"kind":"ban","severity":"high","target":"5.9.1.1","until":{},"message":"ban 5.9.1.1 [Germany / Hetzner Online GmbH (AS24940)] for 2h (offence #1): burst [1x fw_tripwire]","evidence":["10-12 10:00:00 tripwire block TCP/23"],"applied":true,"category":"tripwire"}}"#, 3 * h),
                format_args!(r#"{{"ts":{},"kind":"ban","severity":"high","target":"1.0.0.1","until":{},"message":"ban 1.0.0.1 for 59m (from peer vpn): x","applied":true,"category":"from peers"}}"#, h + 1, 2 * h),
            ),
        )
        .unwrap();
        let source = DataSource::Actions(vec![path.clone()], None);
        let snap = source.load().unwrap();
        let _ = std::fs::remove_file(&path);
        let mut app = App {
            tabs: &LOG_TABS,
            modal: None,
            flash: None,
            source,
            snap: Some(snap),
            error: None,
            tab: 0,
            table: TableState::default().with_selected(0),
            detail: false,
            paused: false,
            min_severity: Severity::Info,
            europe: false,
            net_offset: 0,
            country_sel: (0, None),
        };
        let mut term = Terminal::new(TestBackend::new(160, 45)).unwrap();
        let mut texts = vec![];
        for tab in 0..app.tabs.len() {
            app.switch(tab);
            term.draw(|f| draw(f, &mut app)).unwrap();
            texts.push(term.backend().buffer().content().iter().map(|c| c.symbol()).collect::<String>());
        }
        let t = &texts[0];
        assert!(
            t.contains("1 Overview") && t.contains("5 Map") && !t.contains("Offenders") && !t.contains("Exposure"),
            "only what a log can show"
        );
        assert!(t.contains("Decision log") && t.contains("2 bans") && t.contains("Skipped:       1 lines"), "{t}");
        assert!(t.contains("from peer vpn") && t.contains("tripwire") && t.contains("decision log, read-only"));
        assert!(texts[1].contains("Active bans at the end of the log (2)"), "both still active at the end (1h+1s)");
        assert!(texts[3].contains("DE Germany") && texts[3].contains("Telnet"), "countries from the ban message label");
        assert!(texts[4].contains("active bans in 1 countries") && !texts[4].contains("logged in"), "no login data in a log");
        assert!(!texts[4].contains("● users"));
        assert!(texts[5].contains("Bans per day, 1970-01-01 - 1970-01-01 (1 days, peak 2"), "{}", texts[5]);
        assert!(texts[5].contains("1970-01-01") && texts[5].contains("Germany 1") && texts[5].contains("Hetzner Online GmbH (AS24940) 1"));
        // small terminals don't panic
        for (w, h) in [(60, 15), (20, 6)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &mut app)).unwrap();
        }
    }
}
