//! Persistent bot state: abuse reports and the bot allowlist, plus who created which
//! account with the former /create (kept in the file). The file format is the Python bot's: `[{user: entry}, [allowed jids]]`,
//! so an existing state file carries over unchanged.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub const DEFAULT_USER_CREATION_LIMIT: u64 = 5;
pub const ABUSER_THRESHOLD: usize = 5;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Entry {
    /// Accounts this user created: (username, Unix time).
    pub add: Vec<(String, f64)>,
    pub limit: u64,
    /// Users this user reported: username -> (Unix time, reason).
    pub abuse: IndexMap<String, (f64, String)>,
    /// The user's language code (see `i18n::Language` in the binary); absent: English. Older
    /// versions of the bot ignore the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
}

impl Entry {
    fn new(limit: u64) -> Self {
        Entry { add: Vec::new(), limit, abuse: IndexMap::new(), lang: None }
    }
}

/// Writes `bytes` to a new owner-only temporary file and renames it over `path`, so a
/// crash, a power loss or a full disk never leaves a truncated file behind.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.to_owned().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    // the rename itself survives a power loss only once the directory is on disk
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::File::open(dir).and_then(|d| d.sync_all()).with_context(|| format!("syncing {}", dir.display()))?;
    }
    Ok(())
}

/// What [`State::prune`] removed.
#[derive(Debug, Default, PartialEq)]
pub struct Pruned {
    /// Users' entries (language, reports they filed, accounts they created).
    pub entries: usize,
    /// Reports and created-account records inside the remaining entries.
    pub reports: usize,
    /// Bot access of deleted accounts.
    pub allowed: usize,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
struct Data(IndexMap<String, Entry>, Vec<String>);

#[derive(Debug)]
pub struct State {
    path: PathBuf,
    data: Data,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        let data = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("{}: not a valid state file", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(State { path: path.to_owned(), data })
    }

    fn save(&self) -> Result<()> {
        write_private(&self.path, &serde_json::to_vec(&self.data)?)
    }

    fn entries(&self) -> &IndexMap<String, Entry> {
        &self.data.0
    }

    /// Forgets a deleted account: its quota, its invites and the reports against it.
    pub fn remove_user(&mut self, who: &str) -> Result<()> {
        self.reset_abuse_reports(who)?;
        if self.data.0.shift_remove(who).is_some() {
            self.save()?;
        }
        Ok(())
    }

    /// Forgets what is no longer needed: entries of accounts that don't exist any more
    /// (ejabberd deletes inactive ones by itself), reports about or by them, reports older
    /// than `report_max_age` seconds, and bot access of deleted accounts of `domain`.
    pub fn prune(&mut self, exists: impl Fn(&str) -> bool, domain: &str, now: f64, report_max_age: f64) -> Result<Pruned> {
        let mut pruned = Pruned::default();
        let before = self.data.1.len();
        self.data.1.retain(|jid| match jid.rsplit_once('@') {
            Some((user, d)) if d.eq_ignore_ascii_case(domain) => exists(&user.to_lowercase()),
            _ => true,
        });
        pruned.allowed = before - self.data.1.len();
        let before = self.data.0.len();
        self.data.0.retain(|who, _| exists(who));
        pruned.entries = before - self.data.0.len();
        for entry in self.data.0.values_mut() {
            let before = entry.abuse.len() + entry.add.len();
            entry.abuse.retain(|target, (ts, _)| exists(target) && now - *ts < report_max_age);
            entry.add.retain(|(user, _)| exists(user));
            pruned.reports += before - entry.abuse.len() - entry.add.len();
        }
        if pruned != Pruned::default() {
            self.save()?;
        }
        Ok(pruned)
    }

    /// Records `who`'s report against `abuser`. Returns `None` when `who` already
    /// reported them, otherwise whether `abuser` has now reached [`ABUSER_THRESHOLD`].
    pub fn push_abuse_user(&mut self, who: &str, abuser: &str, reason: &str, now: f64) -> Result<Option<bool>> {
        let entry = self.data.0.entry(who.to_owned()).or_insert_with(|| Entry::new(DEFAULT_USER_CREATION_LIMIT));
        if entry.abuse.contains_key(abuser) {
            return Ok(None);
        }
        entry.abuse.insert(abuser.to_owned(), (now, reason.to_owned()));
        self.save()?;
        Ok(Some(self.reporters_for_abuser(abuser).len() >= ABUSER_THRESHOLD))
    }

    /// `who`'s own reports: (reported user, report time, reason).
    pub fn reports_by(&self, who: &str) -> Vec<(&str, f64, &str)> {
        self.entries().get(who).map(|e| e.abuse.iter().map(|(u, (ts, r))| (u.as_str(), *ts, r.as_str())).collect()).unwrap_or_default()
    }

    /// (reporter, report time)
    pub fn reporters_for_abuser(&self, abuser: &str) -> Vec<(&str, f64)> {
        self.entries().iter().filter_map(|(k, v)| v.abuse.get(abuser).map(|(ts, _)| (k.as_str(), *ts))).collect()
    }

    pub fn reset_abuse_reports(&mut self, abuser: &str) -> Result<()> {
        let mut updated = false;
        for v in self.data.0.values_mut() {
            updated |= v.abuse.shift_remove(abuser).is_some();
        }
        if updated {
            self.save()?;
        }
        Ok(())
    }

    /// The language code set for `who`, if any.
    pub fn language(&self, who: &str) -> Option<&str> {
        self.entries().get(who).and_then(|e| e.lang.as_deref())
    }

    pub fn set_language(&mut self, who: &str, code: &str) -> Result<()> {
        let entry = self.data.0.entry(who.to_owned()).or_insert_with(|| Entry::new(DEFAULT_USER_CREATION_LIMIT));
        if entry.lang.as_deref() != Some(code) {
            entry.lang = Some(code.to_owned());
            self.save()?;
        }
        Ok(())
    }

    pub fn allow_bot_access(&mut self, jid: &str) -> Result<()> {
        if !self.can_access_bot(jid) {
            self.data.1.push(jid.to_owned());
            self.save()?;
        }
        Ok(())
    }

    /// Also drops entries differing in case only (older bots stored names as typed).
    pub fn deny_bot_access(&mut self, jid: &str) -> Result<()> {
        let before = self.data.1.len();
        self.data.1.retain(|u| u.to_lowercase() != jid.to_lowercase());
        if self.data.1.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// `jid` lowercase; entries are compared ignoring case.
    pub fn can_access_bot(&self, jid: &str) -> bool {
        self.data.1.iter().any(|u| u.to_lowercase() == jid)
    }

    pub fn users_with_bot_access(&self) -> &[String] {
        &self.data.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state(name: &str) -> (PathBuf, State) {
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-test-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let _ = fs::remove_file(&path);
        let state = State::load(&path).unwrap();
        (path, state)
    }

    #[test]
    fn reads_the_python_bot_state_file() {
        let (path, _) = tmp_state("python");
        fs::write(
            &path,
            r#"[{"alice": {"add": [["bob", 1727630000.5]], "limit": 5, "abuse": {"eve": [1727630100.25, "Spam"]}},
                "zed": {"add": [], "limit": 0, "abuse": {}}},
               ["alice@example.org"]]"#,
        )
        .unwrap();
        let mut s = State::load(&path).unwrap();
        assert_eq!(s.reporters_for_abuser("eve"), vec![("alice", 1727630100.25)]);
        assert!(s.can_access_bot("alice@example.org"));

        // Saving keeps the format, and the order of entries.
        s.push_abuse_user("zed", "eve", "Spam too", 1727630200.0).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(v[0]["alice"]["add"][0], serde_json::json!(["bob", 1727630000.5]));
        assert_eq!(v[0]["alice"]["limit"], 5);
        assert_eq!(v[0]["alice"]["abuse"]["eve"], serde_json::json!([1727630100.25, "Spam"]));
        assert_eq!(v[1], serde_json::json!(["alice@example.org"]));
        let order: Vec<_> = v[0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(order, ["alice", "zed"]);
    }

    #[test]
    fn abuse_reports() {
        let (path, mut s) = tmp_state("abuse");

        for (i, who) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            assert_eq!(s.push_abuse_user(who, "eve", "spam", 2.0).unwrap(), Some(i == 4));
        }
        assert_eq!(s.push_abuse_user("a", "eve", "again", 3.0).unwrap(), None);
        s.reset_abuse_reports("eve").unwrap();
        assert!(s.reporters_for_abuser("eve").is_empty());

        s.push_abuse_user("a", "mallory", "spam", 4.0).unwrap();
        s.remove_user("a").unwrap();
        assert!(!s.data.0.contains_key("a"));
        assert_eq!(State::load(&path).unwrap().data, s.data);
    }

    #[test]
    fn allowlist() {
        let (_, mut s) = tmp_state("allow");
        s.allow_bot_access("bob@example.org").unwrap();
        s.allow_bot_access("bob@example.org").unwrap();
        assert_eq!(s.users_with_bot_access(), ["bob@example.org"]);
        s.deny_bot_access("bob@example.org").unwrap();
        assert!(!s.can_access_bot("bob@example.org"));
        // entries stored as typed by older bots
        s.data.1.push("John@example.org".into());
        assert!(s.can_access_bot("john@example.org"));
        s.deny_bot_access("john@example.org").unwrap();
        assert!(s.users_with_bot_access().is_empty());
    }

    #[test]
    fn pruning_forgets_deleted_accounts_and_old_reports() {
        let (path, mut s) = tmp_state("prune");
        s.allow_bot_access("alice@example.org").unwrap();
        s.allow_bot_access("gone@example.org").unwrap();
        s.allow_bot_access("friend@elsewhere.net").unwrap();
        s.set_language("gone", "FR").unwrap();
        s.push_abuse_user("alice", "gone", "spam", 1000.0).unwrap();
        s.push_abuse_user("alice", "eve", "old", 1000.0).unwrap();
        s.push_abuse_user("alice", "mallory", "recent", 9000.0).unwrap();
        let exists = |u: &str| ["alice", "eve", "mallory"].contains(&u);
        let pruned = s.prune(exists, "example.org", 10_000.0, 5000.0).unwrap();
        assert_eq!(pruned, Pruned { entries: 1, reports: 2, allowed: 1 });
        assert_eq!(s.users_with_bot_access(), ["alice@example.org", "friend@elsewhere.net"]);
        assert_eq!(s.language("gone"), None);
        assert_eq!(s.reporters_for_abuser("mallory"), vec![("alice", 9000.0)]);
        assert!(s.reporters_for_abuser("eve").is_empty(), "too old");
        assert_eq!(State::load(&path).unwrap().data, s.data, "saved");
        assert_eq!(s.prune(exists, "example.org", 10_000.0, 5000.0).unwrap(), Pruned::default(), "nothing left to do");
    }

    #[test]
    fn languages_are_kept_with_the_user() {
        let (path, mut s) = tmp_state("lang");
        assert_eq!(s.language("bob"), None);
        s.set_language("bob", "FR").unwrap();
        assert_eq!(State::load(&path).unwrap().language("bob"), Some("FR"));
        // entries without a language are written as before
        s.push_abuse_user("carol", "eve", "spam", 1.0).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(v[0]["bob"]["lang"], "FR");
        assert!(v[0]["carol"].get("lang").is_none());
        s.remove_user("bob").unwrap();
        assert_eq!(s.language("bob"), None);
    }
}
