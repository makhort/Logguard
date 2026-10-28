//! logguard's snapshot (what its dashboard shows, `engine::Snapshot` there), as the console
//! keeps it: a JSON object read without knowing logguard's types, so a node running an older
//! or newer logguard still shows what it has.
//!
//! Its lists can be long: every active ban is in it, and a flood leaves hundreds of
//! thousands. [`trim`] keeps the newest or first few of each long list while it parses, so
//! memory follows what is kept, not what was sent, and counts the rest. The active bans are
//! also counted by where they were decided and what they cover, all of them ([`BanTally`]).

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result};
use serde::de::{DeserializeSeed, IgnoredAny, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

/// Which of a list's entries are kept.
#[derive(Clone, Copy, Debug)]
enum Keep {
    /// The first ones (logguard already ranks the list).
    First,
    /// Those with the highest value of this field (a time: the newest).
    Newest(&'static str),
}

/// The long lists and how many entries of each are kept.
const LISTS: &[(&str, usize, Keep)] = &[
    ("bans", 3000, Keep::Newest("since")),
    ("recent", 500, Keep::Newest("ts")),
    ("alerts", 300, Keep::Newest("ts")),
    ("offenders", 300, Keep::First),
    ("accounts", 100, Keep::First),
    ("trusted", 300, Keep::First),
    ("allowed", 500, Keep::First),
    ("allow_hosts", 200, Keep::First),
    ("patterns", 200, Keep::First),
];

/// Active bans by origin ("local", or the peer node that decided it) and kind ("address" or
/// "network"), counted over the whole list, not only the entries kept.
pub type BanTally = BTreeMap<(String, String), usize>;

/// Origins counted apart; more fall into "other" (any key holder can name nodes).
const MAX_ORIGINS: usize = 64;

/// A trimmed snapshot.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub value: Map<String, Value>,
    /// The full length of each list that was cut.
    pub cut: BTreeMap<String, usize>,
    pub bans: BanTally,
}

impl Snapshot {
    /// The snapshot with how long its cut lists were, as `_cut`, and the ban tally as
    /// `_bans` (for the agent's reply and the API).
    pub fn to_value(&self) -> Value {
        let mut v = self.value.clone();
        if !self.cut.is_empty() {
            v.insert("_cut".into(), serde_json::to_value(&self.cut).unwrap_or_default());
        }
        let tally: Vec<Value> =
            self.bans.iter().map(|((origin, kind), n)| serde_json::json!({ "origin": origin, "kind": kind, "n": n })).collect();
        v.insert("_bans".into(), Value::Array(tally));
        Value::Object(v)
    }

    /// The full length of list `name`.
    pub fn len_of(&self, name: &str) -> usize {
        self.cut.get(name).copied().unwrap_or_else(|| self.value.get(name).and_then(Value::as_array).map_or(0, Vec::len))
    }
}

struct Capped<'t> {
    keep: usize,
    how: Keep,
    /// Counts every entry here (the bans).
    tally: Option<&'t mut BanTally>,
}

fn count(tally: &mut BanTally, ban: &Value) {
    let origin = match ban.get("origin").and_then(Value::as_str) {
        Some(o) => o.chars().filter(|c| !c.is_control()).take(64).collect(),
        None => "local".to_string(),
    };
    let kind = if ban.get("net").and_then(Value::as_str).is_some_and(|n| n.contains('/')) { "network" } else { "address" };
    let distinct = tally.keys().map(|(o, _)| o).collect::<std::collections::BTreeSet<_>>().len();
    let origin = if distinct >= MAX_ORIGINS && !tally.keys().any(|(o, _)| *o == origin) { "other".to_string() } else { origin };
    *tally.entry((origin, kind.to_string())).or_default() += 1;
}

fn order_key(v: &Value, field: &str) -> i64 {
    v.get(field).and_then(Value::as_i64).unwrap_or(i64::MIN)
}

impl<'de> Visitor<'de> for Capped<'_> {
    type Value = (Vec<Value>, usize);

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok((vec![], 0))
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut kept: Vec<Value> = Vec::new();
        let mut total = 0;
        match self.how {
            Keep::First => {
                while kept.len() < self.keep {
                    let Some(v) = seq.next_element::<Value>()? else { return Ok((kept, total)) };
                    kept.push(v);
                    total += 1;
                }
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    total += 1;
                }
            }
            Keep::Newest(field) => {
                let cut = |kept: &mut Vec<Value>, keep: usize| {
                    kept.sort_by_key(|v| std::cmp::Reverse(order_key(v, field)));
                    kept.truncate(keep);
                };
                while let Some(v) = seq.next_element::<Value>()? {
                    if let Some(t) = self.tally.as_deref_mut() {
                        count(t, &v);
                    }
                    kept.push(v);
                    total += 1;
                    if kept.len() >= 2 * self.keep.max(1) {
                        cut(&mut kept, self.keep);
                    }
                }
                cut(&mut kept, self.keep);
            }
        }
        Ok((kept, total))
    }
}

impl<'de> DeserializeSeed<'de> for Capped<'_> {
    type Value = (Vec<Value>, usize);

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

/// Parses a snapshot (a JSON object), keeping at most a few thousand entries of each long list.
pub fn trim(json: &str) -> Result<Snapshot> {
    let top: BTreeMap<String, &RawValue> = serde_json::from_str(json).context("not a logguard snapshot (a JSON object)")?;
    let mut out = Snapshot::default();
    let mut agents_tally: Option<BanTally> = None;
    for (name, raw) in top {
        if name == "_bans" {
            // an agent's tally of all its bans, taken over: its list was cut before it came here
            if let Ok(list) = serde_json::from_str::<Vec<Value>>(raw.get()) {
                let mut t = BanTally::new();
                for e in list.iter().take(4 * MAX_ORIGINS) {
                    if let (Some(o), Some(k), Some(n)) =
                        (e.get("origin").and_then(Value::as_str), e.get("kind").and_then(Value::as_str), e.get("n").and_then(Value::as_u64))
                    {
                        if matches!(k, "address" | "network") {
                            t.insert((o.chars().filter(|c| !c.is_control()).take(64).collect(), k.to_string()), n as usize);
                        }
                    }
                }
                agents_tally = Some(t);
            }
            continue;
        }
        if name == "_cut" {
            // an agent's own counts, taken over: its lists were cut before they came here
            if let Ok(cut) = serde_json::from_str::<BTreeMap<String, usize>>(raw.get()) {
                out.cut.extend(cut.into_iter().filter(|(k, _)| LISTS.iter().any(|(l, _, _)| l == k)));
            }
            continue;
        }
        let value = match LISTS.iter().find(|(l, _, _)| *l == name) {
            Some((_, keep, how)) => {
                let mut de = serde_json::Deserializer::from_str(raw.get());
                let tally = (name == "bans").then_some(&mut out.bans);
                let (kept, total) =
                    Capped { keep: *keep, how: *how, tally }.deserialize(&mut de).with_context(|| format!("snapshot field {name}"))?;
                if total > kept.len() {
                    let before = out.cut.get(&name).copied().unwrap_or(0);
                    out.cut.insert(name.clone(), total.max(before));
                }
                Value::Array(kept)
            }
            None => serde_json::from_str(raw.get()).with_context(|| format!("snapshot field {name}"))?,
        };
        out.value.insert(name, value);
    }
    if let Some(t) = agents_tally {
        out.bans = t;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lists_are_cut() {
        let bans: Vec<String> = (0..10_000)
            .map(|i| match i % 4 {
                0 => format!(r#"{{"net":"198.51.{}.0/24","since":{i},"until":1,"origin":"vpn"}}"#, i % 250),
                _ => format!(r#"{{"net":"192.0.2.{}","since":{i},"until":1}}"#, i % 250),
            })
            .collect();
        let offenders: Vec<String> = (0..1000).map(|i| format!(r#"{{"ip":"x","danger":{}}}"#, 1000 - i)).collect();
        let json = format!(
            r#"{{"mode":"enforce","bans":[{}],"offenders":[{}],"recent":[],"alerts":null,"world":{{"geo":true}}}}"#,
            bans.join(","),
            offenders.join(",")
        );
        let s = trim(&json).unwrap();
        let kept = s.value["bans"].as_array().unwrap();
        assert_eq!(kept.len(), 3000);
        assert_eq!(kept[0]["since"], 9999, "newest first");
        assert_eq!(kept[2999]["since"], 7000);
        assert_eq!(s.len_of("bans"), 10_000);
        assert_eq!(s.value["offenders"].as_array().unwrap().len(), 300);
        assert_eq!(s.value["offenders"][0]["danger"], 1000, "logguard's own order");
        assert_eq!(s.len_of("offenders"), 1000);
        assert_eq!(s.len_of("recent"), 0);
        assert_eq!(s.value["alerts"], Value::Array(vec![]));
        assert_eq!(s.value["world"]["geo"], true);
        let tally = |t: &BanTally, o: &str, k: &str| t.get(&(o.to_string(), k.to_string())).copied().unwrap_or(0);
        assert_eq!((tally(&s.bans, "local", "address"), tally(&s.bans, "vpn", "network")), (7500, 2500), "all bans, not the kept ones");
        // through an agent: its counts survive
        let again = trim(&serde_json::to_string(&s.to_value()).unwrap()).unwrap();
        assert_eq!(again.len_of("bans"), 10_000);
        assert_eq!(again.bans, s.bans);
        assert_eq!(again.value["bans"].as_array().unwrap().len(), 3000);
        assert!(!again.value.contains_key("_cut") && !again.value.contains_key("_bans"));
    }

    #[test]
    fn not_a_snapshot() {
        assert!(trim("[1,2]").is_err());
        assert!(trim(r#"{"bans": 5}"#).is_err());
        assert!(trim("error: daemon is stopping").is_err());
        let deep = format!("{{\"x\":{}{}}}", "[".repeat(1000), "]".repeat(1000));
        assert!(trim(&deep).is_err(), "nesting beyond serde_json's limit");
    }
}
