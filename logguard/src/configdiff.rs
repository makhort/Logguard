//! `logguard config-diff`: compares an installed configuration with this binary's
//! defaults, and optionally with the previous binary's defaults, so an upgrade needs
//! no manual merge with `logguard.toml.new`.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use toml::Value;

use crate::config::Config;
use crate::time::Dur;

/// Options still accepted so older files load, but ignored, and what replaced them.
const RETIRED: [(&str, &str); 2] = [
    ("subnets.wide_min_bad_ips", "subnet bans now grow step by step, see subnets.wide_max_step"),
    ("subnets.wide_min_subnets", "subnet bans now grow step by step, see subnets.wide_max_step"),
];

/// Dotted key (`scoring.weights.fw_block`) -> value. Arrays (including arrays of tables
/// such as `[[ratelimit]]`) are single values; empty tables are kept as values.
fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Table(t) if !t.is_empty() => {
            for (k, v) in t {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&key, v, out);
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

/// The same leaves with their real key paths (a key may itself contain a dot: `"abc.d"`).
fn leaves(path: &mut Vec<String>, v: &Value, out: &mut Vec<(Vec<String>, Value)>) {
    match v {
        Value::Table(t) if !t.is_empty() => {
            for (k, v) in t {
                path.push(k.clone());
                leaves(path, v, out);
                path.pop();
            }
        }
        _ => out.push((path.clone(), v.clone())),
    }
}

/// Whether this version rejects the option as unknown. The printed defaults can't decide
/// it alone: options unset by default (`notify.api`) have no TOML form, and free-form
/// tables (`[notify.languages]`) are empty. So the option is parsed on its own, and only an
/// unknown name counts (a bad value alone is not this report's business).
fn unknown_option(path: &[String], v: &Value) -> bool {
    let mut doc = v.clone();
    for k in path.iter().rev() {
        doc = Value::Table(toml::Table::from_iter([(k.clone(), doc)]));
    }
    // "unknown variant": a key of a table keyed by fixed names (`scoring.weights.fw_blok`).
    doc.try_into::<Config>().is_err_and(|e| {
        let e = e.to_string();
        e.contains("unknown field") || e.contains("unknown variant")
    })
}

fn flat(v: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    flatten("", v, &mut out);
    out
}

/// Equal as configuration values: `40` = `40.0`, `"10m"` = `"600s"` = `600`.
fn same(a: &Value, b: &Value) -> bool {
    let dur = |v: &Value| match v {
        Value::String(s) => s.parse::<Dur>().ok().map(|d| d.0),
        Value::Integer(n) => u64::try_from(*n).ok(),
        _ => None,
    };
    match (a, b) {
        (Value::Integer(x), Value::Float(y)) | (Value::Float(y), Value::Integer(x)) => (*x as f64 - y).abs() < 1e-9,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b)),
        (Value::Table(x), Value::Table(y)) => x.len() == y.len() && x.iter().all(|(k, a)| y.get(k).is_some_and(|b| same(a, b))),
        _ if a == b => true,
        _ => dur(a).is_some_and(|x| dur(b) == Some(x)) && (matches!(a, Value::String(_)) || matches!(b, Value::String(_))),
    }
}

fn show(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 100 {
        let cut = (0..=97).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0);
        format!("{}...", &s[..cut])
    } else {
        s
    }
}

pub struct DiffOpts {
    /// List every option the file doesn't set, not just new/changed ones.
    pub all: bool,
}

/// The report for `installed` (the config file's text). `old_defaults` is the output of the
/// previous binary's `print-config` without a config file; without it "new" and "changed"
/// can't be told apart from "never set", so only whole missing sections are listed.
pub fn diff(installed: &str, old_defaults: Option<&str>, opts: &DiffOpts) -> Result<String> {
    let mine: Value = installed.parse::<toml::Table>().context("parsing the installed config")?.into();
    let mut mine_paths = Vec::new();
    leaves(&mut Vec::new(), &mine, &mut mine_paths);
    let mine = flat(&mine);
    let cur = flat(&Value::try_from(Config::default())?);
    let old = match old_defaults {
        Some(text) => Some(flat(&text.parse::<toml::Table>().context("parsing the previous defaults")?.into())),
        None => None,
    };
    let mut out = String::new();
    let mut section = |title: &str, lines: Vec<String>| {
        if !lines.is_empty() {
            out += &format!("{title}\n");
            for l in lines {
                out += &format!("  {l}\n");
            }
            out += "\n";
        }
    };

    // Keys this version doesn't know (deny_unknown_fields: the daemon won't start).
    let unknown: Vec<String> = mine_paths
        .iter()
        .filter(|(p, v)| !cur.contains_key(&p.join(".")) && unknown_option(p, v))
        .map(|(p, v)| format!("{} = {}  (misspelled, or removed in this version)", p.join("."), show(v)))
        .collect();
    section("UNKNOWN options in your file - logguard refuses to start until they are fixed or removed:", unknown);
    let retired: Vec<String> = RETIRED.iter().filter_map(|(k, why)| mine.get(*k).map(|v| format!("{k} = {}  ({why})", show(v)))).collect();
    section("Options no longer used (ignored; you can remove them):", retired);

    if let Some(old) = &old {
        let new: Vec<String> = cur
            .iter()
            .filter(|(k, _)| !old.contains_key(*k))
            .map(|(k, v)| if mine.contains_key(k) { format!("{k} (already set in your file)") } else { format!("{k} = {}", show(v)) })
            .collect();
        section("New options in this version (defaults shown; add them to your file to change them):", new);
        let changed: Vec<String> = cur
            .iter()
            .filter_map(|(k, v)| {
                let was = old.get(k)?;
                if same(was, v) {
                    return None;
                }
                Some(match mine.get(k) {
                    Some(m) => format!("{k}: {} -> {}  (you set {}: unaffected)", show(was), show(v), show(m)),
                    None => format!("{k}: {} -> {}  (not in your file: the new default applies)", show(was), show(v)),
                })
            })
            .collect();
        section("Changed defaults:", changed);
        let removed: Vec<String> = old.keys().filter(|k| !cur.contains_key(*k) && !mine.contains_key(*k)).cloned().collect();
        section("Options removed in this version (not in your file, nothing to do):", removed);
    } else {
        let top = |k: &str| k.split('.').next().unwrap_or(k).to_string();
        let mut missing: BTreeMap<String, usize> = BTreeMap::new();
        for k in cur.keys().filter(|k| !mine.keys().any(|m| top(m) == top(k))) {
            *missing.entry(top(k)).or_default() += 1;
        }
        section(
            "Sections/options not in your file (built-in defaults apply; `logguard print-config` shows them):",
            missing.into_iter().map(|(s, n)| if n == 1 { s } else { format!("[{s}] ({n} options)") }).collect(),
        );
    }

    if opts.all {
        let unset: Vec<String> = cur.iter().filter(|(k, _)| !mine.contains_key(*k)).map(|(k, v)| format!("{k} = {}", show(v))).collect();
        section("All options not set in your file (current defaults):", unset);
        let redundant: Vec<String> =
            mine.iter().filter(|(k, v)| cur.get(*k).is_some_and(|d| same(v, d))).map(|(k, v)| format!("{k} = {}", show(v))).collect();
        section("Set to the default value anyway (could be removed):", redundant);
    }

    match Config::from_toml(installed) {
        Ok(_) => out += "Your file is valid for this version.\n",
        Err(e) => out += &format!("Your file is NOT valid for this version: {e:#}\n"),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_compare_like_config() {
        let v = |s: &str| s.parse::<toml::Table>().unwrap().remove("x").unwrap();
        assert!(same(&v("x = 40"), &v("x = 40.0")));
        assert!(same(&v("x = \"10m\""), &v("x = \"600s\"")));
        assert!(same(&v("x = 600"), &v("x = \"10m\"")));
        assert!(!same(&v("x = 600"), &v("x = 601")));
        assert!(!same(&v("x = \"a\""), &v("x = \"b\"")));
        assert!(same(&v("x = [1, \"2h\"]"), &v("x = [1.0, \"7200s\"]")));
    }

    #[test]
    fn report() {
        let old_defaults = {
            // the previous version: no [canary], a different default, a since-removed option
            let mut t: toml::Table = toml::to_string(&Config::default()).unwrap().parse().unwrap();
            t.remove("canary");
            t["scoring"]["weights"].as_table_mut().unwrap().insert("ssh_auth_fail".into(), Value::Float(34.0));
            t["scoring"]["weights"].as_table_mut().unwrap().insert("xmpp_auth_fail".into(), Value::Float(34.0));
            t["bans"].as_table_mut().unwrap().insert("old_knob".into(), Value::Boolean(true));
            let subnets = t["subnets"].as_table_mut().unwrap();
            subnets.remove("wide_max_step");
            subnets.insert("wide_min_bad_ips".into(), Value::Integer(12));
            subnets.insert("wide_min_subnets".into(), Value::Integer(4));
            toml::to_string(&t).unwrap()
        };
        let installed = r#"
mode = "enforce"
[scoring.weights]
xmpp_auth_fail = 30
[subnets]
min_bad_ip = 3
"#;
        let r = diff(installed, Some(&old_defaults), &DiffOpts { all: false }).unwrap();
        assert!(r.contains("subnets.min_bad_ip = 3  (misspelled"), "{r}");
        assert!(r.contains("  canary.xmpp = []\n"), "{r}");
        assert!(r.contains("scoring.weights.ssh_auth_fail: 34.0 -> 25.0  (not in your file: the new default applies)"), "{r}");
        assert!(r.contains("scoring.weights.xmpp_auth_fail: 34.0 -> 25.0  (you set 30: unaffected)"), "{r}");
        assert!(r.contains("Options removed in this version (not in your file, nothing to do):\n  bans.old_knob\n"), "{r}");
        assert!(!r.contains("mode"), "unchanged settings aren't listed: {r}");
        assert!(r.contains("NOT valid"), "{r}");

        // Valid options the printed defaults don't show: unset by default, free-form tables.
        let installed = "[notify]\napi = \"127.0.0.1:5285\"\napy = 1\n[notify.languages]\nalice = \"ru\"\n\"abc.d\" = \"ru\"\n";
        let r = diff(installed, Some(&old_defaults), &DiffOpts { all: false }).unwrap();
        assert!(r.contains("notify.apy = 1  (misspelled"), "{r}");
        let r = diff("[scoring.weights]\nfw_blok = 5\n", Some(&old_defaults), &DiffOpts { all: false }).unwrap();
        assert!(r.contains("scoring.weights.fw_blok = 5  (misspelled"), "{r}");
        assert!(!r.contains("notify.api =") && !r.contains("alice") && !r.contains("abc.d"), "{r}");

        // Retired options: still valid, reported as unused; not in the file, nothing to do.
        let r = diff("[subnets]\nwide_min_bad_ips = 12\n", Some(&old_defaults), &DiffOpts { all: false }).unwrap();
        assert!(
            r.contains("Options no longer used (ignored; you can remove them):\n  subnets.wide_min_bad_ips = 12  (subnet bans now grow"),
            "{r}"
        );
        assert!(
            r.contains("Options removed in this version (not in your file, nothing to do):\n  bans.old_knob\n  subnets.wide_min_subnets\n"),
            "{r}"
        );
        assert!(r.contains("subnets.wide_max_step = 2") && r.contains("Your file is valid"), "{r}");

        let r = diff("mode = \"enforce\"\n[canary]\nssh = [\"root\"]\n", None, &DiffOpts { all: true }).unwrap();
        assert!(r.contains("[scoring] ("), "{r}");
        assert!(!r.contains("[canary]"), "{r}");
        assert!(r.contains("All options not set in your file"), "{r}");
        assert!(r.contains("Your file is valid"), "{r}");
    }
}
