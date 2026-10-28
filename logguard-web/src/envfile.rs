//! config.env, read the way systemd's `EnvironmentFile=` reads it, for the commands run by hand
//! (`check`, `passwd`, ...). Sourcing it in a shell instead (`set -a; . config.env`) goes wrong
//! on a list with blanks: `AGENT_ALLOW=192.0.2.1, 192.0.2.2` becomes a command named
//! `192.0.2.2` run with AGENT_ALLOW set for it alone, and the setting stays unset.

use std::path::Path;

/// The unit's settings file; `LOGGUARD_WEB_CONFIG` names another (empty: none).
pub const DEFAULT_PATH: &str = "/opt/logguard-web/config.env";

/// `KEY=value` lines as systemd reads them: the value is the rest of the line, blanks inside
/// included, trimmed at both ends; a value in double or single quotes loses them (`\"` and
/// `\\` inside double quotes are a quote and a backslash). A line ending in a backslash goes
/// on in the next. Lines starting with `#` or `;`, and lines that aren't `KEY=value` with a
/// valid name, are skipped. A name set twice keeps the last value, as in systemd.
pub fn parse(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut joined = String::new();
    for raw in text.lines() {
        if let Some(head) = raw.strip_suffix('\\') {
            joined.push_str(head);
            continue;
        }
        joined.push_str(raw);
        let line = std::mem::take(&mut joined);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        let valid = key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            continue;
        }
        let value = unquote(value.trim());
        out.retain(|(k, _)| k != key);
        out.push((key.to_string(), value));
    }
    out
}

fn unquote(v: &str) -> String {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut s = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match (c, chars.clone().next()) {
                ('\\', Some(n @ ('"' | '\\'))) => {
                    s.push(n);
                    chars.next();
                }
                _ => s.push(c),
            }
        }
        s
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// Sets the file's variables that the environment doesn't have yet (the environment wins: the
/// service already has the same file from systemd, and an `export` for a test overrides it).
/// Returns how many it set, or None without a readable file. Call before any thread starts.
pub fn load(path: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut set = 0;
    for (k, v) in parse(&text) {
        if std::env::var_os(&k).is_none() {
            std::env::set_var(&k, v);
            set += 1;
        }
    }
    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_lines_like_systemd() {
        let text = "# comment\n; also one\nAGENT_ALLOW=192.0.2.1, 192.0.2.2, 198.51.100.0/24\n\
                    NODES = \"a.example:7949, b.example:7949\"\n  CONSOLE_ALLOW='any'\n\
                    TLS_CERT=/opt/x/tls.crt  \nEMPTY=\nQUOTE=\"say \\\"hi\\\" \\\\ there\"\n\
                    LONG=one, \\\ntwo\nbad name=x\n1BAD=x\nno equals sign\nAGENT_LISTEN=0.0.0.0:7949\nAGENT_LISTEN=127.0.0.1:7949\n";
        let got = parse(text);
        let get = |k: &str| got.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("AGENT_ALLOW"), Some("192.0.2.1, 192.0.2.2, 198.51.100.0/24"), "blanks inside stay");
        assert_eq!(get("NODES"), Some("a.example:7949, b.example:7949"));
        assert_eq!(get("CONSOLE_ALLOW"), Some("any"));
        assert_eq!(get("TLS_CERT"), Some("/opt/x/tls.crt"));
        assert_eq!(get("EMPTY"), Some(""));
        assert_eq!(get("QUOTE"), Some("say \"hi\" \\ there"));
        assert_eq!(get("LONG"), Some("one, two"));
        assert_eq!(get("AGENT_LISTEN"), Some("127.0.0.1:7949"), "the last one wins");
        assert!(get("bad name").is_none() && get("1BAD").is_none());
        assert_eq!(got.len(), 8, "AGENT_LISTEN once");
    }

    #[test]
    fn the_template_reads_whole() {
        let got = parse(include_str!("../deploy/config.env.example"));
        assert!(got.iter().any(|(k, v)| k == "AGENT_LISTEN" && v == "0.0.0.0:7949"));
        assert!(got.iter().any(|(k, _)| k == "REFRESH_SECS"));
        assert!(!got.iter().any(|(k, _)| k == "METRICS_TOKEN_FILE"), "commented out");
    }

    #[test]
    fn the_environment_wins() {
        let dir = std::env::temp_dir().join(format!("lgw-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.env");
        std::fs::write(&f, "LGW_TEST_A=from file, with blanks\nLGW_TEST_B=from file\n").unwrap();
        std::env::set_var("LGW_TEST_B", "from the environment");
        assert_eq!(load(&f), Some(1));
        assert_eq!(std::env::var("LGW_TEST_A").unwrap(), "from file, with blanks");
        assert_eq!(std::env::var("LGW_TEST_B").unwrap(), "from the environment");
        assert_eq!(load(&dir.join("missing")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
