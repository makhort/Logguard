//! Text for Telegram: at most 4096 characters per message, formatting given as entities
//! (offsets in UTF-16 code units) rather than Markdown or HTML, so nothing in a log line
//! can change how a message displays.

use crate::api::Entity;

/// UTF-16 code units per message, with room to spare under the API's 4096.
pub const LIMIT: usize = 4000;
const CONTINUED: &str = "(continued)\n";

#[derive(Debug, Clone, PartialEq)]
pub struct Out {
    pub text: String,
    pub entities: Vec<Entity>,
}

/// Text as Telegram keeps it: no control characters except line breaks and tabs (`\r\n`
/// becomes `\n`). Telegram would drop or refuse the others, which moves the entities.
pub fn clean(text: &str) -> String {
    text.replace("\r\n", "\n").chars().filter(|&c| c == '\n' || c == '\t' || !c.is_control()).collect()
}

/// What an alert with no text says, rather than an empty message Telegram refuses.
pub const EMPTY: &str = "(an empty message)";

pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The longest start of `s` within `limit` UTF-16 code units.
pub fn truncate(s: &str, limit: usize) -> &str {
    let mut n = 0;
    for (i, c) in s.char_indices() {
        n += c.len_utf16();
        if n > limit {
            return &s[..i];
        }
    }
    s
}

/// Pieces of at most `limit` UTF-16 code units, cut after a line where possible, each
/// without trailing blanks (the API trims them, which would move the entities).
pub fn split(text: &str, limit: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut len = 0;
    let mut flush = |cur: &mut String, len: &mut usize| {
        let piece = cur.trim_end();
        if !piece.trim_start().is_empty() {
            parts.push(piece.to_string());
        }
        cur.clear();
        *len = 0;
    };
    for line in text.split_inclusive('\n') {
        let n = utf16_len(line);
        if len + n > limit {
            flush(&mut cur, &mut len);
        }
        if n <= limit {
            cur.push_str(line);
            len += n;
            continue;
        }
        for c in line.chars() {
            if len + c.len_utf16() > limit {
                flush(&mut cur, &mut len);
            }
            cur.push(c);
            len += c.len_utf16();
        }
    }
    flush(&mut cur, &mut len);
    parts
}

/// A logguard admin message: its first line (the subject, with the server's name) in bold,
/// the rest as a monospace block, as the digest's columns need. Long ones go out in several
/// messages, the later ones marked as continued.
pub fn alert(text: &str) -> Vec<Out> {
    let text = clean(text);
    let text = match text.trim() {
        "" => EMPTY,
        t => t,
    };
    let (subject, body) = match text.split_once('\n') {
        Some((s, b)) => (s.trim(), b.trim_start_matches(['\n', '\r']).trim_end()),
        None => (text, ""),
    };
    // cut where it may, then no blank at the end (Telegram would trim it under the entity)
    let subject = truncate(subject, 300).trim_end();
    let first = format!("{subject}\n\n");
    let bold = |len| Entity { kind: "bold", offset: 0, length: len };
    let pieces = split(body, LIMIT - utf16_len(&first).max(utf16_len(CONTINUED)));
    if pieces.is_empty() {
        return vec![Out { text: subject.to_string(), entities: vec![bold(utf16_len(subject))] }];
    }
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| {
            let head = if i == 0 { first.as_str() } else { CONTINUED };
            let mut entities = if i == 0 {
                vec![bold(utf16_len(subject))]
            } else {
                vec![Entity { kind: "italic", offset: 0, length: utf16_len(CONTINUED) - 1 }]
            };
            entities.push(Entity { kind: "pre", offset: utf16_len(head), length: utf16_len(&piece) });
            Out { text: format!("{head}{piece}"), entities }
        })
        .collect()
}

/// A reply without formatting (Telegram still links /commands in it).
pub fn plain(text: &str) -> Vec<Out> {
    // a later piece may start with blanks, which Telegram would trim off
    split(clean(text).trim(), LIMIT).into_iter().map(|text| Out { text: text.trim_start().to_string(), entities: vec![] }).collect()
}

/// A duration for people: `3d 4h`, `2h 5m`, `4m`, `12s`.
pub fn duration(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h", s / 86400, s % 86400 / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text an entity covers.
    fn covered(out: &Out, e: &Entity) -> String {
        let units: Vec<u16> = out.text.encode_utf16().collect();
        String::from_utf16(&units[e.offset..e.offset + e.length]).unwrap()
    }

    #[test]
    fn subject_bold_body_monospace() {
        let out = alert("[xmpp] logguard: system ✓\n\n[High] ban 1.2.3.4 → 1h\n  10-16 12:00 Привіт 😀\n\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].text, "[xmpp] logguard: system ✓\n\n[High] ban 1.2.3.4 → 1h\n  10-16 12:00 Привіт 😀");
        assert_eq!(covered(&out[0], &out[0].entities[0]), "[xmpp] logguard: system ✓");
        assert_eq!(out[0].entities[1].kind, "pre");
        assert_eq!(
            covered(&out[0], &out[0].entities[1]),
            "[High] ban 1.2.3.4 → 1h\n  10-16 12:00 Привіт 😀",
            "UTF-16 offsets (😀 is two units)"
        );
        let only = alert("just a subject");
        assert_eq!(only, vec![Out { text: "just a subject".into(), entities: vec![Entity { kind: "bold", offset: 0, length: 14 }] }]);
    }

    #[test]
    fn long_messages_are_split_on_lines() {
        let body: String = (0..400).map(|i| format!("  {i:>4} 1.2.3.{} 😀 points\n", i % 250)).collect();
        let out = alert(&format!("[vpn] logguard daily digest\n\n{body}"));
        assert!(out.len() >= 3, "{}", out.len());
        let mut lines = 0;
        for (i, o) in out.iter().enumerate() {
            assert!(utf16_len(&o.text) <= LIMIT);
            let pre = o.entities.last().unwrap();
            assert_eq!(pre.offset + pre.length, utf16_len(&o.text), "the block runs to the end");
            let block = covered(o, pre);
            assert!(block.starts_with("  ") || block.starts_with(char::is_numeric), "whole lines: {block:.20}");
            lines += block.lines().count();
            if i > 0 {
                assert!(o.text.starts_with("(continued)\n"));
                assert_eq!(covered(o, &o.entities[0]), "(continued)");
            }
        }
        assert_eq!(lines, 400, "no line lost");
    }

    #[test]
    fn overlong_lines_are_cut() {
        let line = "x".repeat(10_000);
        let parts = split(&line, LIMIT);
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [4000, 4000, 2000]);
        assert_eq!(plain("  \n\n").len(), 0);
        assert_eq!(truncate("ab😀c", 3), "ab", "never half a character");
        assert_eq!(truncate("ab😀c", 4), "ab😀");
    }

    #[test]
    fn control_characters_and_empty_text() {
        let out = alert("[xmpp] subject\r\n\r\nline\u{0}one\u{1b}[31m red\ttab\u{7f}");
        assert_eq!(out[0].text, "[xmpp] subject\n\nlineone[31m red\ttab");
        let pre = &out[0].entities[1];
        assert_eq!(pre.offset + pre.length, utf16_len(&out[0].text));
        assert_eq!(alert(" \n\u{0} \n")[0].text, EMPTY, "never an empty message");
        assert_eq!(alert("")[0].text, EMPTY);
        let long = format!("{} tail", "x".repeat(299));
        assert_eq!(alert(&long)[0].text, "x".repeat(299), "a long subject cut on a blank");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(12), "12s");
        assert_eq!(duration(300), "5m");
        assert_eq!(duration(3 * 3600 + 12 * 60), "3h 12m");
        assert_eq!(duration(2 * 86400 + 3 * 3600), "2d 3h");
        assert_eq!(duration(-5), "0s");
    }
}
