//! Log lines to stderr, which systemd puts in the journal. logguard reads them there
//! (`[sources] apps = ["logguard-web"]`) and scores failed logins and probes: every line
//! about a client starts with fixed text and the client's address, which the client can't
//! choose (it comes from the connection), and text the client did choose is escaped onto
//! the same line.

use std::io::Write;

/// Text as one line without anything a terminal acts on: control characters as escapes.
pub fn one_line(text: &str) -> String {
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

pub fn line(msg: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{}", one_line(msg));
}

#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => { $crate::log::line(&format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    #[test]
    fn one_line() {
        assert_eq!(super::one_line("GET /x\nlogin failed from 1.2.3.4: x"), "GET /x\\nlogin failed from 1.2.3.4: x");
    }
}
