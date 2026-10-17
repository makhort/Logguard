//! Normalised security events produced by the per-source parsers.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::record::Source;
use crate::time::Micros;

/// One observable behaviour of a remote address. Weights live in the config;
/// positive signals (`*AuthOk`) build trust instead of score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// TLS handshake failure on a client connection (old protocol, no shared cipher...).
    XmppTlsFail,
    /// Failed SASL authentication.
    XmppAuthFail,
    XmppAuthOk,
    /// Client-port connection that never attempted authentication.
    XmppNoAuth,
    /// Connection to a non-client XMPP port (s2s, http, turn) from a non-trusted host.
    XmppConn,
    /// Inbound s2s stream rejected as malformed / bogus host.
    XmppS2sBad,
    /// Request for a missing upload file (URL guessing).
    XmppHttpMiss,
    /// Rejected FAST token (`HT-*` mechanism): almost always a legitimate client with an
    /// expired token, so it scores low and doesn't count towards account attacks.
    XmppTokenFail,
    /// New account registered in-band.
    XmppRegister,
    SshAuthFail,
    SshInvalidUser,
    SshAuthOk,
    /// Pre-authentication disconnects, failed negotiation, banner garbage.
    SshPreauth,
    /// OpenSSH PerSourcePenalties already penalised this source.
    SshPenalty,
    /// Packet dropped by UFW.
    FwBlock,
    /// Packet dropped by a UFW `limit` rule (rate-limited SSH).
    FwLimit,
    /// Blocked packet to a tripwire port (telnet, RDP, ...): nobody legitimate goes there.
    FwTripwire,
    /// Suspicious activity reported by another cluster node (points scaled by `report_factor`).
    PeerReport,
    /// Request for secrets / path traversal refused by the web server (`.env`, `config/`, `../`).
    WebProbe,
    /// Failed Nextcloud login.
    NcAuthFail,
    /// Login attempt on a canary account (`[canary]`): a name nobody legitimate uses.
    XmppCanary,
    SshCanary,
    NcCanary,
}

/// Event detail of a *successful* login to a canary account (worse than a failed one).
pub const CANARY_LOGIN: &str = "LOGGED IN to canary account";

impl Signal {
    pub const ALL: [Signal; 23] = [
        Signal::XmppTlsFail,
        Signal::XmppAuthFail,
        Signal::XmppAuthOk,
        Signal::XmppNoAuth,
        Signal::XmppConn,
        Signal::XmppS2sBad,
        Signal::XmppHttpMiss,
        Signal::XmppTokenFail,
        Signal::XmppRegister,
        Signal::SshAuthFail,
        Signal::SshInvalidUser,
        Signal::SshAuthOk,
        Signal::SshPreauth,
        Signal::SshPenalty,
        Signal::FwBlock,
        Signal::FwLimit,
        Signal::FwTripwire,
        Signal::PeerReport,
        Signal::WebProbe,
        Signal::NcAuthFail,
        Signal::XmppCanary,
        Signal::SshCanary,
        Signal::NcCanary,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Signal::XmppTlsFail => "xmpp_tls_fail",
            Signal::XmppAuthFail => "xmpp_auth_fail",
            Signal::XmppAuthOk => "xmpp_auth_ok",
            Signal::XmppNoAuth => "xmpp_no_auth",
            Signal::XmppConn => "xmpp_conn",
            Signal::XmppS2sBad => "xmpp_s2s_bad",
            Signal::XmppHttpMiss => "xmpp_http_miss",
            Signal::XmppTokenFail => "xmpp_token_fail",
            Signal::XmppRegister => "xmpp_register",
            Signal::SshAuthFail => "ssh_auth_fail",
            Signal::SshInvalidUser => "ssh_invalid_user",
            Signal::SshAuthOk => "ssh_auth_ok",
            Signal::SshPreauth => "ssh_preauth",
            Signal::SshPenalty => "ssh_penalty",
            Signal::FwBlock => "fw_block",
            Signal::FwLimit => "fw_limit",
            Signal::FwTripwire => "fw_tripwire",
            Signal::PeerReport => "peer_report",
            Signal::WebProbe => "web_probe",
            Signal::NcAuthFail => "nc_auth_fail",
            Signal::XmppCanary => "xmpp_canary",
            Signal::SshCanary => "ssh_canary",
            Signal::NcCanary => "nc_canary",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Signal::XmppAuthOk | Signal::SshAuthOk)
    }

    pub fn is_canary(self) -> bool {
        matches!(self, Signal::XmppCanary | Signal::SshCanary | Signal::NcCanary)
    }

    pub fn is_auth_failure(self) -> bool {
        matches!(self, Signal::XmppAuthFail | Signal::SshAuthFail | Signal::SshInvalidUser | Signal::NcAuthFail)
    }

    pub fn source(self) -> Source {
        match self {
            Signal::XmppTlsFail
            | Signal::XmppAuthFail
            | Signal::XmppAuthOk
            | Signal::XmppNoAuth
            | Signal::XmppConn
            | Signal::XmppS2sBad
            | Signal::XmppHttpMiss
            | Signal::XmppTokenFail
            | Signal::XmppRegister
            | Signal::XmppCanary => Source::Ejabberd,
            Signal::SshAuthFail
            | Signal::SshInvalidUser
            | Signal::SshAuthOk
            | Signal::SshPreauth
            | Signal::SshPenalty
            | Signal::SshCanary => Source::Ssh,
            Signal::FwBlock | Signal::FwLimit | Signal::FwTripwire => Source::Ufw,
            Signal::PeerReport => Source::Peer,
            Signal::WebProbe | Signal::NcAuthFail | Signal::NcCanary => Source::Nextcloud,
        }
    }
}

/// Transport protocol of the observed traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Other,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub ts: Micros,
    pub ip: IpAddr,
    pub signal: Signal,
    /// Local (destination) port the behaviour was seen on, when known.
    pub port: Option<u16>,
    /// TCP for every service log; UFW reports the real protocol.
    pub proto: Proto,
    /// XMPP JID or SSH user name involved, when known.
    pub account: Option<String>,
    /// Short human-readable evidence.
    pub detail: String,
}

impl Event {
    pub fn new(ts: Micros, ip: IpAddr, signal: Signal) -> Self {
        Event { ts, ip, signal, port: None, proto: Proto::Tcp, account: None, detail: String::new() }
    }

    pub fn port(mut self, port: Option<u16>) -> Self {
        self.port = port;
        self
    }

    pub fn proto(mut self, proto: Proto) -> Self {
        self.proto = proto;
        self
    }

    /// Account names come from attackers (any login name they try): control characters are
    /// dropped (they would reach terminals via `status`) and the length is capped (they
    /// are kept per account, up to `MAX_ACCOUNTS` of them).
    pub fn account(mut self, account: Option<&str>) -> Self {
        self.account = account.map(|a| clean(a, MAX_ACCOUNT_LEN));
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = clean(&detail.into(), 160);
        self
    }
}

/// Longest account name kept; real JIDs and user names are far shorter.
pub const MAX_ACCOUNT_LEN: usize = 200;

/// Invisible characters that change how the text around them displays: bidirectional
/// overrides and isolates (U+202E makes `exe.txt` show as `txt.exe`), zero-width and other
/// format characters, Unicode tags. Not `char::is_control`, which covers C0/C1 only.
pub fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}')
}

/// Text for a person to read (a report, a digest, an XMPP message): line breaks and tabs
/// stay; other control characters and [`is_hidden`] ones go.
pub fn plain_text(s: &str) -> String {
    s.chars().filter(|&c| c == '\n' || c == '\t' || !(c.is_control() || is_hidden(c))).collect()
}

/// Log text without control characters (terminal escape sequences) or [`is_hidden`] ones,
/// at most `max` chars (an ellipsis marks a cut).
pub fn clean(s: &str, max: usize) -> String {
    let mut out: String = s.chars().filter(|c| !(c.is_control() || is_hidden(*c))).take(max + 1).collect();
    if out.chars().count() > max {
        out = out.chars().take(max).collect();
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_removed() {
        let spoof = "invoice\u{202E}fdp.exe \u{200B}x\u{2066}y\u{2069} \u{E0041}tag";
        assert_eq!(clean(spoof, 100), "invoicefdp.exe xy tag");
        assert_eq!(plain_text("line 1\n\tline\u{202D} 2\u{1b}[31m"), "line 1\n\tline 2[31m");
        assert_eq!(plain_text("日本 🦀 é"), "日本 🦀 é", "ordinary text is untouched");
    }

    #[test]
    fn attacker_text_is_cleaned() {
        let e = Event::new(0, "192.0.2.1".parse().unwrap(), Signal::NcAuthFail)
            .account(Some("bob\u{1b}]52;c;ZXZpbA==\u{7}"))
            .detail("nextcloud login failed for bob\u{1b}[2J");
        assert_eq!(e.account.as_deref(), Some("bob]52;c;ZXZpbA=="));
        assert_eq!(e.detail, "nextcloud login failed for bob[2J");
        let long = "x".repeat(5000);
        assert_eq!(
            Event::new(0, "192.0.2.1".parse().unwrap(), Signal::NcAuthFail).account(Some(&long)).account.unwrap().chars().count(),
            MAX_ACCOUNT_LEN + 1
        );
        assert_eq!(clean("ab", 2), "ab");
        assert_eq!(clean("abc", 2), "ab…");
    }

    #[test]
    fn names_match_serde() {
        for s in Signal::ALL {
            assert_eq!(serde_json::to_value(s).unwrap(), s.name());
        }
    }
}
