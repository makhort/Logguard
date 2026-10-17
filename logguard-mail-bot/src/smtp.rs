//! The way out: SMTP to a mail server, the local Postfix (on loopback, plain SMTP allowed)
//! or any other (TLS, from the start or by STARTTLS, never falling back to plain), with
//! or without authentication. One connection per mail: the bot sends a few a day, and an
//! idle connection would only time out on the server's side.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, SmtpTransport, Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// TLS from the first byte ("SMTPS", usually port 465).
    Implicit,
    /// Plain first, then STARTTLS, required (usually port 587; 25 between servers).
    StartTls,
    /// No TLS: only to a mail server on this host (loopback).
    None,
}

impl FromStr for TlsMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "tls" | "implicit" | "smtps" => Ok(TlsMode::Implicit),
            "starttls" => Ok(TlsMode::StartTls),
            "none" | "off" | "plain" => Ok(TlsMode::None),
            _ => Err(format!("'{s}': tls, starttls or none")),
        }
    }
}

impl TlsMode {
    pub fn default_port(self) -> u16 {
        match self {
            TlsMode::Implicit => 465,
            TlsMode::StartTls => 587,
            TlsMode::None => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// PLAIN or LOGIN, whichever the server offers (PLAIN first) when a user is set; none
    /// without one.
    Auto,
    Plain,
    Login,
    None,
}

impl FromStr for Auth {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Auth::Auto),
            "plain" => Ok(Auth::Plain),
            "login" => Ok(Auth::Login),
            "none" | "off" => Ok(Auth::None),
            _ => Err(format!("'{s}': auto, plain, login or none")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    /// The name the server's certificate must carry (the host name, unless it is an address).
    pub tls_name: String,
    /// Trust only this CA (PEM: the CA that issued the server's certificate) instead of the
    /// system's CA store, e.g. for the local Postfix's own certificate.
    pub ca_file: Option<PathBuf>,
    pub auth: Auth,
    pub user: String,
    pub password: String,
    /// The name the bot gives in EHLO.
    pub helo: String,
    pub timeout: Duration,
}

/// Whether `host` is this machine: plain SMTP is allowed only there.
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Settings {
    /// The mechanisms to offer, empty for no authentication.
    pub fn mechanisms(&self) -> Vec<Mechanism> {
        match self.auth {
            Auth::None => vec![],
            Auth::Auto if self.user.is_empty() => vec![],
            Auth::Auto => vec![Mechanism::Plain, Mechanism::Login],
            Auth::Plain => vec![Mechanism::Plain],
            Auth::Login => vec![Mechanism::Login],
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let bare = self.host.trim_matches(['[', ']']);
        let ipv6 = bare.parse::<std::net::Ipv6Addr>().is_ok();
        if bare.is_empty() || bare.contains(|c: char| c.is_whitespace() || c == '/' || c == '@') || (bare.contains(':') && !ipv6) {
            return Err(format!("SMTP_HOST '{}' is not a host name or address (the port goes in SMTP_PORT)", self.host));
        }
        if self.port == 0 {
            return Err("SMTP_PORT can't be 0".into());
        }
        if self.tls == TlsMode::None && !is_loopback(&self.host) {
            return Err(format!(
                "SMTP_TLS=none is for a mail server on this host only (127.0.0.1, ::1, localhost), not {}: use tls or starttls",
                self.host
            ));
        }
        if self.tls != TlsMode::None && self.tls_name.is_empty() {
            return Err("SMTP_TLS_NAME is empty".into());
        }
        let auth = !self.mechanisms().is_empty();
        if auth && (self.user.is_empty() || self.password.is_empty()) {
            return Err("SMTP_AUTH needs SMTP_USER and a password (SMTP_PASSWORD_FILE or SMTP_PASSWORD)".into());
        }
        if !auth && !self.password.is_empty() {
            return Err("a password is set but SMTP_AUTH=none (or no SMTP_USER): set both, or neither".into());
        }
        if self.helo.is_empty() || self.helo.contains(|c: char| !(c.is_ascii_alphanumeric() || ".-".contains(c))) {
            return Err(format!("HELO_NAME '{}' is not a host name", self.helo));
        }
        Ok(())
    }

    fn tls_parameters(&self) -> Result<TlsParameters, String> {
        let mut b = TlsParameters::builder(self.tls_name.clone());
        if let Some(path) = &self.ca_file {
            let pem = std::fs::read(path).map_err(|e| format!("SMTP_CA_FILE {}: {e}", path.display()))?;
            let cert = Certificate::from_pem(&pem).map_err(|e| format!("SMTP_CA_FILE {}: {e}", path.display()))?;
            b = b.certificate_store(CertificateStore::None).add_root_certificate(cert);
        }
        b.build_rustls().map_err(|e| format!("TLS: {e}"))
    }

    /// The client, ready to connect (nothing is sent yet).
    pub fn transport(&self) -> Result<SmtpTransport, String> {
        self.validate()?;
        let tls = match self.tls {
            TlsMode::Implicit => Tls::Wrapper(self.tls_parameters()?),
            TlsMode::StartTls => Tls::Required(self.tls_parameters()?),
            TlsMode::None => Tls::None,
        };
        let mut b = SmtpTransport::builder_dangerous(self.host.trim_matches(['[', ']']))
            .port(self.port)
            .tls(tls)
            .timeout(Some(self.timeout))
            .hello_name(ClientId::Domain(self.helo.clone()));
        let mechanisms = self.mechanisms();
        if !mechanisms.is_empty() {
            b = b.credentials(Credentials::new(self.user.clone(), self.password.clone())).authentication(mechanisms);
        }
        Ok(b.build())
    }

    /// Where the bot sends, for the log: `smtp.example.org:587 (STARTTLS, PLAIN/LOGIN as alerts)`.
    pub fn describe(&self) -> String {
        let tls = match self.tls {
            TlsMode::Implicit => "TLS",
            TlsMode::StartTls => "STARTTLS",
            TlsMode::None => "no TLS",
        };
        let auth = match self.mechanisms().as_slice() {
            [] => "no login".to_string(),
            m => format!("{} as {}", m.iter().map(|m| m.to_string()).collect::<Vec<_>>().join("/"), self.user),
        };
        format!("{}:{} ({tls}, {auth})", self.host, self.port)
    }
}

/// Why a mail didn't go out.
#[derive(Clone, Debug, PartialEq)]
pub struct SendError {
    /// The server refused for good (5xx), or the client can't do what it needs (no common
    /// login mechanism): the same mail will be refused again.
    pub permanent: bool,
    /// It isn't about this mail: the login, or the connection itself (STARTTLS missing). Then
    /// no other mail goes through either, and trying one (a note) would only fail again: a
    /// failed login more counts towards the server's ban.
    pub global: bool,
    pub text: String,
}

impl SendError {
    /// A failure that may pass (out of reach, a 4xx, a TLS problem).
    pub fn transient(text: impl Into<String>) -> SendError {
        SendError { permanent: false, global: false, text: text.into() }
    }

    /// A refusal of this mail alone (as far as the bot can tell).
    pub fn refused(text: impl Into<String>) -> SendError {
        SendError { permanent: true, global: false, text: text.into() }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Replies that refuse the login, not a mail: 530 authentication required, 534 mechanism too
/// weak, 535 credentials invalid, 538 encryption required for the mechanism (RFC 4954).
const LOGIN_REFUSED: [u16; 4] = [530, 534, 535, 538];

/// lettre's own error when the server offers no STARTTLS: the server's setup, or someone in
/// the way stripping it. Not given up on for good, as an attacker could otherwise stop the bot.
const NO_STARTTLS: &str = "STARTTLS is not supported";

impl From<lettre::transport::smtp::Error> for SendError {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        // lettre's text names the cause: "permanent error (535): 5.7.8 authentication failed"
        let text = e.to_string();
        let code = e.status().map(u16::from);
        if e.is_client() && text.contains(NO_STARTTLS) {
            return SendError { permanent: false, global: true, text: format!("{text} (stripped on the way?)") };
        }
        let login = code.is_some_and(|c| LOGIN_REFUSED.contains(&c));
        SendError { permanent: e.is_permanent() || e.is_client(), global: e.is_client() || login, text }
    }
}

/// What sends the mails: SMTP, or a fake in tests.
pub trait Outgoing {
    /// One mail (all of it, CRLF line ends), from `from` to every one of `to`.
    fn send(&mut self, from: &str, to: &[String], mail: &[u8]) -> Result<(), SendError>;
}

pub struct Smtp {
    transport: SmtpTransport,
}

impl Smtp {
    pub fn new(settings: &Settings) -> Result<Smtp, String> {
        if settings.tls != TlsMode::None && settings.ca_file.is_none() && rustls_native_certs::load_native_certs().certs.is_empty() {
            // every TLS connection would fail, and be retried forever
            return Err("no CA certificates on this system (/etc/ssl/certs): install ca-certificates, or set SMTP_CA_FILE".into());
        }
        Ok(Smtp { transport: settings.transport()? })
    }

    /// Connects, starts TLS and logs in, sends nothing.
    pub fn check(&self) -> Result<(), SendError> {
        match self.transport.test_connection() {
            Ok(true) => Ok(()),
            Ok(false) => Err(SendError::transient("the server didn't answer NOOP")),
            Err(e) => Err(e.into()),
        }
    }
}

fn envelope(from: &str, to: &[String]) -> Result<Envelope, SendError> {
    let bad = |a: &str, e: lettre::address::AddressError| SendError { permanent: true, global: true, text: format!("address {a}: {e}") };
    let from = Address::from_str(from).map_err(|e| bad(from, e))?;
    let to = to.iter().map(|a| Address::from_str(a).map_err(|e| bad(a, e))).collect::<Result<Vec<_>, _>>()?;
    Envelope::new(Some(from), to).map_err(|e| SendError { permanent: true, global: true, text: e.to_string() })
}

impl Outgoing for Smtp {
    fn send(&mut self, from: &str, to: &[String], mail: &[u8]) -> Result<(), SendError> {
        self.transport.send_raw(&envelope(from, to)?, mail).map(|_| ()).map_err(SendError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            host: "smtp.example.org".into(),
            port: 587,
            tls: TlsMode::StartTls,
            tls_name: "smtp.example.org".into(),
            ca_file: None,
            auth: Auth::Auto,
            user: "alerts@example.org".into(),
            password: "secret".into(),
            helo: "vpn.example.org".into(),
            timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn plain_smtp_only_on_this_host() {
        let s = Settings { tls: TlsMode::None, ..settings() };
        assert!(s.validate().unwrap_err().contains("this host only"));
        for host in ["127.0.0.1", "::1", "[::1]", "localhost", "127.0.0.2"] {
            assert!(Settings { host: host.into(), ..s.clone() }.validate().is_ok(), "{host}");
        }
        assert!(Settings { host: "127.0.0.1.example.net".into(), ..s.clone() }.validate().is_err());
        for bad in ["smtp.example.org:587", "", "a b", "user@smtp.example.org"] {
            assert!(Settings { host: bad.into(), tls: TlsMode::StartTls, ..s.clone() }.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn authentication_settings() {
        assert!(settings().validate().is_ok());
        assert_eq!(settings().mechanisms(), [Mechanism::Plain, Mechanism::Login]);
        assert_eq!(Settings { auth: Auth::Login, ..settings() }.mechanisms(), [Mechanism::Login]);
        let anonymous = Settings { user: String::new(), password: String::new(), ..settings() };
        assert!(anonymous.mechanisms().is_empty() && anonymous.validate().is_ok(), "auto without a user: no login");
        assert!(Settings { password: String::new(), ..settings() }.validate().is_err(), "a user needs a password");
        assert!(Settings { auth: Auth::None, ..settings() }.validate().is_err(), "a password nobody uses is a mistake");
        assert!(Settings { helo: "bad name".into(), ..settings() }.validate().is_err());
        assert_eq!(settings().describe(), "smtp.example.org:587 (STARTTLS, PLAIN/LOGIN as alerts@example.org)");
    }

    #[test]
    fn modes_parse() {
        assert_eq!("SMTPS".parse::<TlsMode>(), Ok(TlsMode::Implicit));
        assert_eq!("starttls".parse::<TlsMode>(), Ok(TlsMode::StartTls));
        assert_eq!("none".parse::<TlsMode>().map(TlsMode::default_port), Ok(25));
        assert!("ssl3".parse::<TlsMode>().is_err());
        assert_eq!("LOGIN".parse::<Auth>(), Ok(Auth::Login));
        assert!("cram-md5".parse::<Auth>().is_err());
    }

    #[test]
    fn envelopes_take_plain_addresses() {
        assert!(envelope("a@example.org", &["b@example.org".into()]).is_ok());
        assert!(envelope("a@example.org", &["not an address".into()]).unwrap_err().permanent);
    }
}
