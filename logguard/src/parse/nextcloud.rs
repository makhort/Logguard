//! Nextcloud (AIO) parsing.
//!
//! * Apache error log (`docker logs nextcloud-aio-apache`): refused requests for secrets
//!   (`AH01797/AH01630 client denied by server configuration: /var/www/html/config/.env`)
//!   and path traversal (`AH10244 invalid URI path (/../.env)`). Real users never send these.
//! * nextcloud.log (JSON lines): `Login failed: alice (Remote IP: 1.2.3.4)`.

use crate::event::{Event, Signal};
use crate::net::{parse_ip, parse_ip_port};
use crate::record::Record;

pub fn feed(rec: &Record, out: &mut Vec<Event>) {
    let m = rec.msg.as_str();
    if m.starts_with('{') {
        login(rec, out);
        return;
    }
    // Apache 2.4: "[client 1.2.3.4:51234]"; Nextcloud AIO's format: "[client: 1.2.3.4]".
    let Some(start) = m.find("[client") else { return };
    let tail = &m[start + 7..];
    let Some(end) = tail.find(']') else { return };
    let token = tail[..end].trim_start_matches(':').trim();
    let Some((ip, _)) = parse_ip_port(token) else { return };
    let detail = if let Some(i) = m.find("client denied by server configuration: ") {
        let path = &m[i + 39..];
        format!("denied: {}", &path[..path.find(']').unwrap_or(path.len())])
    } else if m.contains("AH10244") || m.contains("AH00126") {
        let what = m.split("invalid URI path (").nth(1).and_then(|p| p.split(')').next()).unwrap_or("invalid URI");
        format!("path traversal: {what}")
    } else {
        return;
    };
    out.push(Event::new(rec.ts, ip, Signal::WebProbe).port(Some(443)).detail(detail));
}

fn login(rec: &Record, out: &mut Vec<Event>) {
    #[derive(serde::Deserialize)]
    struct Line {
        #[serde(rename = "remoteAddr")]
        remote_addr: Option<String>,
        message: Option<String>,
    }
    let Ok(l) = serde_json::from_str::<Line>(&rec.msg) else { return };
    let (Some(addr), Some(msg)) = (l.remote_addr, l.message) else { return };
    let Some(rest) = msg.strip_prefix("Login failed: ") else { return };
    let Some(ip) = parse_ip(&addr) else { return };
    // "alice (Remote IP: 1.2.3.4)" or "'alice' (Remote IP: '1.2.3.4')"
    let user = rest.split(" (Remote IP").next().unwrap_or(rest).trim_matches(['\'', '"']);
    out.push(
        Event::new(rec.ts, ip, Signal::NcAuthFail).port(Some(443)).account(Some(user)).detail(format!("nextcloud login failed for {user}")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::parse_nextcloud_line;

    fn parse(line: &str) -> Vec<Event> {
        let mut out = vec![];
        if let Some(r) = parse_nextcloud_line(line) {
            feed(&r, &mut out);
        }
        out
    }

    #[test]
    fn apache_probes() {
        let e = parse("[Mon Oct 05 06:48:49 2026] [error] [client: 11.6.32.142] [AH01797: client denied by server configuration: /var/www/html/config/aws.yml] [Mozilla/5.0]");
        assert_eq!(
            (e[0].signal, e[0].ip.to_string(), e[0].detail.as_str()),
            (Signal::WebProbe, "11.6.32.142".into(), "denied: /var/www/html/config/aws.yml")
        );
        assert_eq!(crate::time::fmt_ts(e[0].ts), "2026-10-05 06:48:49");
        let e = parse("2026-10-11T17:49:18.123456789Z [Sun Oct 11 17:49:18 2026] [error] [client: 11.29.52.117] [AH10244: invalid URI path (/../.env)] [UA]");
        assert_eq!(e[0].detail, "path traversal: /../.env");
        let e = parse("[Tue Oct 06 08:27:23.123 2026] [authz_core:error] [pid 9] [client 203.0.113.9:51234] AH01630: client denied by server configuration: /var/www/html/.git");
        assert_eq!(e[0].ip.to_string(), "203.0.113.9");
        // benign lines
        assert!(parse("[Fri Oct 02 15:53:01.527478 2026] [mpm_event:notice] [pid 73:tid 73] AH00489: Apache/2.4.68 (Unix) configured")
            .is_empty());
        assert!(parse("{\"level\":\"warn\",\"ts\":1791182928.33,\"logger\":\"http.handlers.reverse_proxy\",\"request\":{\"remote_ip\":\"11.6.32.142\"}}").is_empty());
        assert!(parse("Waiting for Nextcloud to start...").is_empty());
    }

    #[test]
    fn failed_logins() {
        let e = parse(
            r#"{"reqId":"x","level":2,"time":"2026-10-11T19:16:24+00:00","remoteAddr":"198.51.100.4","user":"--","app":"core","method":"POST","url":"/login","message":"Login failed: alice (Remote IP: 198.51.100.4)","userAgent":"curl"}"#,
        );
        assert_eq!((e[0].signal, e[0].account.as_deref()), (Signal::NcAuthFail, Some("alice")));
        assert_eq!(crate::time::fmt_ts(e[0].ts), "2026-10-11 19:16:24");
        let e = parse(
            r#"{"time":"2026-10-11T19:16:25+00:00","remoteAddr":"198.51.100.4","message":"Login failed: 'bob' (Remote IP: '198.51.100.4')"}"#,
        );
        assert_eq!(e[0].account.as_deref(), Some("bob"));
        assert!(parse(r#"{"time":"2026-10-11T19:16:25+00:00","remoteAddr":"198.51.100.4","message":"Trusted domain error"}"#).is_empty());
        // real line from the server (Nextcloud 34.0.4)
        let e = parse(
            r#"{"reqId":"WVnDVHYg2lFh0z5kmXVC","level":2,"time":"2026-10-11T19:54:01+00:00","remoteAddr":"11.20.37.110","user":"--","app":"no app in context","method":"POST","url":"/login","scriptName":"/index.php","message":"Login failed: admin (Remote IP: 11.20.37.110)","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0","version":"11.5.4.1","data":[]}"#,
        );
        assert_eq!((e[0].signal, e[0].ip.to_string(), e[0].account.as_deref()), (Signal::NcAuthFail, "11.20.37.110".into(), Some("admin")));
        assert_eq!(crate::time::fmt_ts(e[0].ts), "2026-10-11 19:54:01");
        // real line from the server: the updater's own "../" path, no remote address
        assert!(parse(r#"{"reqId":"K2G5HUQ5mwhjHWlRkmIw","level":1,"time":"2026-09-06T15:23:53+00:00","remoteAddr":"","user":"--","app":"updater","method":"","url":"--","scriptName":"/var/www/html/updater/../occ","message":"\OC\Updater::updateEnd: Update successful","userAgent":"--","version":"11.5.3.2","occ_command":["/var/www/html/updater/../occ","upgrade"],"data":{"app":"updater"}}"#).is_empty());
        assert!(
            crate::record::parse_nextcloud_line(r#"{"remoteAddr":"","message":"dirty table reads: SELECT ...","exception":{"Trace":[]}}"#)
                .is_none(),
            "skipped before parsing"
        );
    }
}
