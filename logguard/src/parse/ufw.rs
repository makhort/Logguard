//! UFW kernel log parsing (`[UFW BLOCK]`, `[UFW LIMIT BLOCK]`), IPv4 and IPv6,
//! TCP and UDP alike. Hosts with plain iptables log the same way with a LOG rule of their
//! own, prefix `[LOGGUARD BLOCK] ` (see the README, "Requirements").

use crate::event::{Event, Proto, Signal};
use crate::net::parse_ip;
use crate::record::Record;

/// Log prefixes of blocked packets: ufw's, and the one for a LOG rule of your own.
const PREFIXES: [&str; 2] = ["[UFW ", "[LOGGUARD "];

/// Whether a kernel message is a firewall log line this parser reads.
pub fn is_firewall_log(msg: &str) -> bool {
    PREFIXES.iter().any(|p| msg.contains(p))
}

pub fn feed(rec: &Record, out: &mut Vec<Event>) {
    let m = &rec.msg;
    let Some((start, len)) = PREFIXES.iter().find_map(|p| m.find(p).map(|i| (i, p.len()))) else { return };
    let Some(end) = m[start..].find(']') else { return };
    let action = &m[start + len..start + end];
    let signal = match action {
        "BLOCK" => Signal::FwBlock,
        "LIMIT BLOCK" => Signal::FwLimit,
        _ => return, // ALLOW / AUDIT lines are not hostile by themselves
    };
    let (mut src, mut dpt, mut proto) = (None, None, "");
    for kv in m[start + end + 1..].split_whitespace() {
        match kv.split_once('=') {
            Some(("SRC", v)) => src = parse_ip(v),
            Some(("DPT", v)) => dpt = v.parse::<u16>().ok(),
            Some(("PROTO", v)) => proto = v,
            _ => {}
        }
    }
    if let Some(ip) = src {
        let what = match dpt {
            Some(p) => format!("{} {proto}/{p}", action.to_lowercase()),
            None => format!("{} {proto}", action.to_lowercase()),
        };
        let proto = match proto {
            "TCP" => Proto::Tcp,
            "UDP" => Proto::Udp,
            _ => Proto::Other,
        };
        out.push(Event::new(rec.ts, ip, signal).port(dpt).proto(proto).detail(what));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Source;

    fn parse(msg: &str) -> Vec<Event> {
        let mut out = vec![];
        feed(&Record { ts: 0, source: Source::Ufw, pid: 0, msg: msg.into(), cursor: None }, &mut out);
        out
    }

    #[test]
    fn tcp_udp_v6_and_limit() {
        let tcp = parse("[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.4 DST=11.17.39.236 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=1 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0");
        assert_eq!((tcp[0].signal, tcp[0].port), (Signal::FwBlock, Some(23)));
        let udp = parse("[12.3] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.5 DST=11.17.39.236 LEN=50 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=UDP SPT=5 DPT=161 LEN=30");
        assert_eq!((udp[0].port, udp[0].proto), (Some(161), Proto::Udp));
        let v6 = parse("[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=50 FLOWLBL=0 PROTO=TCP SPT=1 DPT=22 WINDOW=1 RES=0x00 SYN URGP=0");
        assert_eq!(v6[0].ip.to_string(), "2001:db8::1");
        let lim = parse("[UFW LIMIT BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.6 DST=11.17.39.236 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=5 DPT=9843 WINDOW=1 RES=0x00 SYN URGP=0");
        assert_eq!(lim[0].signal, Signal::FwLimit);
        assert!(parse("[UFW AUDIT] IN=eth0 SRC=1.1.1.1 DPT=1").is_empty());
    }

    #[test]
    fn own_iptables_log_rule() {
        let line =
            "[LOGGUARD BLOCK] IN=eth0 OUT= MAC=aa SRC=198.51.100.9 DST=192.0.2.1 LEN=44 PROTO=TCP SPT=1 DPT=3389 WINDOW=1024 SYN URGP=0";
        assert!(is_firewall_log(line) && !is_firewall_log("[LOGGUARD] something else"));
        let e = parse(line);
        assert_eq!((e[0].signal, e[0].port, e[0].detail.as_str()), (Signal::FwBlock, Some(3389), "block TCP/3389"));
        assert!(parse("[LOGGUARD ACCEPT] IN=eth0 SRC=198.51.100.9 DPT=22").is_empty());
    }
}
