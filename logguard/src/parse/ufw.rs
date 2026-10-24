//! UFW kernel log parsing (`[UFW BLOCK]`, `[UFW LIMIT BLOCK]`), IPv4 and IPv6,
//! TCP and UDP alike. Hosts with plain iptables log the same way with a LOG rule of their
//! own, prefix `[LOGGUARD BLOCK] ` (see the README, "Requirements").

use crate::event::{Event, Proto, Signal};
use crate::net::parse_ip;
use crate::record::Record;

/// Log prefixes of blocked packets: ufw's, and the one for a LOG rule of your own.
const PREFIXES: [&str; 2] = ["[UFW ", "[LOGGUARD "];

/// The action (`BLOCK`, `LIMIT BLOCK`) and the packet's fields of a firewall log line, if
/// `msg` is one. Only what the kernel's packet logger writes counts: the prefix at the start,
/// then `IN=<interface> OUT=<interface>`. Other kernel messages carry text any local user
/// chooses: a crashing program's is `<its name>[pid]: segfault ... in <its file name>`, and
/// a program named `[UFW BLOCK] IN= ... SRC=<anyone> DPT=23` would otherwise get any address
/// banned. A process name holds 15 bytes at most, so it can't reach the `OUT=` that follows.
fn firewall_line(msg: &str) -> Option<(&str, &str)> {
    let m = super::kernel::text(msg);
    let rest = PREFIXES.iter().find_map(|p| m.strip_prefix(p))?;
    let (action, fields) = rest.split_once(']')?;
    let fields = fields.strip_prefix(' ')?;
    let mut f = fields.split(' ');
    (f.next()?.starts_with("IN=") && f.next()?.starts_with("OUT=")).then_some((action, fields))
}

/// Whether a kernel message is a firewall log line this parser reads.
pub fn is_firewall_log(msg: &str) -> bool {
    firewall_line(msg).is_some()
}

pub fn feed(rec: &Record, out: &mut Vec<Event>) {
    let Some((action, fields)) = firewall_line(&rec.msg) else { return };
    let signal = match action {
        "BLOCK" => Signal::FwBlock,
        "LIMIT BLOCK" => Signal::FwLimit,
        _ => return, // ALLOW / AUDIT lines are not hostile by themselves
    };
    let (mut src, mut dpt, mut proto) = (None, None, "");
    for kv in fields.split_whitespace() {
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
        feed(&Record { ts: 0, source: Source::Ufw, pid: 0, msg: msg.into(), cursor: None, sender: None }, &mut out);
        out
    }

    #[test]
    fn tcp_udp_v6_and_limit() {
        let tcp = parse("[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.4 DST=11.25.39.236 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=1 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0");
        assert_eq!((tcp[0].signal, tcp[0].port), (Signal::FwBlock, Some(23)));
        let udp = parse("[12.3] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.5 DST=11.25.39.236 LEN=50 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=UDP SPT=5 DPT=161 LEN=30");
        assert_eq!((udp[0].port, udp[0].proto), (Some(161), Proto::Udp));
        let v6 = parse("[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=2001:db8::1 DST=2001:db8::2 LEN=80 TC=0 HOPLIMIT=50 FLOWLBL=0 PROTO=TCP SPT=1 DPT=22 WINDOW=1 RES=0x00 SYN URGP=0");
        assert_eq!(v6[0].ip.to_string(), "2001:db8::1");
        let lim = parse("[UFW LIMIT BLOCK] IN=eth0 OUT= MAC=aa SRC=1.2.3.6 DST=11.25.39.236 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=5 DPT=9843 WINDOW=1 RES=0x00 SYN URGP=0");
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
        assert!(parse("[LOGGUARD ACCEPT] IN=eth0 OUT= SRC=198.51.100.9 DPT=22").is_empty());
        let out = parse("[UFW BLOCK] IN= OUT=eth0 SRC=192.0.2.1 DST=203.0.113.7 LEN=60 PROTO=TCP SPT=40000 DPT=25");
        assert_eq!(out[0].port, Some(25), "a blocked packet going out");
    }

    /// A program any local user names and crashes makes the kernel log its name (15 bytes
    /// at most) at the start and its file name further on: neither makes a firewall line.
    #[test]
    fn crashing_programs_cannot_forge_blocks() {
        let forged = [
            "[UFW BLOCK] IN=[4242]: segfault at 0 ip 000055d0c0de1129 sp 00007ffd2a1b8e40 error 4 in [UFW BLOCK] IN= OUT= SRC=203.0.113.9 DPT=23 PROTO=TCP x[55d0c0de1000+1000] likely on CPU 0 (core 0, socket 0)",
            "evil[4242]: segfault at 0 ip 000055d0c0de1129 sp 00007ffd2a1b8e40 error 4 in [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DPT=23 PROTO=TCP x[55d0c0de1000+1000]",
            "traps: [UFW BLOCK][4242] trap invalid opcode ip:55d0 sp:7ffd error:0 in [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DPT=23 PROTO=TCP [55d0+1000]",
            "[UFW BLOCK]IN=[4242]: segfault at 0 ip 0 sp 0 error 4 in OUT= SRC=203.0.113.9 DPT=23 PROTO=TCP",
        ];
        for line in forged {
            assert!(!is_firewall_log(line) && parse(line).is_empty(), "{line}");
        }
    }
}
