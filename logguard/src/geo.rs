//! Offline IP -> country and network owner ("Germany / Hetzner Online GmbH (AS24940)").
//!
//! Everything is looked up in memory from database files downloaded once a week, so no
//! address ever leaves the server. Default source: DB-IP's free "lite" databases
//! (CC BY 4.0, monthly, no account; https://db-ip.com): country per address range
//! (geolocated, not just where the network is registered) and the owning network (ASN
//! and organisation name). iptoasn.com's `ip2asn-*.tsv.gz` (public domain) is accepted
//! as the network database too; it carries registry handles instead of company names.

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::time::Dur;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoCfg {
    pub enabled: bool,
    /// `{month}` is replaced by the current `YYYY-MM` (the previous month if that isn't out yet).
    /// Empty = don't use that database.
    pub country_url: String,
    pub asn_url: String,
    /// Downloaded databases are kept here (`country.gz`, `asn.gz`) and reused after restarts.
    pub dir: PathBuf,
    pub refresh: Dur,
    /// Download command; the URL is appended and the file is read from its stdout.
    pub fetch: Vec<String>,
}

impl Default for GeoCfg {
    fn default() -> Self {
        GeoCfg {
            enabled: false,
            country_url: "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz".into(),
            asn_url: "https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz".into(),
            dir: "/var/lib/logguard/geo".into(),
            refresh: Dur(7 * 86_400),
            fetch: ["curl", "-fsSL", "--max-time", "300", "--retry", "2", "--max-filesize", "200000000"].map(String::from).to_vec(),
        }
    }
}

/// What is known about one address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Geo {
    pub country: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

impl Geo {
    pub fn country_name(&self) -> Option<&'static str> {
        self.country.map(|c| country_name(&c))
    }

    /// "Germany / Hetzner Online GmbH (AS24940)", or whichever half is known.
    pub fn label(&self) -> Option<String> {
        let net = match (&self.org, self.asn) {
            (Some(o), Some(n)) => Some(format!("{o} (AS{n})")),
            (None, Some(n)) => Some(format!("AS{n}")),
            (Some(o), None) => Some(o.clone()),
            (None, None) => None,
        };
        match (self.country_name(), net) {
            (Some(c), Some(n)) => Some(format!("{c} / {n}")),
            (Some(c), None) => Some(c.to_string()),
            (None, n) => n,
        }
    }
}

/// Sorted, non-overlapping ranges. IPv6 is kept at /64 granularity (the upper 64 bits),
/// which halves memory; no database distinguishes locations inside a /64.
#[derive(Default)]
struct Ranges<K, V> {
    v: Vec<(K, K, V)>,
}

impl<K: Ord + Copy, V: PartialEq + Copy> Ranges<K, V> {
    fn push(&mut self, start: K, end: K, val: V, adjacent: impl Fn(K, K) -> bool) {
        if let Some(last) = self.v.last_mut() {
            // Neighbouring ranges with the same value merge (e.g. a country's consecutive blocks).
            if last.2 == val && adjacent(last.1, start) {
                last.1 = last.1.max(end);
                return;
            }
        }
        self.v.push((start, end, val));
    }

    fn finish(&mut self) {
        self.v.sort_unstable_by_key(|r| r.0);
        self.v.shrink_to_fit();
    }

    fn get(&self, k: K) -> Option<V> {
        let i = self.v.partition_point(|r| r.0 <= k).checked_sub(1)?;
        let r = self.v[i];
        (k <= r.1).then_some(r.2)
    }
}

/// (country, asn, org index into `orgs`)
type AsVal = ([u8; 2], u32, u32);

#[derive(Default)]
pub struct GeoDb {
    cc4: Ranges<u32, [u8; 2]>,
    cc6: Ranges<u64, [u8; 2]>,
    as4: Ranges<u32, AsVal>,
    as6: Ranges<u64, AsVal>,
    orgs: Vec<String>,
    /// e.g. "country: 712345 ranges, network: 498765 ranges"
    pub summary: String,
}

const NO_CC: [u8; 2] = *b"--";
/// Longest organisation name kept (the longest real ones are about 100 characters).
const MAX_ORG_LEN: usize = 120;

fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

enum Key {
    V4(u32, u32),
    V6(u64, u64),
}

fn key(start: &str, end: &str) -> Option<Key> {
    match (start.trim().parse::<IpAddr>().ok()?, end.trim().parse::<IpAddr>().ok()?) {
        (IpAddr::V4(a), IpAddr::V4(b)) => Some(Key::V4(a.into(), b.into())),
        (IpAddr::V6(a), IpAddr::V6(b)) => Some(Key::V6((u128::from(a) >> 64) as u64, (u128::from(b) >> 64) as u64)),
        _ => None,
    }
}

fn cc(s: &str) -> Option<[u8; 2]> {
    let b = s.trim().as_bytes();
    (b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic) && s.trim() != "ZZ")
        .then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

/// iptoasn descriptions start with the registry handle: "GTELECOM-AS-AP Gtelecom Pty Ltd".
fn tidy_org(desc: &str) -> &str {
    let desc = desc.trim();
    match desc.split_once(' ') {
        Some((handle, rest))
            if !rest.trim().is_empty() && handle.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_') =>
        {
            rest.trim()
        }
        _ => desc,
    }
}

impl GeoDb {
    /// Loads whichever of `<dir>/country.gz` and `<dir>/asn.gz` exist.
    pub fn load(dir: &Path) -> Result<GeoDb> {
        let mut db = GeoDb::default();
        let mut parts = Vec::new();
        for (name, is_country) in [("country.gz", true), ("asn.gz", false)] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
            let n = db
                .read(BufReader::new(flate2::read::GzDecoder::new(file)), is_country)
                .with_context(|| format!("reading {}", path.display()))?;
            parts.push(format!("{} {n} ranges", if is_country { "country" } else { "network" }));
        }
        if parts.is_empty() {
            bail!("no geo database in {} yet", dir.display());
        }
        db.summary = parts.join(", ");
        Ok(db)
    }

    /// Reads one database (CSV or iptoasn TSV); returns the number of ranges kept.
    pub fn read(&mut self, r: impl BufRead, is_country: bool) -> Result<usize> {
        let mut org_ids: std::collections::HashMap<String, u32> =
            self.orgs.iter().enumerate().map(|(i, o)| (o.clone(), i as u32)).collect();
        let mut lines = 0usize;
        for_each_line(r, |line| {
            let f: Vec<String> = if line.contains('\t') { line.split('\t').map(String::from).collect() } else { split_csv(line) };
            let Some(k) = f.get(1).and_then(|end| key(&f[0], end)) else { return };
            lines += 1;
            if is_country {
                // DB-IP: start,end,CC (iptoasn ip2country: start,end,CC)
                let Some(c) = f.get(2).and_then(|c| cc(c)) else { return };
                match k {
                    Key::V4(a, b) => self.cc4.push(a, b, c, |e, s| e.checked_add(1) == Some(s)),
                    Key::V6(a, b) => self.cc6.push(a, b, c, |e, s| e.checked_add(1) == Some(s)),
                }
            } else {
                // DB-IP: start,end,asn,org; iptoasn: start,end,asn,cc,description
                let Some(asn) = f.get(2).and_then(|n| n.trim().parse::<u32>().ok()).filter(|n| *n > 0) else { return };
                let (country, org) =
                    if f.len() >= 5 { (cc(&f[3]).unwrap_or(NO_CC), tidy_org(&f[4])) } else { (NO_CC, f.get(3).map_or("", |s| s.trim())) };
                // Downloaded text that reaches terminals (TUI), XMPP messages and the digest.
                let org = crate::event::clean(org, MAX_ORG_LEN);
                let org = org.as_str();
                let id = match org_ids.get(org) {
                    Some(id) => *id,
                    None => {
                        let id = self.orgs.len() as u32;
                        self.orgs.push(org.to_string());
                        org_ids.insert(org.to_string(), id);
                        id
                    }
                };
                let v = (country, asn, id);
                match k {
                    Key::V4(a, b) => self.as4.push(a, b, v, |e, s| e.checked_add(1) == Some(s)),
                    Key::V6(a, b) => self.as6.push(a, b, v, |e, s| e.checked_add(1) == Some(s)),
                }
            }
        })?;
        if lines == 0 {
            bail!("no address ranges found (not a DB-IP CSV or iptoasn TSV file?)");
        }
        self.orgs.shrink_to_fit();
        let n = if is_country {
            self.cc4.finish();
            self.cc6.finish();
            self.cc4.v.len() + self.cc6.v.len()
        } else {
            self.as4.finish();
            self.as6.finish();
            self.as4.v.len() + self.as6.v.len()
        };
        Ok(n)
    }

    pub fn lookup(&self, ip: IpAddr) -> Geo {
        let (country, net) = match ip {
            IpAddr::V4(a) => {
                let k = u32::from(a);
                (self.cc4.get(k), self.as4.get(k))
            }
            IpAddr::V6(a) => {
                let k = (u128::from(a) >> 64) as u64;
                (self.cc6.get(k), self.as6.get(k))
            }
        };
        // Prefer the geolocated country; the network's registration country is a fallback.
        let country = country.or(net.map(|n| n.0).filter(|c| *c != NO_CC));
        Geo { country, asn: net.map(|n| n.1), org: net.and_then(|n| self.orgs.get(n.2 as usize)).filter(|o| !o.is_empty()).cloned() }
    }

    pub fn label(&self, ip: IpAddr) -> Option<String> {
        self.lookup(ip).label()
    }

    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let k = match ip {
            IpAddr::V4(a) => self.as4.get(u32::from(a)),
            IpAddr::V6(a) => self.as6.get((u128::from(a) >> 64) as u64),
        };
        k.map(|v| v.1)
    }
}

/// Database lines are short and DB-IP's files have ~1-2 million of them: anything far
/// beyond is a broken or hostile download, which must not exhaust the service's memory.
const MAX_LINE: usize = 4096;
const MAX_LINES: usize = 10_000_000;

/// Calls `f` for each line, bounded in line length and count.
fn for_each_line(mut r: impl BufRead, mut f: impl FnMut(&str)) -> Result<()> {
    let mut buf = Vec::new();
    for _ in 0..MAX_LINES {
        buf.clear();
        let n = std::io::Read::take(&mut r, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_LINE && buf.last() != Some(&b'\n') {
            bail!("line longer than {MAX_LINE} bytes: not a geo database");
        }
        f(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']));
    }
    bail!("more than {MAX_LINES} lines: not a geo database")
}

/// Number of usable ranges in a database, as `GeoDb::read` would load them.
fn count_ranges(r: impl BufRead, is_country: bool) -> Result<usize> {
    let mut n = 0;
    for_each_line(r, |line| {
        let f: Vec<String> = if line.contains('\t') { line.split('\t').map(String::from).collect() } else { split_csv(line) };
        let ok = f.get(1).and_then(|end| key(&f[0], end)).is_some()
            && if is_country {
                f.get(2).and_then(|c| cc(c)).is_some()
            } else {
                f.get(2).and_then(|a| a.trim().parse::<u32>().ok()).is_some_and(|a| a > 0)
            };
        n += usize::from(ok);
    })?;
    Ok(n)
}

/// Current and previous `YYYY-MM` (UTC).
fn months(now: crate::time::Micros) -> [String; 2] {
    let (y, m, _) = crate::time::civil_from_days(now.div_euclid(86_400 * crate::time::SEC));
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

/// Largest compressed database accepted (DB-IP's are ~5-10 MB).
const MAX_DOWNLOAD: u64 = 200 << 20;

/// Downloads the databases that are missing or older than `refresh`. Each download is
/// checked (it must decompress and parse) before it replaces the previous copy.
/// Returns what was downloaded, and the problems met.
pub fn refresh(cfg: &GeoCfg, now: crate::time::Micros) -> (Vec<String>, Vec<String>) {
    let (mut done, mut errors) = (Vec::new(), Vec::new());
    let _ = std::fs::create_dir_all(&cfg.dir);
    for (url, name, is_country) in [(&cfg.country_url, "country.gz", true), (&cfg.asn_url, "asn.gz", false)] {
        if url.is_empty() {
            let _ = std::fs::remove_file(cfg.dir.join(name));
            continue;
        }
        let path = cfg.dir.join(name);
        let age = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a.as_secs() < cfg.refresh.0) {
            continue;
        }
        let mut last_err = None;
        for month in months(now) {
            let u = url.replace("{month}", &month);
            // Streamed to a file and validated from there while decompressing: neither the
            // download nor a second database is ever held in memory (MemoryMax=128M).
            let tmp = path.with_extension("tmp");
            let result = (|| -> Result<usize> {
                let mut file = std::fs::File::create(&tmp)?;
                crate::feeds::fetch_into(&cfg.fetch, &u, &mut file, MAX_DOWNLOAD)?;
                file.sync_all()?;
                let gz = flate2::read::GzDecoder::new(std::fs::File::open(&tmp)?);
                let n = count_ranges(BufReader::new(gz), is_country).context("checking the download")?;
                if n < 1000 {
                    bail!("only {n} ranges");
                }
                std::fs::rename(&tmp, &path)?;
                Ok(n)
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            match result {
                Ok(n) => {
                    done.push(format!("{u} ({n} ranges)"));
                    last_err = None;
                    break;
                }
                Err(e) => last_err = Some(format!("{u}: {e:#}")),
            }
            if !url.contains("{month}") {
                break;
            }
        }
        errors.extend(last_err);
    }
    (done, errors)
}

/// Credit line required by DB-IP's CC BY 4.0 licence, for texts that show its data.
pub fn attribution(cfg: &GeoCfg, loaded: bool) -> String {
    let dbip = [&cfg.country_url, &cfg.asn_url].iter().any(|u| u.contains("db-ip.com"));
    if loaded && dbip {
        "\nIP locations: DB-IP.com (CC BY 4.0)\n".into()
    } else {
        String::new()
    }
}

/// English short names of ISO 3166-1 alpha-2 codes.
pub fn country_name(code: &[u8; 2]) -> &'static str {
    let code = std::str::from_utf8(code).unwrap_or("??");
    COUNTRIES.split('|').find_map(|e| e.strip_prefix(code).and_then(|n| n.strip_prefix(' '))).unwrap_or(match code {
        "EU" => "European Union",
        "AP" => "Asia/Pacific",
        _ => "unknown country",
    })
}

/// The code of a country as `country_name` spells it ("Germany" -> DE).
pub fn country_code(name: &str) -> Option<[u8; 2]> {
    COUNTRIES.split('|').find_map(|e| {
        let (code, n) = e.split_once(' ')?;
        (n == name && code.len() == 2).then(|| [code.as_bytes()[0], code.as_bytes()[1]])
    })
}

const COUNTRIES: &str = "AD Andorra|AE United Arab Emirates|AF Afghanistan|AG Antigua and Barbuda|AI Anguilla|AL Albania|AM Armenia|\
AO Angola|AQ Antarctica|AR Argentina|AS American Samoa|AT Austria|AU Australia|AW Aruba|AX Åland Islands|AZ Azerbaijan|\
BA Bosnia and Herzegovina|BB Barbados|BD Bangladesh|BE Belgium|BF Burkina Faso|BG Bulgaria|BH Bahrain|BI Burundi|BJ Benin|\
BL Saint Barthélemy|BM Bermuda|BN Brunei|BO Bolivia|BQ Caribbean Netherlands|BR Brazil|BS Bahamas|BT Bhutan|BV Bouvet Island|\
BW Botswana|BY Belarus|BZ Belize|CA Canada|CC Cocos Islands|CD DR Congo|CF Central African Republic|CG Congo|CH Switzerland|\
CI Côte d'Ivoire|CK Cook Islands|CL Chile|CM Cameroon|CN China|CO Colombia|CR Costa Rica|CU Cuba|CV Cape Verde|CW Curaçao|\
CX Christmas Island|CY Cyprus|CZ Czechia|DE Germany|DJ Djibouti|DK Denmark|DM Dominica|DO Dominican Republic|DZ Algeria|\
EC Ecuador|EE Estonia|EG Egypt|EH Western Sahara|ER Eritrea|ES Spain|ET Ethiopia|FI Finland|FJ Fiji|FK Falkland Islands|\
FM Micronesia|FO Faroe Islands|FR France|GA Gabon|GB United Kingdom|GD Grenada|GE Georgia|GF French Guiana|GG Guernsey|GH Ghana|\
GI Gibraltar|GL Greenland|GM Gambia|GN Guinea|GP Guadeloupe|GQ Equatorial Guinea|GR Greece|GS South Georgia|GT Guatemala|GU Guam|\
GW Guinea-Bissau|GY Guyana|HK Hong Kong|HM Heard and McDonald Islands|HN Honduras|HR Croatia|HT Haiti|HU Hungary|ID Indonesia|\
IE Ireland|IL Israel|IM Isle of Man|IN India|IO British Indian Ocean Territory|IQ Iraq|IR Iran|IS Iceland|IT Italy|JE Jersey|\
JM Jamaica|JO Jordan|JP Japan|KE Kenya|KG Kyrgyzstan|KH Cambodia|KI Kiribati|KM Comoros|KN Saint Kitts and Nevis|KP North Korea|\
KR South Korea|KW Kuwait|KY Cayman Islands|KZ Kazakhstan|LA Laos|LB Lebanon|LC Saint Lucia|LI Liechtenstein|LK Sri Lanka|\
LR Liberia|LS Lesotho|LT Lithuania|LU Luxembourg|LV Latvia|LY Libya|MA Morocco|MC Monaco|MD Moldova|ME Montenegro|\
MF Saint Martin|MG Madagascar|MH Marshall Islands|MK North Macedonia|ML Mali|MM Myanmar|MN Mongolia|MO Macao|\
MP Northern Mariana Islands|MQ Martinique|MR Mauritania|MS Montserrat|MT Malta|MU Mauritius|MV Maldives|MW Malawi|MX Mexico|\
MY Malaysia|MZ Mozambique|NA Namibia|NC New Caledonia|NE Niger|NF Norfolk Island|NG Nigeria|NI Nicaragua|NL Netherlands|\
NO Norway|NP Nepal|NR Nauru|NU Niue|NZ New Zealand|OM Oman|PA Panama|PE Peru|PF French Polynesia|PG Papua New Guinea|\
PH Philippines|PK Pakistan|PL Poland|PM Saint Pierre and Miquelon|PN Pitcairn|PR Puerto Rico|PS Palestine|PT Portugal|PW Palau|\
PY Paraguay|QA Qatar|RE Réunion|RO Romania|RS Serbia|RU Russia|RW Rwanda|SA Saudi Arabia|SB Solomon Islands|SC Seychelles|\
SD Sudan|SE Sweden|SG Singapore|SH Saint Helena|SI Slovenia|SJ Svalbard and Jan Mayen|SK Slovakia|SL Sierra Leone|SM San Marino|\
SN Senegal|SO Somalia|SR Suriname|SS South Sudan|ST São Tomé and Príncipe|SV El Salvador|SX Sint Maarten|SY Syria|SZ Eswatini|\
TC Turks and Caicos Islands|TD Chad|TF French Southern Territories|TG Togo|TH Thailand|TJ Tajikistan|TK Tokelau|TL Timor-Leste|\
TM Turkmenistan|TN Tunisia|TO Tonga|TR Türkiye|TT Trinidad and Tobago|TV Tuvalu|TW Taiwan|TZ Tanzania|UA Ukraine|UG Uganda|\
UM US Minor Outlying Islands|US United States|UY Uruguay|UZ Uzbekistan|VA Vatican City|VC Saint Vincent and the Grenadines|\
VE Venezuela|VG British Virgin Islands|VI US Virgin Islands|VN Vietnam|VU Vanuatu|WF Wallis and Futuna|WS Samoa|XK Kosovo|\
YE Yemen|YT Mayotte|ZA South Africa|ZM Zambia|ZW Zimbabwe";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn hostile_files_are_rejected() {
        let long = format!("1.0.0.0,1.0.0.255,{}\n", "A".repeat(10_000));
        assert!(count_ranges(long.as_bytes(), true).unwrap_err().to_string().contains("line longer"));
        let ok = "1.0.0.0,1.0.0.255,AU\r\n1.0.1.0,1.0.1.255,CN\n";
        assert_eq!(count_ranges(ok.as_bytes(), true).unwrap(), 2);
    }

    pub(crate) fn sample() -> GeoDb {
        let mut db = GeoDb::default();
        let country = "0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n5.9.0.0,5.9.127.255,DE\n5.9.128.0,5.9.255.255,DE\n\
                       11.28.0.0,11.28.255.255,FI\n3fff:100::,3fff:100:ffff:ffff:ffff:ffff:ffff:ffff,DE\n";
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n5.9.0.0,5.9.255.255,24940,\"Hetzner Online GmbH\"\n\
                   11.28.0.0,11.28.255.255,24940,\"Hetzner Online GmbH\"\n3fff:100::,3fff:100:ffff:ffff:ffff:ffff:ffff:ffff,24940,\"Hetzner Online GmbH\"\n";
        assert_eq!(db.read(country.as_bytes(), true).unwrap(), 4, "ZZ dropped, adjacent DE blocks merged");
        assert_eq!(db.read(asn.as_bytes(), false).unwrap(), 4);
        db
    }

    #[test]
    fn lookups_and_labels() {
        let db = sample();
        let l = |ip: &str| db.label(ip.parse().unwrap());
        assert_eq!(l("5.9.200.1").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("11.28.3.4").as_deref(), Some("Finland / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.0.1").as_deref(), Some("Australia / Cloudflare, Inc. (AS13335)"));
        assert_eq!(l("3fff:100:1:2::3").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.1.1"), None);
        assert_eq!(l("0.1.2.3"), None);
        assert_eq!(db.asn("11.28.3.4".parse().unwrap()), Some(24940));
    }

    #[test]
    fn org_names_are_cleaned() {
        let mut db = GeoDb::default();
        let asn =
            format!("1.0.0.0,1.0.0.255,13335,\"Evil\x1b]0;pwned\x07 Corp\u{9b}31m\"\n2.0.0.0,2.0.0.255,64500,\"{}\"\n", "x".repeat(500));
        db.read(asn.as_bytes(), false).unwrap();
        assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Evil]0;pwned Corp31m (AS13335)"));
        let long = db.lookup("2.0.0.1".parse().unwrap()).org.unwrap();
        assert_eq!(long.chars().count(), MAX_ORG_LEN + 1, "capped, with an ellipsis");
    }

    #[test]
    fn iptoasn_format() {
        let mut db = GeoDb::default();
        let tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
                   1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n";
        assert_eq!(db.read(tsv.as_bytes(), false).unwrap(), 2, "unrouted ranges skipped");
        let g = db.lookup("1.0.5.5".parse().unwrap());
        assert_eq!(g.label().as_deref(), Some("Australia / Gtelecom Pty Ltd (AS38803)"), "registration country as fallback");
        assert_eq!(db.label("1.0.0.9".parse().unwrap()).as_deref(), Some("United States / CLOUDFLARENET (AS13335)"));
        assert!(db.read("garbage\n".as_bytes(), true).is_err());
        assert_eq!(count_ranges(tsv.as_bytes(), false).unwrap(), 2);
        assert_eq!(count_ranges("1.0.0.0,1.0.0.255,AU\nx,y,z\n".as_bytes(), true).unwrap(), 1);
    }

    #[test]
    fn helpers() {
        assert_eq!(
            split_csv(r#"1.0.0.0,1.0.0.255,13335,"Cloudflare, ""Inc."""#),
            vec!["1.0.0.0", "1.0.0.255", "13335", "Cloudflare, \"Inc.\""]
        );
        assert_eq!(country_name(b"DE"), "Germany");
        assert_eq!(country_name(b"ZW"), "Zimbabwe");
        assert_eq!(country_name(b"AD"), "Andorra");
        assert_eq!(country_name(b"QQ"), "unknown country");
        // 2026-01-15: current and previous month
        assert_eq!(months(20_468 * 86_400 * crate::time::SEC), ["2026-01".to_string(), "2025-12".to_string()]);
    }
}
