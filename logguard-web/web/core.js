// logguard console: what the page works out, apart from the page itself, so it can be tested
// without a browser (`node --test web/tests`). Nothing here touches the DOM.

export const ms = (t) => t / 1000;

export function duration(msecs) {
  let sec = Math.max(0, Math.round(msecs / 1000));
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const hr = Math.floor(sec / 3600); sec -= hr * 3600;
  const m = Math.floor(sec / 60); sec -= m * 60;
  if (d) return hr ? `${d}d ${hr}h` : `${d}d`;
  if (hr) return m ? `${hr}h ${m}m` : `${hr}h`;
  if (m) return `${m}m`;
  return `${sec}s`;
}

export function compact(n) {
  if (n >= 1e6) return `${+(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${+(n / 1e3).toFixed(1)}K`;
  return String(n);
}

export function matches(q, ...fields) {
  if (!q) return true;
  const needle = q.toLowerCase();
  return fields.some((f) => f !== null && f !== undefined && String(f).toLowerCase().includes(needle));
}

// A round top for the axis whose half is a whole number too (counts have no halves).
export function niceMax(v) {
  v = Math.max(2, v);
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const k of p === 1 ? [2, 4, 6, 8, 10] : [1, 2, 4, 5, 6, 8, 10]) if (k * p >= v) return k * p;
  return 10 * p;
}

// Places of several lists added up by key (a network spanning the countries picked).
export function mergePlaces(list) {
  const by = new Map();
  for (const p of list) {
    const e = by.get(p.key) || { key: p.key, name: p.name, country: p.country, bans: 0, offenders: 0, events: 0, nodes: [] };
    e.bans += p.bans || 0; e.offenders += p.offenders || 0; e.events += p.events || 0;
    e.nodes = [...new Set([...e.nodes, ...(p.nodes || [])])].sort();
    by.set(p.key, e);
  }
  return [...by.values()];
}

export function mergePorts(lists) {
  const by = new Map();
  for (const l of lists) for (const [port, n] of l || []) by.set(port, (by.get(port) || 0) + n);
  return [...by.entries()];
}

// What the weekly report leaves out: one blocked packet isn't worth a mail.
export const WORTH = 3;

// How long a source counts as reported after its provider was marked mailed.
export const REPORTED_DAYS = 30;

// The sources reported lately (`reported`: provider key -> {at, sources}), as a set.
export function reportedSources(reported, now = Date.now()) {
  const out = new Set();
  for (const r of Object.values(reported || {})) {
    if (r && now - r.at < REPORTED_DAYS * 86400000) for (const n of r.sources || []) out.add(n);
  }
  return out;
}

// The sources worth showing and the providers left with any, added up again. `f.fresh` leaves
// out the sources reported lately (`reported`, as above).
export function abuseRows(report, f, reported = {}, now = Date.now()) {
  const out = [];
  const done = f.fresh ? reportedSources(reported, now) : new Set();
  for (const p of report.providers || []) {
    const country = p.countries.map(([c, n]) => `${c} ${n}`).join(" ");
    const sources = p.sources.filter((x) => (!f.worth || x.events >= WORTH) && !done.has(x.net)
      && matches(f.q, p.name, p.key, country, x.net, x.activity, (x.members || []).join(" ")));
    if (!sources.length) continue;
    const sum = (k) => sources.reduce((a, x) => a + (x[k] || 0), 0);
    out.push({ ...p, sources, bans: sum("bans"), events: sum("events"), first: Math.min(...sources.map((x) => x.first)), last: Math.max(...sources.map((x) => x.last)) });
  }
  return out;
}

export const utc = (t) => `${new Date(ms(t)).toISOString().slice(0, 19).replace("T", " ")} UTC`;

export const providerName = (p) => p.name || (p.asn ? `AS${p.asn}` : "Unknown network");

// One provider's part as an e-mail to its abuse desk, like the weekly report's: the
// attacked servers by their public address, never by the nodes' names. `limit`: only the first
// sources (a mailto: link can't carry much), saying how many more the attached file has.
export function abuseText(p, report, limit = Infinity) {
  const n = p.sources.length;
  const lines = [
    "Hello,",
    "",
    `the following ${n === 1 ? "address" : `${n} addresses or networks`} in your network (${providerName(p)}${p.asn && p.name ? `, AS${p.asn}` : ""}) attacked our servers`,
    `between ${utc(report.from)} and ${utc(report.to)}. Please investigate and stop the abuse.`,
    "The evidence is taken from our server logs (firewall and the attacked services); all times",
    "are UTC and account names are withheld.",
  ];
  for (const x of p.sources.slice(0, limit)) {
    lines.push("", "--------------------------------------------------------------------------");
    lines.push(`Source: ${x.net}${x.country_name ? `   [${x.country_name}]` : ""}`);
    lines.push(`Seen: ${utc(x.first)} - ${utc(x.last)} (${x.bans} incident${x.bans === 1 ? "" : "s"})`);
    lines.push(`Activity: ${x.activity || "malicious activity"}`);
    if ((x.members || []).length) lines.push(`Addresses involved: ${x.members.join(", ")}`);
    if ((x.evidence || []).length) {
      lines.push("Log excerpt:");
      for (const l of x.evidence) lines.push(`  ${utc(l.ts)}  ${l.to ? `(to ${l.to}) ` : ""}${l.text}`);
      if (x.omitted) lines.push(`  ... and ${x.omitted} more`);
    }
  }
  if (n > limit) lines.push("", `... and ${n - limit} more source${n - limit === 1 ? "" : "s"}: all of them are in the attached file.`);
  return `${lines.join("\n")}\n`;
}

export function abuseSubject(p, report) {
  const n = p.sources.length;
  const day = (t) => utc(t).slice(0, 10);
  return `Abuse from your network${p.asn ? ` (AS${p.asn})` : ""}: ${n} source${n === 1 ? "" : "s"}, ${day(report.from)} to ${day(report.to)}`;
}

// A mailto: link to the provider's abuse desk with the report in it, as many sources as fit in
// `max` characters (mail programs cut long links): {url, cut} (sources left out).
export function mailto(addresses, p, report, max = 6000) {
  const subject = encodeURIComponent(abuseSubject(p, report));
  const to = addresses.map(encodeURIComponent).join(",");
  for (let limit = p.sources.length; ; limit--) {
    const url = `mailto:${to}?subject=${subject}&body=${encodeURIComponent(abuseText(p, report, limit))}`;
    if (url.length <= max || limit <= 1) return { url, cut: p.sources.length - limit };
  }
}

// ------------------------------------------------------------------ RDAP

// RDAP data is written by the network's owner, who may be the attacker: only plain e-mail
// addresses are taken, as by the console (src/rdap.rs) and logguard's weekly report.
export function plainEmail(e) {
  if (typeof e !== "string") return null;
  e = e.trim().toLowerCase();
  const ok = e.length <= 100 && e.split("@").length === 2 && !e.startsWith("@") && e.includes(".") && /^[a-z0-9@._+-]+$/.test(e);
  return ok ? e : null;
}

// The abuse mailboxes and the network's name in an RDAP answer (parsed JSON).
export function parseRdap(v) {
  if (!v || typeof v !== "object") return null;
  const abuse = [];
  const walk = (o, depth) => {
    if (depth > 8) return;
    for (const e of Array.isArray(o.entities) ? o.entities : []) {
      if (!e || typeof e !== "object") continue;
      if (Array.isArray(e.roles) && e.roles.includes("abuse") && Array.isArray(e.vcardArray) && Array.isArray(e.vcardArray[1])) {
        for (const item of e.vcardArray[1]) {
          const m = Array.isArray(item) && item[0] === "email" ? plainEmail(item[3]) : null;
          if (m && !abuse.includes(m)) abuse.push(m);
        }
      }
      walk(e, depth + 1);
    }
  };
  walk(v, 0);
  const name = typeof v.name === "string" ? v.name : "";
  const handle = typeof v.handle === "string" ? v.handle : "";
  const network = (name && handle ? `${name}, ${handle}` : name || handle).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, 100);
  return { abuse: abuse.slice(0, 5), network };
}

// ------------------------------------------------------------------ exports, links

// CSV (RFC 4180), safe to open in a spreadsheet: what came from strangers (log lines, network
// names) can't become a formula.
export function csv(rows) {
  const cell = (v) => {
    let t = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`;
    return /[",\r\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
  };
  return rows.map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

const IPV4 = String.raw`(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?`;
// IPv6 loosely here, checked by v6ok
const IPV6 = String.raw`[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:\/\d{1,3})?`;
const ADDRESS = new RegExp(`(?<![\\w.:/])(?:${IPV4}|${IPV6})(?![\\w.:])`, "g");

function v6ok(a) {
  const [addr, prefix] = a.split("/");
  if (prefix !== undefined && !(Number(prefix) <= 128)) return false;
  const halves = addr.split("::");
  if (halves.length > 2) return false;
  const groups = (h) => (h === "" ? [] : h.split(":"));
  const all = halves.flatMap(groups);
  if (all.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return halves.length === 2 ? all.length <= 7 : all.length === 8;
}

// Text split into plain pieces and addresses (with their networks): [{text} | {addr}].
export function linkify(text) {
  text = String(text);
  const out = [];
  let at = 0;
  for (const m of text.matchAll(ADDRESS)) {
    if (m[0].includes(":") && !v6ok(m[0])) continue;
    if (m.index > at) out.push({ text: text.slice(at, m.index) });
    out.push({ addr: m[0] });
    at = m.index + m[0].length;
  }
  if (at < text.length) out.push({ text: text.slice(at) });
  return out;
}

// "#/alerts?level=high&q=ssh" as {parts: ["alerts"], query: {level: "high", q: "ssh"}}.
export function parseHash(hash) {
  const [path, qs] = String(hash).replace(/^#\/?/, "").split("?");
  const parts = path.split("/").filter((p, i) => p !== "" || i === 0).map((p) => { try { return decodeURIComponent(p); } catch (_) { return p; } });
  const query = {};
  for (const [k, v] of new URLSearchParams(qs || "")) query[k] = v;
  return { parts, query };
}

// A view's filters as a query string: only what differs from their defaults ("" when none).
export function queryFor(filters, defaults) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filters || {})) {
    if (k === "selected" || v === (defaults || {})[k]) continue;
    q.set(k, typeof v === "boolean" ? (v ? "1" : "0") : String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

// Applies a query to a view's filters, each value as its default's type; unknown keys are left out.
export function applyQuery(filters, defaults, query) {
  for (const [k, v] of Object.entries(query || {})) {
    if (!(k in (defaults || {})) || k === "selected") continue;
    const d = defaults[k];
    if (typeof d === "boolean") filters[k] = v === "1" || v === "true";
    else if (typeof d === "string") filters[k] = v.slice(0, 200);
  }
  return filters;
}

// For each setting, the value most nodes have, and which nodes differ: {key: {common, differ: Set}}
// (all of them when no value has a majority).
export function drift(rows, keys) {
  const out = {};
  for (const k of keys) {
    const counts = new Map();
    for (const r of rows) {
      const v = JSON.stringify(r.values[k] ?? null);
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const common = sorted[0];
    // no value most nodes share (two nodes, two values): every node differs
    const tie = sorted.length > 1 && sorted[1][1] === common[1];
    const differ = new Set(rows.filter((r) => counts.size > 1 && (tie || JSON.stringify(r.values[k] ?? null) !== common[0])).map((r) => r.id));
    out[k] = { common: common ? JSON.parse(common[0]) : null, differ };
  }
  return out;
}
