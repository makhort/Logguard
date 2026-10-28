// What the page works out (core.js).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  abuseRows, abuseText, abuseSubject, mailto, parseRdap, plainEmail, csv, linkify, parseHash, queryFor, applyQuery,
  drift, niceMax, duration, mergePlaces, reportedSources,
} from "../core.js";

const T = 1793000000000000; // 2026-10-26 07:33 UTC (logguard's microseconds)
const source = (net, events, extra = {}) => ({
  net, first: T, last: T + 60e6, bans: 1, events, activity: "SSH probing / login attempts", members: [],
  evidence: [{ ts: T, server: "vpn", to: "192.0.2.1", text: "failed password login (account name withheld)" }], omitted: 0, ...extra,
});
const report = {
  window: "7d", from: T - 7 * 86400e6, to: T,
  providers: [
    { key: "AS64500", asn: 64500, name: "Example Net", countries: [["NL", "Netherlands"]], sources: [source("198.51.100.7", 5), source("198.51.100.8", 1)] },
    { key: "unknown", asn: null, name: null, countries: [], sources: [source("203.0.113.9", 4)] },
  ],
};

test("abuse rows: worth, search, already mailed", () => {
  const f = { q: "", worth: true, fresh: false };
  let rows = abuseRows(report, f);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].sources.map((x) => x.net), ["198.51.100.7"], "one line isn't worth a mail");
  assert.equal(rows[0].events, 5, "added up again");
  rows = abuseRows(report, { ...f, q: "netherlands" });
  assert.deepEqual(rows.map((p) => p.key), ["AS64500"]);
  const marked = { AS64500: { at: Date.now() - 86400000, sources: ["198.51.100.7"] }, old: { at: Date.now() - 90 * 86400000, sources: ["203.0.113.9"] } };
  assert.deepEqual([...reportedSources(marked)], ["198.51.100.7"], "marks older than 30 days are over");
  rows = abuseRows(report, { ...f, fresh: true }, marked);
  assert.deepEqual(rows.map((p) => p.key), ["unknown"]);
});

test("the e-mail text, and the mailto link that fits", () => {
  const p = report.providers[0];
  const text = abuseText(p, report);
  assert.match(text, /^Hello,\n/);
  assert.match(text, /in your network \(Example Net, AS64500\) attacked our servers/);
  assert.match(text, /\(to 192\.0\.2\.1\) failed password login/);
  assert.ok(!text.includes("vpn"), "never a node's name");
  assert.match(abuseText(p, report, 1), /\.\.\. and 1 more source: all of them are in the attached file/);
  assert.equal(abuseSubject(p, report), "Abuse from your network (AS64500): 2 sources, 2026-10-19 to 2026-10-26");
  const all = mailto(["abuse@example.net"], p, report);
  assert.equal(all.cut, 0);
  assert.ok(all.url.startsWith("mailto:abuse%40example.net?subject=Abuse%20from"));
  const short = mailto(["abuse@example.net"], p, report, 900);
  assert.equal(short.cut, 1, "the second source left for the attached file");
  assert.ok(short.url.length <= 900 || short.cut === p.sources.length - 1);
});

test("RDAP answers: only plain mailboxes", () => {
  const ok = parseRdap({ handle: "NET-1", name: "EXAMPLE", entities: [{ roles: ["registrant"], entities: [{ roles: ["abuse"], vcardArray: ["vcard", [["email", {}, "text", "Abuse@Example.net"]]] }] }] });
  assert.deepEqual(ok, { abuse: ["abuse@example.net"], network: "EXAMPLE, NET-1" });
  const evil = parseRdap({ name: "X\nTo: someone@else", entities: [{ roles: ["abuse"], vcardArray: ["vcard", [["email", {}, "text", "a@b.example\nBcc: x@y.z"], ["email", {}, "text", "ok@isp.example"]]] }] });
  assert.deepEqual(evil.abuse, ["ok@isp.example"]);
  assert.ok(!evil.network.includes("\n"));
  assert.equal(plainEmail("x@y"), null);
  assert.equal(parseRdap(null), null);
  const deep = { entities: [] };
  let at = deep;
  for (let i = 0; i < 50; i++) { const e = { entities: [] }; at.entities.push(e); at = e; }
  assert.deepEqual(parseRdap(deep).abuse, [], "deep nesting stops");
});

test("CSV: quoted, and no formulas from strangers", () => {
  assert.equal(csv([["a", 'say "hi"', "x,y"], ["=cmd|' /C calc'!A0", "+1", "-2", "@SUM(A1)", "line\nbreak"]]),
    'a,"say ""hi""","x,y"\r\n\'=cmd|\' /C calc\'!A0,\'+1,\'-2,\'@SUM(A1),"line\nbreak"\r\n');
});

test("addresses in text", () => {
  const parts = linkify("ban 192.0.2.5 at 10:15:30 for 2001:db8::/32; not 300.1.1.1 or x10.0.0.1 or 192.0.2.50x");
  assert.deepEqual(parts.filter((p) => p.addr).map((p) => p.addr), ["192.0.2.5", "2001:db8::/32"]);
  assert.equal(parts.map((p) => p.text || p.addr).join(""), "ban 192.0.2.5 at 10:15:30 for 2001:db8::/32; not 300.1.1.1 or x10.0.0.1 or 192.0.2.50x");
  assert.deepEqual(linkify("[2001:db8::5]:22 fe80::1").filter((p) => p.addr).map((p) => p.addr), ["2001:db8::5", "fe80::1"]);
});

test("links carry the filters that differ", () => {
  const defaults = { level: "all", q: "", group: false, selected: "" };
  const f = { level: "high", q: "ssh x", group: true, selected: "DE" };
  const qs = queryFor(f, defaults);
  assert.equal(qs, "?level=high&q=ssh+x&group=1");
  const { parts, query } = parseHash(`#/alerts${qs}`);
  assert.deepEqual(parts, ["alerts"]);
  const back = applyQuery({ ...defaults }, defaults, { ...query, evil: "x", selected: "FR" });
  assert.deepEqual(back, { level: "high", q: "ssh x", group: true, selected: "" });
  assert.equal(queryFor(defaults, defaults), "");
  assert.deepEqual(parseHash("#/address/192.0.2.0/24").parts, ["address", "192.0.2.0", "24"]);
});

test("settings that differ between nodes", () => {
  const rows = [{ id: "0", values: { mode: "enforce", v: "0.3.0" } }, { id: "1", values: { mode: "enforce", v: "0.3.0" } }, { id: "2", values: { mode: "shadow", v: "0.3.0" } }];
  const d = drift(rows, ["mode", "v"]);
  assert.deepEqual([...d.mode.differ], ["2"]);
  assert.equal(d.mode.common, "enforce");
  assert.equal(d.v.differ.size, 0);
  const two = drift([{ id: "a", values: { v: "1" } }, { id: "b", values: { v: "2" } }], ["v"]);
  assert.deepEqual([...two.v.differ], ["a", "b"], "no majority: both marked");
});

test("small helpers", () => {
  assert.equal(niceMax(7), 8);
  assert.equal(niceMax(130), 200);
  assert.equal(duration(90061000), "1d 1h");
  assert.equal(duration(61000), "1m");
  const m = mergePlaces([{ key: "DE", name: "Germany", bans: 2, nodes: ["a"] }, { key: "DE", name: "Germany", bans: 3, nodes: ["b", "a"] }]);
  assert.deepEqual(m.map((x) => [x.bans, x.nodes]), [[5, ["a", "b"]]]);
});
