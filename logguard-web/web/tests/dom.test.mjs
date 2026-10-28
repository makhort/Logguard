// The in-place refresh (dom.js): what stays the same stays the same node.
import { test } from "node:test";
import assert from "node:assert/strict";
import { install } from "./fake-dom.mjs";

install();
const { h, patch } = await import("../dom.js");

const rows = (keys, label = "") => h("tbody", null, keys.map((k) => h("tr", { "data-k": k }, h("td", null, `${k}${label}`))));

test("unchanged text and elements are kept", () => {
  const root = h("div");
  patch(root, [h("p", { class: "a" }, "hello"), h("span", null, "x")]);
  const [p, text] = [root.childNodes[0], root.childNodes[0].childNodes[0]];
  patch(root, [h("p", { class: "b" }, "hello"), h("span", null, "y")]);
  assert.equal(root.childNodes[0], p, "the same element");
  assert.equal(root.childNodes[0].childNodes[0], text, "the same text node: a selection in it survives");
  assert.equal(p.getAttribute("class"), "b");
  assert.equal(root.childNodes[1].textContent, "y");
});

test("keyed rows keep their elements when a row arrives on top", () => {
  const root = h("table");
  patch(root, [rows(["b", "c"])]);
  const [b, c] = root.childNodes[0].childNodes;
  patch(root, [rows(["a", "b", "c"])]);
  const now = root.childNodes[0].childNodes;
  assert.deepEqual(now.map((r) => r.textContent), ["a", "b", "c"]);
  assert.equal(now[1], b);
  assert.equal(now[2], c);
  patch(root, [rows(["c", "a"])]);
  assert.deepEqual(root.childNodes[0].childNodes.map((r) => r.textContent), ["c", "a"], "gone rows go, moved ones move");
  assert.equal(root.childNodes[0].childNodes[0], c);
});

test("kept elements get the new handlers", () => {
  const root = h("div");
  const seen = [];
  patch(root, [h("button", { onclick: () => seen.push("old") }, "go")]);
  const button = root.childNodes[0];
  patch(root, [h("button", { onclick: () => seen.push("new") }, "go")]);
  assert.equal(root.childNodes[0], button);
  button.fire("click");
  assert.deepEqual(seen, ["new"]);
  patch(root, [h("button", null, "go")]);
  button.fire("click");
  assert.deepEqual(seen, ["new"], "a handler gone is gone");
});

test("parts with a signature are kept or replaced whole", () => {
  const root = h("div");
  patch(root, [h("div", { "data-sig": "1" }, "chart 1")]);
  const chart = root.childNodes[0];
  patch(root, [h("div", { "data-sig": "1" }, "chart 1 again")]);
  assert.equal(root.childNodes[0], chart, "the same data: not redrawn");
  assert.equal(chart.textContent, "chart 1");
  patch(root, [h("div", { "data-sig": "2" }, "chart 2")]);
  assert.notEqual(root.childNodes[0], chart);
  assert.equal(root.childNodes[0].textContent, "chart 2");
});

test("a details the reader opened stays open", () => {
  const root = h("div");
  patch(root, [h("details", null, h("summary", null, "more"))]);
  root.childNodes[0].setAttribute("open", "");
  patch(root, [h("details", null, h("summary", null, "more"))]);
  assert.ok(root.childNodes[0].hasAttribute("open"));
});
