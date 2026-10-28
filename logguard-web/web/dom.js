export const SVG = "http://www.w3.org/2000/svg";

export function add(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false) continue;
    if (Array.isArray(k)) add(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
  return el;
}

// Handlers live in el._on, called through one listener per event type: a refresh patches the
// page in place (see patch) and hands the elements it keeps the new handlers.
export function dispatch(e) {
  const f = this._on && this._on[e.type];
  if (f) return f.call(this, e);
}

export function on(el, type, fn) {
  if (!el._on) el._on = {};
  if (!(type in el._on)) el.addEventListener(type, dispatch);
  el._on[type] = fn;
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) on(el, k.slice(2), v);
    else if (k === "key") el.style.setProperty("--key", v);
    else if (k === "width") el.style.width = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  return add(el, kids);
}

export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined) continue;
    if (k.startsWith("on")) on(el, k.slice(2), v);
    else if (k === "paint") el.style.setProperty("stroke", v);
    else if (k === "fillPaint") el.style.setProperty("fill", v);
    else el.setAttribute(k, v);
  }
  return add(el, kids);
}

// Brings `el` (on the page) to what `want` (just built) shows, changing only what differs: a
// refresh keeps the scroll positions, the text selected, the focus and what was opened. A
// part with `data-sig` (a chart, the map: their handlers hold their own elements) is kept
// while its signature is the same, else replaced whole.
export function morph(el, want) {
  if (el.nodeType !== want.nodeType || el.nodeName !== want.nodeName) { el.replaceWith(want); return; }
  if (el.nodeType !== 1) { if (el.nodeValue !== want.nodeValue) el.nodeValue = want.nodeValue; return; }
  const sig = want.getAttribute("data-sig");
  if (sig !== null || el.hasAttribute("data-sig")) { if (sig !== el.getAttribute("data-sig")) el.replaceWith(want); return; }
  for (const a of [...el.attributes]) {
    // a <details> opened by the reader stays open
    if (!want.hasAttribute(a.name) && !(a.name === "open" && el.nodeName === "DETAILS")) el.removeAttribute(a.name);
  }
  for (const a of want.attributes) if (el.getAttribute(a.name) !== a.value) el.setAttribute(a.name, a.value);
  for (const t of new Set([...Object.keys(el._on || {}), ...Object.keys(want._on || {})])) {
    if (want._on && want._on[t]) on(el, t, want._on[t]);
    else el._on[t] = null;
  }
  if (el.nodeName === "INPUT" && el !== document.activeElement) { el.checked = want.checked; el.value = want.value; }
  patch(el, [...want.childNodes]);
  if (el.nodeName === "SELECT") el.value = want.value;
}

// Patches `parent`'s children to `kids` (as h() takes them). Children with `data-k` are
// matched by it (a new row on top doesn't rewrite every row below), the rest in order.
export function patch(parent, kids) {
  const next = [...add(document.createDocumentFragment(), Array.isArray(kids) ? kids : [kids]).childNodes];
  const key = (n) => (n.nodeType === 1 ? n.getAttribute("data-k") : null);
  const keys = new Set(next.map(key).filter((k) => k !== null));
  const old = new Map();
  for (const c of parent.childNodes) if (key(c) !== null) old.set(key(c), c);
  let cur = parent.firstChild;
  const skipGone = () => { while (cur && key(cur) !== null && !keys.has(key(cur))) { const gone = cur; cur = cur.nextSibling; gone.remove(); } };
  for (const n of next) {
    skipGone();
    const k = key(n);
    if (k !== null) {
      const match = old.get(k);
      old.delete(k);
      if (!match) parent.insertBefore(n, cur);
      else if (match === cur) { cur = cur.nextSibling; morph(match, n); }
      else { parent.insertBefore(match, cur); morph(match, n); }
    } else if (cur && key(cur) === null) {
      const here = cur;
      cur = cur.nextSibling;
      morph(here, n);
    } else parent.insertBefore(n, cur);
  }
  while (cur) { const gone = cur; cur = cur.nextSibling; gone.remove(); }
}

// A view's part rebuilt by `fill` on every refresh and patched into the page.
export function livePart(root, fill) {
  const el = h("div");
  root.appendChild(el);
  return () => {
    const fresh = h("div");
    fill(fresh);
    patch(el, [...fresh.childNodes]);
  };
}
