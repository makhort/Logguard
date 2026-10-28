// Just enough of a DOM for dom.js's patching: nodes, attributes, children, listeners.

class FakeNode {
  constructor(type, name) {
    this.nodeType = type;
    this.nodeName = name;
    this.childNodes = [];
    this.parentNode = null;
  }
  get firstChild() { return this.childNodes[0] || null; }
  get nextSibling() {
    const p = this.parentNode;
    return p ? p.childNodes[p.childNodes.indexOf(this) + 1] || null : null;
  }
  get textContent() { return this.nodeType === 3 ? this.nodeValue : this.childNodes.map((c) => c.textContent).join(""); }
  appendChild(n) { return this.insertBefore(n, null); }
  insertBefore(n, ref) {
    if (n.nodeType === 11) {
      for (const c of [...n.childNodes]) this.insertBefore(c, ref);
      return n;
    }
    if (n.parentNode) n.parentNode.removeChild(n);
    const i = ref ? this.childNodes.indexOf(ref) : this.childNodes.length;
    this.childNodes.splice(i < 0 ? this.childNodes.length : i, 0, n);
    n.parentNode = this;
    return n;
  }
  removeChild(n) {
    const i = this.childNodes.indexOf(n);
    if (i >= 0) this.childNodes.splice(i, 1);
    n.parentNode = null;
    return n;
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceWith(n) {
    const p = this.parentNode;
    p.insertBefore(n, this);
    p.removeChild(this);
  }
}

class FakeElement extends FakeNode {
  constructor(tag) {
    super(1, tag.toUpperCase());
    this.attrs = new Map();
    this.style = { setProperty() {} };
    this.listeners = {};
  }
  get attributes() { return [...this.attrs].map(([name, value]) => ({ name, value })); }
  getAttribute(n) { return this.attrs.has(n) ? this.attrs.get(n) : null; }
  setAttribute(n, v) { this.attrs.set(n, String(v)); }
  hasAttribute(n) { return this.attrs.has(n); }
  removeAttribute(n) { this.attrs.delete(n); }
  set className(v) { this.setAttribute("class", v); }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  fire(t) { for (const f of this.listeners[t] || []) f.call(this, { type: t }); }
}

class FakeText extends FakeNode {
  constructor(t) {
    super(3, "#text");
    this.nodeValue = t;
  }
}

export function install() {
  globalThis.Node = FakeNode;
  globalThis.document = {
    activeElement: null,
    createElement: (t) => new FakeElement(t),
    createElementNS: (_, t) => new FakeElement(t),
    createTextNode: (t) => new FakeText(t),
    createDocumentFragment: () => new FakeNode(11, "#document-fragment"),
  };
}
