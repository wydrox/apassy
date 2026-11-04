// Isolated-world lifecycle regression; real layout/visibility is checked by CDP.
import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import vm from "node:vm";

test("only the worker stop message clears typed references and stops further tracking", () => {
  const listeners = new Map(), messages = [], tracked = new Map();
  class Input { constructor() { this.type = "password"; this.value = "synthetic"; } }
  const field = new Input();
  const context = vm.createContext({
    document: { addEventListener: (name, fn) => listeners.set(name, fn) },
    HTMLInputElement: Input, clearTimeout, setTimeout,
    addEventListener() {},
    chrome: { runtime: { id: "extension", sendMessage: async () => ({ ok: true }),
      onMessage: { addListener: (fn) => messages.push(fn) } } },
    apassyLoginTarget: { typedTracker: () => ({
      input: (el, trusted) => { if (trusted) tracked.set(el, el.value); },
      clearAll: () => tracked.clear(), clear: (el) => tracked.delete(el),
    }) },
  });
  context.self = context.top = context;
  vm.runInContext(fs.readFileSync(new URL("../../../extension/login-save.js", import.meta.url), "utf8"), context);
  const input = () => listeners.get("input")({ composedPath: () => [field], isTrusted: true });
  input(); assert.equal(tracked.size, 1);
  for (const sender of [{ id: "another-extension" }, { id: "extension", tab: { id: 5 } }]) {
    messages[0]({ type: "login_features_stop" }, sender); assert.equal(tracked.size, 1);
  }
  messages[0]({ type: "login_features_stop" }, { id: "extension" });
  assert.equal(tracked.size, 0); input(); assert.equal(tracked.size, 0);
});

// The content script with a fake DOM that counts its banners and its offer requests.
function savePage() {
  const page = { offers: 0, banners: [], listeners: new Map(), offer: { id: "offer-1" } };
  class Element {
    constructor() { this.children = []; this.isConnected = false; }
    setAttribute() {}
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    addEventListener() {}
    attachShadow() { const root = new Element(); root.querySelectorAll = () => []; return root; }
    remove() { this.isConnected = false; }
    showPopover() {}
    matches() { return true; }
    checkVisibility() { return true; }
  }
  const documentElement = new Element();
  documentElement.append = (node) => { node.isConnected = true; page.banners.push(node); };
  class IntersectionObserverEntry {}
  IntersectionObserverEntry.prototype.isVisible = false;
  const context = vm.createContext({
    document: { addEventListener() {}, createElement: () => new Element(), documentElement, visibilityState: "visible" },
    HTMLInputElement: class {}, IntersectionObserverEntry, performance,
    IntersectionObserver: class { observe() {} takeRecords() { return []; } disconnect() {} },
    // No real timers: the banner would otherwise end the test after its lifetime.
    setTimeout: () => 0, clearTimeout() {},
    addEventListener: (name, fn) => page.listeners.set(name, fn),
    chrome: { runtime: { id: "extension", getURL: (file) => `chrome-extension://extension/${file}`,
      onMessage: { addListener() {} },
      sendMessage: async (message) => {
        if (message.type !== "login_save_offer") return { ok: true };
        page.offers += 1;
        return { ok: true, offer: { ...page.offer, site: "localhost", username: "new@example.test", mode: "save", until: Date.now() + 60_000 } };
      } } },
    apassyLoginTarget: { typedTracker: () => ({ input() {}, clearAll() {}, clear() {} }) },
  });
  context.self = context.top = context;
  page.context = context;
  page.run = () => vm.runInContext(fs.readFileSync(new URL("../../../extension/login-save.js", import.meta.url), "utf8"), context);
  page.settle = () => new Promise((resolve) => setImmediate(resolve));
  page.shown = () => page.banners.filter((banner) => banner.isConnected);
  return page;
}

test("the first pageshow of a document asks for no second offer; a page back from the cache does", async () => {
  const page = savePage();
  page.run(); await page.settle();
  assert.equal(page.offers, 1); assert.equal(page.banners.length, 1);
  // A script that ran before the load event sees the first pageshow of its document.
  page.listeners.get("pageshow")({ persisted: false }); await page.settle();
  assert.equal(page.offers, 1); assert.equal(page.banners.length, 1);
  assert.deepEqual(page.shown(), page.banners);
  page.listeners.get("pagehide")(); assert.equal(page.shown().length, 0);
  page.listeners.get("pageshow")({ persisted: true }); await page.settle();
  assert.equal(page.offers, 2); assert.equal(page.shown().length, 1);
});

test("a second resume of the same offer keeps its banner; another offer replaces it", async () => {
  const page = savePage();
  page.run(); await page.settle();
  const [first] = page.banners;
  // A new injection of the scripts into this document resumes the one already there.
  page.run(); await page.settle();
  assert.equal(page.offers, 2); assert.equal(page.banners.length, 1); assert.equal(first.isConnected, true);
  page.offer = { id: "offer-2" };
  page.context.apassyLoginSave.resume(); await page.settle();
  assert.equal(page.banners.length, 2); assert.equal(first.isConnected, false);
  assert.deepEqual(page.shown(), [page.banners[1]]);
});
