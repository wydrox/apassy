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
