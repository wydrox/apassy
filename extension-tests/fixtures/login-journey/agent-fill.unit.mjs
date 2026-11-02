// Synthetic service-worker checks, not browser or native-guard acceptance.
import assert from "node:assert/strict";
import { test } from "node:test";
import { loadBackground } from "../passkey-bridge/mock-chrome.mjs";
import fs from "node:fs";
import vm from "node:vm";

test("agent fill sends only a field acknowledgement back to the host", async () => {
  const bg = loadBackground();
  bg.tabs.set(5, "https://example.com/login");
  bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused: true }) };
  const scripts = [];
  bg.chrome.scripting.executeScript = async (details) => {
    scripts.push(details);
    return [{ result: { ok: true, username: true, password: true } }];
  };
  const packets = [];
  bg.setHost((request, { port }) => {
    packets.push(request);
    port.postMessage({ ok: true, data: packets.length === 1 ? {
      type: "agent_fill", receipt: "synthetic-ticket", origin: "https://example.com",
      username: "synthetic-user", password: "synthetic-password", code: "",
    } : { type: "none" } });
  });
  await bg.context.apassyAgentFillTest.pollAgentFill();
  assert.equal(scripts.length, 1);
  assert.deepEqual(Array.from(packets[1].filled), ["username", "password"]);
  assert.equal(JSON.stringify(packets).includes("synthetic-password"), false);
});

test("a changed origin gets no page injection", async () => {
  const bg = loadBackground();
  bg.tabs.set(5, "https://evil.example/login");
  bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused: true }) };
  let injections = 0;
  bg.chrome.scripting.executeScript = async () => { injections++; return []; };
  const packets = [];
  bg.setHost((request, { port }) => {
    packets.push(request);
    port.postMessage({ ok: true, data: packets.length === 1 ? {
      type: "agent_fill", receipt: "synthetic-ticket", origin: "https://example.com",
      username: "synthetic-user", password: "synthetic-password", code: "",
    } : { type: "none" } });
  });
  await bg.context.apassyAgentFillTest.pollAgentFill();
  assert.equal(injections, 0);
  assert.deepEqual(Array.from(packets[1].filled), []);
});

test("the agent visibility guard clears a revealed password and reports no value", () => {
  let notify;
  let disconnected = false;
  const reports = [];
  class Input {
    constructor() { this.type = "password"; this.name = "password"; this._value = ""; }
    get value() { return this._value; }
    set value(value) { this._value = value; }
    getAttribute() { return ""; }
    getBoundingClientRect() { return { width: 100, height: 20 }; }
    getRootNode() { return document; }
    focus() {}
    dispatchEvent() {}
  }
  const input = new Input();
  const document = { querySelectorAll: () => [input] };
  const context = vm.createContext({
    document, HTMLInputElement: Input, location: { origin: "https://example.com" },
    Event: class {}, setTimeout: () => 1, clearTimeout() {}, addEventListener() {},
    MutationObserver: class {
      constructor(callback) { notify = callback; }
      observe() {}
      disconnect() { disconnected = true; }
    },
    chrome: { runtime: { sendMessage: async (message) => { reports.push(message); } } },
  });
  vm.runInContext(fs.readFileSync(new URL("../../../extension/fill.js", import.meta.url), "utf8"), context);
  context.fillLogin("https://example.com", "", "synthetic-password", "login", "synthetic-ticket");
  assert.equal(input.value, "synthetic-password");
  input.type = "text";
  notify();
  assert.equal(input.value, "");
  assert.equal(disconnected, true);
  assert.equal(reports[0].receipt, "synthetic-ticket");
  assert.equal(JSON.stringify(reports).includes("synthetic-password"), false);
});
