// Synthetic service-worker checks, not browser or native-guard acceptance.
import assert from "node:assert/strict";
import { test } from "node:test";
import { loadBackground } from "../passkey-bridge/mock-chrome.mjs";
import fs from "node:fs";
import vm from "node:vm";

function agentBackground() {
  const bg = loadBackground();
  bg.chrome.tabs.query = async () => [...bg.tabs].map(([id, url]) => ({ id, url, active: true, windowId: 1 }));
  bg.chrome.tabs.get = async id => {
    if (!bg.tabs.has(id)) throw new Error("Tab closed");
    return { id, url: bg.tabs.get(id), active: true, windowId: 1 };
  };
  bg.chrome.webNavigation = { getFrame: async () => ({ documentId: "DOC-1", documentLifecycle: "active" }) };
  return bg;
}

test("agent fill sends only a field acknowledgement back to the host", async () => {
  const bg = agentBackground();
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
      document: request.document,
      username: "synthetic-user", password: "synthetic-password", code: "",
    } : { type: "none" } });
  });
  await bg.context.apassyAgentFillTest.pollAgentFill();
  assert.equal(scripts.length, 1);
  assert.deepEqual(Array.from(scripts[0].target.documentIds), ["DOC-1"]);
  assert.deepEqual(Array.from(packets[1].filled), ["username", "password"]);
  assert.equal(JSON.stringify(packets).includes("synthetic-password"), false);
});

test("a changed origin gets no page injection", async () => {
  const bg = agentBackground();
  bg.tabs.set(5, "https://evil.example/login");
  bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused: true }) };
  let injections = 0;
  bg.chrome.scripting.executeScript = async () => { injections++; return []; };
  const packets = [];
  bg.setHost((request, { port }) => {
    packets.push(request);
    port.postMessage({ ok: true, data: packets.length === 1 ? {
      type: "agent_fill", receipt: "synthetic-ticket", origin: "https://example.com",
      document: request.document,
      username: "synthetic-user", password: "synthetic-password", code: "",
    } : { type: "none" } });
  });
  await bg.context.apassyAgentFillTest.pollAgentFill();
  assert.equal(injections, 0);
  assert.deepEqual(Array.from(packets[1].filled), []);
});

for (const changed of ["window_id", "tab_id", "document_id", "generation"]) {
  test(`a changed ${changed} gets no injection, even on the same origin`, async () => {
    const bg = agentBackground();
    bg.tabs.set(5, "https://example.com/login");
    bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused: true }) };
    let injections = 0;
    bg.chrome.scripting.executeScript = async () => { injections++; return []; };
    bg.setHost((request, { port }) => {
      const document = { ...request.document };
      document[changed] = typeof document[changed] === "number" ? 99 : "changed";
      port.postMessage({ ok: true, data: request.receipt ? { type: "none" } : {
        type: "agent_fill", receipt: "ticket", origin: "https://example.com",
        document, username: "", password: "synthetic-password", code: "",
      } });
    });
    await bg.context.apassyAgentFillTest.pollAgentFill();
    assert.equal(injections, 0);
  });
}

test("focusing Apassy retains the selected document in an unfocused poll", async () => {
  const bg = agentBackground();
  bg.tabs.set(5, "https://example.com/login");
  let focused = true;
  bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused }) };
  const packets = [];
  bg.setHost((request, { port }) => { packets.push(request); port.postMessage({ ok: true, data: { type: "none" } }); });
  await bg.context.apassyAgentFillTest.pollAgentFill();
  focused = false;
  await bg.context.apassyAgentFillTest.pollAgentFill();
  assert.equal(packets[1].focused, false);
  assert.deepEqual(packets[1].document, packets[0].document);
  assert.equal(packets[1].url, packets[0].url);
});

for (const change of ["navigation", "close", "focus"]) {
  test(`${change} while the host answers refuses the bound delivery`, async () => {
    const bg = agentBackground();
    bg.tabs.set(5, "https://example.com/login");
    let focused = true;
    bg.chrome.windows = { getLastFocused: async () => ({ id: 1, focused }) };
    let injections = 0;
    bg.chrome.scripting.executeScript = async () => { injections++; return []; };
    bg.setHost((request, { port }) => {
      if (!request.receipt) {
        if (change === "navigation") bg.chrome.webNavigation.getFrame = async () => ({ documentId: "DOC-2", documentLifecycle: "active" });
        if (change === "close") bg.tabs.delete(5);
        if (change === "focus") focused = false;
      }
      port.postMessage({ ok: true, data: request.receipt ? { type: "none" } : {
        type: "agent_fill", receipt: "ticket", origin: "https://example.com",
        document: request.document, username: "", password: "synthetic-password", code: "",
      } });
    });
    await bg.context.apassyAgentFillTest.pollAgentFill();
    assert.equal(injections, 0);
  });
}

test("the agent visibility guard clears a password revealed after three minutes", async () => {
  const clock = loadBackground().clock;
  const intervals = new Map();
  let nextInterval = 0;
  let notify;
  let disconnected = false;
  const reports = [];
  class Input {
    constructor() { this.type = "password"; this.name = "password"; this._value = ""; this.isConnected = true; }
    get value() { return this._value; }
    set value(value) { this._value = value; }
    getAttribute() { return ""; }
    getBoundingClientRect() { return { width: 100, height: 20 }; }
    getRootNode() { return document; }
    focus() {}
    dispatchEvent() {}
  }
  const input = new Input();
  const document = { querySelectorAll: () => [input], hasFocus: () => true };
  const context = vm.createContext({
    document, HTMLInputElement: Input, location: { origin: "https://example.com" },
    Event: class {}, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    setInterval(callback, ms) {
      const id = ++nextInterval;
      const tick = () => { callback(); if (intervals.has(id)) intervals.set(id, clock.setTimeout(tick, ms)); };
      intervals.set(id, clock.setTimeout(tick, ms));
      return id;
    },
    clearInterval(id) { clock.clearTimeout(intervals.get(id)); intervals.delete(id); },
    addEventListener() {}, removeEventListener() {},
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
  await clock.advance(180001);
  assert.equal(disconnected, false);
  assert.equal(input.value, "synthetic-password");
  input.type = "text";
  notify();
  assert.equal(input.value, "");
  assert.equal(disconnected, true);
  assert.equal(reports[0].receipt, "synthetic-ticket");
  assert.equal(JSON.stringify(reports).includes("synthetic-password"), false);
});
