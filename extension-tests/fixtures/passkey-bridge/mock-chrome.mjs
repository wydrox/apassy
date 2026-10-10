// A mock of the chrome APIs that the extension uses, for node unit checks.
//
// loadBackground() runs extension/background.js (and fill.js) in a fresh vm
// context with a fake clock. The test plays the browser: it opens runtime ports
// with a sender of its choice (as the browser fills port.sender), answers on
// native ports, and decides what chrome.tabs.get says.
//
// loadPage() runs passkey-page.js and passkey-bridge.js against a small fake
// DOM (window events, CredentialsContainer, PublicKeyCredential). Its
// chrome.runtime.connect goes to a background from loadBackground(), so a test
// can drive navigator.credentials end to end.

import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const EXTENSION_DIR = path.resolve(HERE, "../../../extension");
export const EXTENSION_ID = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
const MANIFEST = JSON.parse(fs.readFileSync(path.join(EXTENSION_DIR, "manifest.json"), "utf8"));
const source = (name) => fs.readFileSync(path.join(EXTENSION_DIR, name), "utf8");

export const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

function event() {
  const listeners = [];
  return {
    listeners,
    addListener: (fn) => listeners.push(fn),
    removeListener: (fn) => { const i = listeners.indexOf(fn); if (i >= 0) listeners.splice(i, 1); },
    fire: (...args) => listeners.slice().map((fn) => fn(...args)),
  };
}

// Two ends of a port. A message is cloned and arrives a little later, as in
// the browser. Closing one end fires onDisconnect on the other end only.
export function portPair(name, sender, setLastError) {
  const make = () => ({ name, onMessage: event(), onDisconnect: event(), closed: false, received: [] });
  const a = make();
  const b = make();
  a.sender = sender;
  b.sender = sender;
  const link = (from, to) => {
    from.postMessage = (message) => {
      if (from.closed) throw new Error("Attempting to use a disconnected port object");
      const copy = structuredClone(message);
      setImmediate(() => {
        if (to.closed) return;
        to.received.push(copy);
        to.onMessage.fire(copy, to);
      });
    };
    from.disconnect = (errorMessage) => {
      if (from.closed) return;
      from.closed = true;
      setImmediate(() => {
        if (to.closed) return;
        to.closed = true;
        if (setLastError) setLastError(errorMessage);
        to.onDisconnect.fire(to);
        if (setLastError) setLastError(undefined);
      });
    };
  };
  link(a, b);
  link(b, a);
  return [a, b];
}

class FakeClock {
  constructor() {
    this.now = 0;
    this.timers = new Map();
    this.next = 1;
  }
  setTimeout = (fn, ms = 0) => {
    const id = this.next++;
    this.timers.set(id, { at: this.now + Math.max(0, ms), fn });
    return id;
  };
  clearTimeout = (id) => { this.timers.delete(id); };
  async advance(ms) {
    const end = this.now + ms;
    for (;;) {
      const due = [...this.timers.entries()].filter(([, t]) => t.at <= end).sort((x, y) => x[1].at - y[1].at)[0];
      if (!due) break;
      this.timers.delete(due[0]);
      this.now = due[1].at;
      due[1].fn();
      await flush();
    }
    this.now = end;
    await flush();
  }
}

// A sender as the browser fills it for the bridge in the top frame of a tab.
export function senderFor(origin, extra = {}) {
  return {
    id: EXTENSION_ID,
    tab: { id: 5, url: `${origin}/login`, ...(extra.tab || {}) },
    frameId: 0,
    documentId: "DOC-1",
    documentLifecycle: "active",
    origin,
    url: `${origin}/login`,
    ...extra,
  };
}

export function loadBackground({ permissions = [] } = {}) {
  const clock = new FakeClock();
  const natives = [];
  const registered = new Map();
  const granted = new Set(permissions);
  const tabs = new Map();
  // documentId -> the origin of that document. A test sets it for its sender.
  const documents = new Map();
  const scripts = [];
  const badge = { text: "", title: "Apassy" };
  let lastError;
  let nativeMode = "ok";
  let host = null;

  const runtime = {
    id: EXTENSION_ID,
    getURL: (p = "") => `chrome-extension://${EXTENSION_ID}/${p}`,
    getManifest: () => structuredClone(MANIFEST),
    get lastError() { return lastError ? { message: lastError } : undefined; },
    onConnect: event(),
    onMessage: event(),
    getContexts: async () => [],
    connectNative(name) {
      if (name !== "com.wydrox.apassy") throw new Error("bad host name");
      const [mine, theirs] = portPair(name, undefined, (m) => { lastError = m; });
      const record = { port: theirs, sent: theirs.received, get disconnected() { return theirs.closed; } };
      natives.push(record);
      if (nativeMode === "missing") {
        setImmediate(() => theirs.disconnect("Specified native messaging host not found."));
      } else if (host) {
        theirs.onMessage.addListener((request) => host(request, record));
      }
      return mine;
    },
  };

  const chrome = {
    runtime,
    permissions: {
      contains: async ({ origins }) => origins.every((o) => granted.has(o)),
      onAdded: event(),
      onRemoved: event(),
    },
    scripting: {
      registerContentScripts: async (list) => { for (const s of list) registered.set(s.id, structuredClone(s)); },
      unregisterContentScripts: async ({ ids }) => { for (const id of ids) registered.delete(id); },
      getRegisteredContentScripts: async ({ ids } = {}) =>
        [...registered.values()].filter((s) => !ids || ids.includes(s.id)).map((s) => structuredClone(s)),
      executeScript: async (details) => {
        // The liveness check of a document: like the browser, it fails for a
        // document that is gone, and runs in the frame of that document.
        if (details.target.documentIds) {
          const [documentId] = details.target.documentIds;
          if (!documents.has(documentId)) throw new Error(`No document with id ${documentId}`);
          return [{ documentId, result: documents.get(documentId) }];
        }
        // The function goes as source; target and args are cloned.
        scripts.push({ func: details.func, target: structuredClone(details.target), args: structuredClone(details.args) });
        return [{ result: scripts.result ? scripts.result(details) : { ok: true } }];
      },
    },
    tabs: {
      get: async (id) => {
        if (!tabs.has(id)) throw new Error("No tab with id");
        return { id, url: tabs.get(id) };
      },
      query: async () => [...tabs.entries()].map(([id, url]) => ({ id, url, lastAccessed: id })),
    },
    action: {
      setBadgeText: async ({ text }) => { badge.text = text; },
      setBadgeBackgroundColor: async () => {},
      setTitle: async ({ title }) => { badge.title = title; },
    },
  };

  const context = vm.createContext({
    chrome,
    crypto: webcrypto,
    TextEncoder,
    URL,
    atob,
    btoa,
    structuredClone,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
  });
  context.self = context;
  context.importScripts = (file) => vm.runInContext(source(file), context, { filename: file });
  vm.runInContext(source("background.js"), context, { filename: "background.js" });

  return {
    context,
    clock,
    natives,
    registered,
    granted,
    tabs,
    documents,
    scripts,
    badge,
    chrome,
    // Messages are cloned, as runtime messaging does.
    handle: async (message) => structuredClone(await context.apassyHandle(structuredClone(message))),
    internals: context.apassyPasskeyTest,
    setNative(mode) { nativeMode = mode; },
    // host(request, record): answer with record.port.postMessage(...)
    setHost(fn) { host = fn; },
    // Opens a port as the bridge does; the browser fills the sender.
    connect(sender, name = "apassy-passkey") {
      const [page, worker] = portPair(name, sender);
      runtime.onConnect.fire(worker);
      return page;
    },
  };
}

// --- the page ----------------------------------------------------------------

// Like the browser: the attributes of these interfaces are accessors on the
// prototype that throw for an object the browser did not make.
function illegal() {
  throw new TypeError("Illegal invocation");
}

function makeInterfaces() {
  class Credential {}
  for (const name of ["id", "type"]) Object.defineProperty(Credential.prototype, name, { get: illegal, enumerable: true, configurable: true });
  class PublicKeyCredential extends Credential {}
  for (const name of ["rawId", "response", "authenticatorAttachment"]) {
    Object.defineProperty(PublicKeyCredential.prototype, name, { get: illegal, enumerable: true, configurable: true });
  }
  PublicKeyCredential.prototype.getClientExtensionResults = illegal;
  PublicKeyCredential.prototype.toJSON = illegal;
  class AuthenticatorResponse {}
  Object.defineProperty(AuthenticatorResponse.prototype, "clientDataJSON", { get: illegal, enumerable: true, configurable: true });
  class AuthenticatorAttestationResponse extends AuthenticatorResponse {}
  Object.defineProperty(AuthenticatorAttestationResponse.prototype, "attestationObject", { get: illegal, enumerable: true, configurable: true });
  for (const name of ["getAuthenticatorData", "getPublicKey", "getPublicKeyAlgorithm", "getTransports"]) {
    AuthenticatorAttestationResponse.prototype[name] = illegal;
  }
  class AuthenticatorAssertionResponse extends AuthenticatorResponse {}
  for (const name of ["authenticatorData", "signature", "userHandle"]) {
    Object.defineProperty(AuthenticatorAssertionResponse.prototype, name, { get: illegal, enumerable: true, configurable: true });
  }
  const calls = [];
  class CredentialsContainer {}
  // The browser's own methods: they record the call and answer "browser".
  Object.defineProperty(CredentialsContainer.prototype, "create", {
    value: function create(options) { calls.push({ op: "create", options, self: this }); return Promise.resolve("browser-create"); },
    writable: true, enumerable: true, configurable: true,
  });
  Object.defineProperty(CredentialsContainer.prototype, "get", {
    value: function get(options) { calls.push({ op: "get", options, self: this }); return Promise.resolve("browser-get"); },
    writable: true, enumerable: true, configurable: true,
  });
  return {
    Credential, PublicKeyCredential, AuthenticatorResponse, AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse, CredentialsContainer, calls,
  };
}

// Runs the two page scripts in this realm against a fresh fake window.
// connect(): what chrome.runtime.connect of the bridge does.
export function loadPage({ connect, bridge = true, clock = new FakeClock() } = {}) {
  const win = new EventTarget();
  const interfaces = makeInterfaces();
  Object.assign(win, interfaces, {
    AbortSignal,
    CustomEvent,
    DOMException,
    btoa,
    atob,
    crypto: webcrypto,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
  });
  win.top = win;
  win.navigator = { credentials: new interfaces.CredentialsContainer() };
  const requests = [];
  win.addEventListener("apassy-passkey-request", (e) => {
    try { requests.push(JSON.parse(e.detail)); } catch { requests.push(null); }
  });
  const run = (file) => {
    const fn = new Function("window", "chrome", "CustomEvent", source(file));
    fn(win, { runtime: { connect: (info) => connect(info) } }, CustomEvent);
  };
  run("passkey-page.js");
  if (bridge) run("passkey-bridge.js");
  return { window: win, navigator: win.navigator, calls: interfaces.calls, interfaces, clock, requests };
}

export { FakeClock };
