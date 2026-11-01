import assert from "node:assert/strict";
import { test } from "node:test";
import { loadBackground, senderFor } from "../passkey-bridge/mock-chrome.mjs";

const ORIGIN = "https://login.example.com";
const TOKEN = "11111111-1111-4111-8111-111111111111";
const URL = `${ORIGIN}/login`;
const ok = (data) => ({ ok: true, code: "ok", message: "", data });
function setup() {
  const bg = loadBackground({ permissions: [`${ORIGIN}/*`] });
  const local = {};
  bg.chrome.storage = { local: {
    get: async () => structuredClone(local),
    set: async (values) => Object.assign(local, structuredClone(values)),
  } };
  bg.chrome.permissions.getAll = async () => ({ origins: [...bg.granted] });
  bg.tabs.set(5, URL);
  bg.registered.set("apassy-login-suggestions", { id: "apassy-login-suggestions", matches: [`${ORIGIN}/*`], matchOriginAsFallback: true,
    js: ["login-target.js", "login-suggestions.js", "login-save.js"] });
  let live = true;
  const calls = [];
  bg.chrome.scripting.executeScript = async (details) => {
    calls.push(details);
    if (!live) throw new Error("document gone");
    if (details.files) return [{ documentId: "DOC-1" }];
    if (!details.args) return [{ documentId: "DOC-1", result: { ok: true, token: TOKEN } }];
    const op = details.args[2];
    return [{ documentId: details.target.documentIds[0], result: op === "read"
      ? { ok: true, username: "synthetic@example.com", password: "synthetic-rotation" }
      : { ok: true, username: true, password: true } }];
  };
  const api = bg.context.apassyLoginTest;
  const target = { tabId: 5, frameId: 0, documentId: "DOC-1", token: TOKEN, origin: ORIGIN, url: URL };
  return { bg, api, target, calls, stale() { live = false; } };
}

for (const [label, override] of Object.entries({
  "other extension": { id: "bad" }, "no document": { documentId: undefined },
  "cached document": { documentLifecycle: "cached" }, "cross origin": { origin: "https://evil.example" },
  "cross origin frame": { url: "https://evil.example/login", origin: "https://evil.example", frameId: 2 },
  "no frame": { frameId: undefined }, "opaque origin": { origin: "null" },
})) {
  test(`field route rejects ${label} before native host`, async () => {
    const { bg, api } = setup();
    const result = await api.handleLoginField({ type: "login_suggestions", token: TOKEN, username: "" }, senderFor(ORIGIN, override));
    assert.equal(result.ok, false);
    assert.equal(bg.natives.length, 0);
  });
}

test("no optional site access means no metadata request", async () => {
  const { bg, api } = setup(); bg.granted.clear();
  const result = await api.handleLoginField({ type: "login_suggestions", token: TOKEN, username: "" }, senderFor(ORIGIN));
  assert.equal(result.code, "site_access"); assert.equal(bg.natives.length, 0);
});

test("suggestions are metadata only; fill requires offered choice and owner/native round trip", async () => {
  const { bg, api, calls } = setup();
  bg.setHost((request, { port }) => port.postMessage(request.cmd === "suggestions"
    ? ok({ type: "logins", origin: ORIGIN, logins: [{ item: 7, title: "Synthetic", username: "synthetic@example.com", password: "MUST-NOT-LEAK" }] })
    : ok({ type: "fill", origin: ORIGIN, item: 7, username: "synthetic@example.com", password: "synthetic-secret" })));
  const suggestions = await api.handleLoginField({ type: "login_suggestions", token: TOKEN, username: " Syn " }, senderFor(ORIGIN));
  assert.equal(bg.natives.length, 1); assert.equal(bg.natives[0].sent[0].cmd, "suggestions");
  assert.equal(bg.natives[0].sent[0].username, " Syn ");
  assert.equal(JSON.stringify(suggestions).includes("MUST-NOT-LEAK"), false);
  assert.equal(calls.some((c) => c.args?.[2] === "fill"), false);
  const wrong = await api.handleLoginField({ type: "login_fill", token: TOKEN, item: 8 }, senderFor(ORIGIN));
  assert.equal(wrong.ok, false); assert.equal(bg.natives.length, 1);
  const fill = await api.handleLoginField({ type: "login_fill", token: TOKEN, item: 7 }, senderFor(ORIGIN));
  assert.equal(fill.ok, true); assert.equal(bg.natives[1].sent[0].cmd, "fill");
  const delivery = calls.find((c) => c.args?.[2] === "fill");
  assert.deepEqual(Array.from(delivery.target.documentIds), ["DOC-1"]);
  assert.equal(JSON.stringify(fill).includes("synthetic-secret"), false);
});

test("same origin iframe uses its own browser document, never frame zero", async () => {
  const { bg, api, calls } = setup();
  bg.setHost((_, { port }) => port.postMessage(ok({ type: "logins", origin: ORIGIN, logins: [] })));
  const result = await api.handleLoginField({ type: "login_suggestions", token: TOKEN, username: "" }, senderFor(ORIGIN, { frameId: 4, documentId: "FRAME-DOC" }));
  assert.equal(result.ok, true);
  assert.ok(calls.every((c) => c.target.documentIds?.[0] === "FRAME-DOC"));
});

test("navigation while owner check waits prevents secret injection", async () => {
  const { bg, target, calls, stale } = setup();
  bg.setHost((request, { port }) => {
    stale(); port.postMessage(ok({ type: "fill", origin: ORIGIN, item: 7, username: "synthetic", password: "secret" }));
  });
  const result = await bg.handle({ type: "fill", tabId: 5, url: URL, item: 7, target });
  assert.equal(result.ok, false); assert.equal(result.code, "page_changed");
  // Browser would reject executing in the stale document; no substitute document is targeted.
  assert.ok(calls.filter((c) => c.args?.[2] === "fill").every((c) => c.target.documentIds[0] === "DOC-1"));
});

test("explicit update sends exact selected identity and reads password only into native request", async () => {
  const { bg, target } = setup();
  bg.setHost((request, { port }) => port.postMessage(request.cmd === "suggestions"
    ? ok({ type: "logins", origin: ORIGIN, logins: [{ item: 7, title: "Synthetic", username: "Case@Example.com" }] })
    : ok({ type: "updated", item: 7, origin: ORIGIN, username: "Case@Example.com" })));
  const result = await bg.handle({ type: "update", tabId: 5, url: URL, target, item: 7, username: "Case@Example.com" });
  assert.equal(result.ok, true);
  assert.equal(bg.natives[1].sent[0].password, "synthetic-rotation");
  assert.equal(bg.natives[1].sent[0].username, "Case@Example.com");
  assert.equal(JSON.stringify(result).includes("synthetic-rotation"), false);
  const wrong = await bg.handle({ type: "update", tabId: 5, url: URL, target, item: 7, username: "case@example.com" });
  assert.equal(wrong.code, "no_match");
  assert.equal(bg.natives.length, 3); // second update stopped after metadata, before mutation
});

test("session outcome excludes password, account labels and sensitive URL; expires on stale document", async () => {
  const { bg, api, target, stale } = setup();
  const storage = {};
  bg.chrome.storage = { ...bg.chrome.storage, session: {
    set: async (v) => Object.assign(storage, structuredClone(v)), get: async (key) => ({ [key]: storage[key] }), remove: async (key) => { delete storage[key]; },
  } };
  await api.rememberLoginResult({ ...target, url: `${URL}?reset=private-token` }, { ok: true, code: "ok", message: "Filled.", password: "NO" });
  assert.equal(JSON.stringify(storage).includes("private-token"), false); assert.equal(JSON.stringify(storage).includes('"NO"'), false);
  assert.equal((await api.recentLoginResult({ id: 5, url: URL })).message, "Filled.");
  stale(); assert.equal(await api.recentLoginResult({ id: 5, url: URL }), null); assert.deepEqual(storage, {});
});

test("disabling suggestions during owner approval invalidates pending inline delivery", async () => {
  const { bg, api, calls } = setup();
  let pending;
  bg.setHost((request, record) => {
    if (request.cmd === "suggestions") record.port.postMessage(ok({ type: "logins", origin: ORIGIN, logins: [{ item: 7, title: "Synthetic", username: "user" }] }));
    else pending = record;
  });
  await api.handleLoginField({ type: "login_suggestions", token: TOKEN, username: "" }, senderFor(ORIGIN));
  const filling = api.handleLoginField({ type: "login_fill", token: TOKEN, item: 7 }, senderFor(ORIGIN));
  for (let i = 0; i < 20 && !pending; i++) await new Promise(setImmediate);
  assert.ok(pending);
  await api.loginAccessChange(URL, false);
  pending.port.postMessage(ok({ type: "fill", origin: ORIGIN, item: 7, username: "user", password: "secret" }));
  const result = await filling;
  assert.equal(result.ok, false); assert.equal(result.code, "page_changed");
  assert.equal(calls.some((c) => c.args?.[2] === "fill"), false);
});
