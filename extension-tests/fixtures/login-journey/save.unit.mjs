import assert from "node:assert/strict";
import { test } from "node:test";
import { loadBackground, senderFor, flush } from "../passkey-bridge/mock-chrome.mjs";
const origin = "https://example.com", username = "alice@example.test", password = "synthetic-typed-value";
const attempt = "11111111-1111-4111-8111-111111111111";
const ok = (data) => ({ ok: true, data });
function setup(logins = []) {
  const bg = loadBackground({ permissions: [`${origin}/*`] });
  bg.context.Date = class extends Date { static now() { return 1000000 + bg.clock.now; } };
  const stored = {};
  bg.chrome.storage = { local: { get: async () => ({ ...stored }), set: async (v) => Object.assign(stored, v) } };
  bg.chrome.permissions.getAll = async () => ({ origins: [...bg.granted] });
  bg.tabs.set(5, origin + "/login");
  bg.chrome.scripting.executeScript = async ({ target }) => [{ documentId: target.documentIds?.[0], result: true }];
  bg.setHost((r, { port }) => port.postMessage(r.cmd === "suggestions" ? ok({ type: "logins", origin, logins }) :
    r.cmd === "status" ? ok({ type: "status", version: "0.5.8" }) :
    r.cmd === "update" ? ok({ type: "updated", item: r.item, origin, username: r.username }) : ok({ type: "saved", item: 12 })));
  const api = bg.context.apassySaveTest;
  const send = (message, extra) => api.handleLoginSave(message, senderFor(origin, extra));
  const capture = (extra = {}, peer) => send({ type: "login_save_capture", attempt, username, password, ...extra }, peer);
  const ready = () => send({ type: "login_save_ready", attempt });
  return { bg, api, stored, send, capture, ready };
}
test("capture stays only in worker memory; metadata query and banner response contain no password", async () => {
  const s = setup(); await s.capture();
  assert.equal(s.api.pendingSaves.get(5).password, password);
  assert.equal(s.bg.natives.length, 0);
  assert.equal((await s.send({ type: "login_save_offer" })).offer, null);
  const reply = await s.ready();
  assert.equal(reply.offer.mode, "save");
  assert(!JSON.stringify(reply).includes(password));
  assert.equal(s.bg.natives[0].sent[0].cmd, "suggestions");
  assert(!JSON.stringify(s.bg.natives[0].sent).includes(password));
  assert(!JSON.stringify(s.stored).includes(password));
});
test("same-tab same-origin next document resumes an offer; old document cannot accept it", async () => {
  const s = setup(); await s.capture();
  const reply = await s.send({ type: "login_save_offer" }, { documentId: "NEXT" });
  assert.equal(reply.offer.mode, "save");
  const rejected = await s.send({ type: "login_save_action", id: reply.offer.id, action: "accept", trustedGesture: true });
  assert.equal(rejected.ok, false);
  assert.equal(s.bg.natives.length, 1);
});
test("exact existing metadata chooses update; only trusted accept sends the typed password once", async () => {
  const s = setup([{ item: 7, title: "Alice", username }]); await s.capture();
  const { offer } = await s.ready(); assert.equal(offer.mode, "update");
  const action = { type: "login_save_action", id: offer.id, action: "accept" };
  assert.equal((await s.send(action)).ok, false);
  assert.equal(s.bg.natives.length, 1);
  const retained = s.api.pendingSaves.get(5);
  assert.equal((await s.send({ ...action, trustedGesture: true })).ok, true);
  const requests = s.bg.natives.flatMap((n) => n.sent);
  const updates = requests.filter((r) => r.cmd === "update");
  assert.equal(updates.length, 1); assert.equal(updates[0].password, password); assert.equal(updates[0].item, 7);
  assert.equal(retained.password, ""); assert.equal(s.api.pendingSaves.size, 0);
  await s.send({ ...action, trustedGesture: true });
  assert.equal(s.bg.natives.flatMap((n) => n.sent).filter((r) => r.cmd === "update").length, 1);
});
test("new login accept uses existing SaveLogin packet and no password in response", async () => {
  const s = setup(); await s.capture(); const { offer } = await s.ready();
  const result = await s.send({ type: "login_save_action", id: offer.id, action: "accept", trustedGesture: true });
  const save = s.bg.natives.flatMap((n) => n.sent).find((r) => r.cmd === "save");
  assert.equal(save.password, password); assert.equal(save.url, origin); assert.equal(save.trusted_gesture, true);
  assert(!JSON.stringify(result).includes(password));
});
for (const reason of ["dismiss", "timeout", "no transition", "tab close", "other origin", "disable", "permission removed"]) {
  test(`pending password erased on ${reason}`, async () => {
    const s = setup(); await s.capture(); const retained = s.api.pendingSaves.get(5);
    if (reason !== "no transition") await s.ready();
    if (reason === "dismiss") await s.send({ type: "login_save_action", id: retained.id, action: "dismiss", trustedGesture: true });
    if (reason === "timeout") await s.bg.clock.advance(180000);
    if (reason === "no transition") await s.bg.clock.advance(15000);
    if (reason === "tab close") s.bg.chrome.tabs.onRemoved.fire(5);
    if (reason === "other origin") s.bg.chrome.tabs.onUpdated.fire(5, { url: "https://other.example/" });
    if (reason === "disable") await s.bg.context.apassyLoginTest.loginAccessChange(origin, false);
    if (reason === "permission removed") s.bg.chrome.permissions.onRemoved.fire({});
    assert.equal(retained.password, ""); assert.equal(s.api.pendingSaves.size, 0);
  });
}
test("Never shares toolbar hostname exclusion and erases the secret", async () => {
  const s = setup(); await s.capture(); const { offer } = await s.ready();
  await s.send({ type: "login_save_action", id: offer.id, action: "never", trustedGesture: true });
  assert.deepEqual(Array.from(s.stored.loginSuggestionsExcluded), ["example.com"]);
  assert.equal(s.api.pendingSaves.size, 0); assert.equal((await s.capture()).ok, false);
});
test("username-first memory is tab/origin bound and expires without extending password lifetime", async () => {
  const s = setup(); await s.capture({ password: "" });
  await s.capture({ username: "" });
  assert.equal(s.api.pendingSaves.get(5).username, username); assert.equal(s.api.saveUsernames.size, 0);
  await s.capture({ password: "" }); await s.bg.clock.advance(180000);
  assert.equal((await s.capture({ username: "" })).ok, false);
  await s.capture({ password: "" }); s.bg.chrome.tabs.onUpdated.fire(5, { url: "https://other.example" });
  assert.equal(s.api.saveUsernames.size, 0);
  assert.equal((await s.capture({ username: "" }, { tab: { id: 6, url: origin + "/login" } })).ok, false);
});
for (const extra of [{ id: "other" }, { frameId: 2 }, { origin: "https://evil.example" }, { documentLifecycle: "cached" }]) {
  test(`untrusted sender rejected: ${JSON.stringify(extra)}`, async () => {
    const s = setup(); const message = { type: "login_save_capture", attempt, username, password };
    assert.equal((await s.send(message, extra)).ok, false); assert.equal(message.password, "");
    assert.equal(s.api.pendingSaves.size, 0); assert.equal(s.bg.natives.length, 0);
  });
}
test("metadata decisions fail closed on errors, wrong origins, ambiguity and a full prefix result", () => {
  const { api } = setup();
  assert.equal(api.saveDecision(ok({ type: "logins", origin: "https://evil.example", logins: [] }), origin, username), null);
  assert.equal(api.saveDecision({ ok: false }, origin, username), null);
  assert.equal(api.saveDecision(ok({ type: "logins", origin, logins: Array.from({ length: 50 }, (_, item) => ({ item, username: username + item })) }), origin, username), null);
  assert.equal(api.saveDecision(ok({ type: "logins", origin, logins: [{ item: 1, username }, { item: 2, username }] }), origin, username), null);
});
test("navigation during metadata lookup cannot resurrect an expired or dismissed offer", async () => {
  const s = setup(); await s.capture();
  let pending;
  s.bg.setHost((_, record) => { pending = record; });
  const offering = s.ready(); await flush(); assert(pending);
  s.bg.chrome.tabs.onUpdated.fire(5, { url: "https://other.example" });
  pending.port.postMessage(ok({ type: "logins", origin, logins: [] }));
  assert.equal((await offering).ok, false); assert.equal(s.api.pendingSaves.size, 0);
});

test("a stalled metadata-only compatibility probe cannot retain or later send a password past the deadline", async () => {
  const s = setup(); await s.capture(); const { offer } = await s.ready();
  let status;
  s.bg.setHost((r, record) => { assert.equal(r.cmd, "status"); status = record; });
  const action = s.send({ type: "login_save_action", id: offer.id, action: "accept", trustedGesture: true });
  await flush(); assert(status);
  const retained = s.api.pendingSaves.get(5);
  await s.bg.clock.advance(180000); assert.equal(retained.password, "");
  status.port.postMessage(ok({ type: "status", version: "0.5.8" }));
  assert.equal((await action).ok, false);
  assert.equal(s.bg.natives.flatMap((n) => n.sent).filter((r) => r.cmd === "save").length, 0);
});

test("a destroyed source document cannot replace the destination banner binding", async () => {
  const s = setup(); await s.capture();
  await s.send({ type: "login_save_offer" }, { documentId: "NEXT" });
  s.bg.chrome.scripting.executeScript = async ({ target }) => {
    if (target.documentIds[0] === "DOC-1") throw new Error("document gone");
    return [{ documentId: target.documentIds[0], result: true }];
  };
  assert.equal((await s.ready()).ok, false);
  assert.equal(s.api.pendingSaves.get(5).offerDocument, "NEXT");
});

test("case-insensitive duplicate metadata preserves the exact selected username in an update", async () => {
  const canonical = "Alice@Example.Test";
  const s = setup([{ item: 7, username: canonical }]); await s.capture();
  const { offer } = await s.ready(); assert.equal(offer.mode, "update"); assert.equal(offer.username, canonical);
  await s.send({ type: "login_save_action", id: offer.id, action: "accept", trustedGesture: true });
  assert.equal(s.bg.natives.flatMap((n) => n.sent).find((r) => r.cmd === "update").username, canonical);
});
