// Unit checks of the passkey part (and the one-time code fill) of
// extension/background.js, with a mock of the chrome APIs.
//
//   node --test fixtures/passkey-bridge/*.unit.mjs        (from extension-tests/)
//
// The "app" here is a test function or the SYNTHETIC authenticator of this
// folder, never Apassy or a vault.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { test } from "node:test";
import { flush, loadBackground, senderFor } from "./mock-chrome.mjs";
import { createSyntheticAuthenticator, fail, ok } from "./synthetic-authenticator.mjs";

const ORIGIN = "https://login.example.com";
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const sha256 = (data) => createHash("sha256").update(data).digest();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function getOptions(extra = {}) {
  return { challenge: b64u(randomBytes(32)), rpId: "example.com", allowCredentials: [], ...extra };
}

function createOptions(extra = {}) {
  return {
    rp: { id: "example.com", name: "Example" },
    user: { id: b64u(randomBytes(16)), name: "user@example.com", displayName: "User" },
    challenge: b64u(randomBytes(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    excludeCredentials: [],
    ...extra,
  };
}

// A background whose tab 5 shows ORIGIN.
function setup(options = {}) {
  const bg = loadBackground(options);
  bg.tabs.set(5, `${ORIGIN}/login`);
  bg.documents.set("DOC-1", ORIGIN);
  return bg;
}

async function request(bg, message, sender = senderFor(ORIGIN)) {
  const port = bg.connect(sender);
  port.postMessage(message);
  await flush();
  return port;
}

function authDataFor(rpId, flags = 0x05, attested) {
  const parts = [sha256(rpId), Buffer.from([flags]), Buffer.from([0, 0, 0, 1])];
  if (attested) {
    const length = Buffer.alloc(2);
    length.writeUInt16BE(attested.length);
    parts.push(Buffer.alloc(16), length, attested, Buffer.from([0xa0]));
  }
  return Buffer.concat(parts);
}

function getAnswer(wire, overrides = {}) {
  return ok({
    type: "passkey",
    rid: wire.rid,
    credential_id: b64(Buffer.from("credential-one")),
    user_handle: b64(Buffer.from("user-handle")),
    authenticator_data: b64(authDataFor(wire.rp_id)),
    signature: b64(randomBytes(70)),
    client_data_json: wire.client_data_json,
    ...overrides,
  });
}

// --- the sender ------------------------------------------------------------------

test("a valid get goes to the app with the browser origin and a clientDataJSON built here", async () => {
  const bg = setup();
  const challenge = randomBytes(32);
  const port = await request(bg, { op: "get", options: getOptions({ challenge: b64u(challenge) }) });
  assert.equal(bg.natives.length, 1);
  const [wire] = bg.natives[0].sent;
  assert.deepEqual(Object.keys(wire).sort(), ["allowed", "client_data_json", "cmd", "origin", "rid", "rp_id", "v"]);
  assert.equal(wire.v, 1);
  assert.equal(wire.cmd, "passkey_get");
  assert.equal(wire.origin, ORIGIN);
  assert.equal(wire.rp_id, "example.com");
  assert.match(wire.rid, UUID);
  assert.deepEqual(wire.allowed, []);
  // Standard base64 with padding, of the exact bytes.
  assert.equal(Buffer.from(wire.client_data_json, "base64").toString("base64"), wire.client_data_json);
  assert.equal(Buffer.from(wire.client_data_json, "base64").toString("utf8"),
    `{"type":"webauthn.get","challenge":"${b64u(challenge)}","origin":"${ORIGIN}","crossOrigin":false}`);
  assert.equal(port.received.length, 0);
});

test("the page cannot choose the origin: an extra field is refused before the app", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: { ...getOptions(), origin: "https://evil.example" } });
  assert.deepEqual(port.received, [{ kind: "fallback" }]);
  assert.equal(bg.natives.length, 0);
  const port2 = await request(bg, { op: "get", options: getOptions(), origin: "https://evil.example" });
  assert.deepEqual(port2.received, [{ kind: "fallback" }]);
  assert.equal(bg.natives.length, 0);
});

const BAD_SENDERS = {
  "another extension": senderFor(ORIGIN, { id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }),
  "no tab": { ...senderFor(ORIGIN), tab: undefined },
  "a subframe": senderFor(ORIGIN, { frameId: 3 }),
  "no documentId": senderFor(ORIGIN, { documentId: undefined }),
  "a prerendered document": senderFor(ORIGIN, { documentLifecycle: "prerender" }),
  "a cached document": senderFor(ORIGIN, { documentLifecycle: "cached" }),
  "an opaque origin": senderFor(ORIGIN, { origin: "null" }),
  "no origin": senderFor(ORIGIN, { origin: undefined }),
  "a url of another origin": senderFor(ORIGIN, { url: "https://evil.example/login" }),
  "a tab on another origin": senderFor(ORIGIN, { tab: { id: 5, url: "https://evil.example/" } }),
  "plain http": senderFor("http://login.example.com"),
  "http on 127.0.0.1": senderFor("http://127.0.0.1:8080"),
  "a file page": senderFor("file://"),
  "an origin with a path": senderFor(ORIGIN, { origin: `${ORIGIN}/x` }),
};

for (const [name, sender] of Object.entries(BAD_SENDERS)) {
  test(`a port from ${name} gets a fallback and nothing reaches the app`, async () => {
    const bg = setup();
    const port = await request(bg, { op: "get", options: getOptions() }, sender);
    assert.deepEqual(port.received, [{ kind: "fallback" }]);
    assert.equal(port.closed, true);
    assert.equal(bg.natives.length, 0);
  });
}

test("a port with another name is closed at once", async () => {
  const bg = setup();
  const port = bg.connect(senderFor(ORIGIN), "other");
  await flush();
  assert.equal(port.closed, true);
  assert.equal(bg.natives.length, 0);
});

test("http://localhost works for a local test site, with the RP ID localhost", async () => {
  const bg = loadBackground();
  bg.tabs.set(5, "http://localhost:4173/login");
  bg.documents.set("DOC-1", "http://localhost:4173");
  await request(bg, { op: "get", options: getOptions({ rpId: "localhost" }) }, senderFor("http://localhost:4173"));
  assert.equal(bg.natives[0].sent[0].origin, "http://localhost:4173");
  assert.equal(bg.natives[0].sent[0].rp_id, "localhost");
});

// --- the RP ID ---------------------------------------------------------------------

const RP_IDS = {
  "example.com": true,
  "login.example.com": true,
  undefined: true,
  "other.com": false,
  "com": false,
  "Example.com": false,
  "xample.com": false,
  "ogin.example.com": false,
  "deeper.login.example.com": false,
  "localhost": false,
  "": false,
  "example.com.": false,
  "exa_mple.com": false,
  "-example.com": false,
};

for (const [rpId, served] of Object.entries(RP_IDS)) {
  test(`RP ID ${JSON.stringify(rpId)} on ${ORIGIN}: ${served ? "served" : "left to the browser"}`, async () => {
    const bg = setup();
    const options = getOptions({ rpId: rpId === "undefined" ? undefined : rpId });
    if (rpId === "undefined") delete options.rpId;
    const port = await request(bg, { op: "get", options });
    if (served) {
      assert.equal(bg.natives.length, 1);
      assert.equal(bg.natives[0].sent[0].rp_id, rpId === "undefined" ? "login.example.com" : rpId);
    } else {
      assert.deepEqual(port.received, [{ kind: "fallback" }]);
      assert.equal(bg.natives.length, 0);
    }
  });
}

test("an IP address origin is never served", async () => {
  const bg = loadBackground();
  bg.tabs.set(5, "https://10.0.0.1/login");
  const port = await request(bg, { op: "get", options: getOptions({ rpId: undefined }) }, senderFor("https://10.0.0.1"));
  assert.deepEqual(port.received, [{ kind: "fallback" }]);
  assert.equal(bg.natives.length, 0);
});

// --- options that Apassy does not serve ----------------------------------------------

const UNSUPPORTED = {
  "conditional mediation": { op: "get", options: getOptions(), mediation: "conditional" },
  "immediate mediation": { op: "get", options: getOptions(), mediation: "immediate" },
  "a prf extension (get)": { op: "get", options: getOptions({ extensions: { prf: true } }) },
  "an appid extension": { op: "get", options: getOptions({ extensions: { appid: true } }) },
  "a large blob extension (create)": { op: "create", options: createOptions({ extensions: { largeBlob: true } }) },
  "no ES256": { op: "create", options: createOptions({ pubKeyCredParams: [{ type: "public-key", alg: -257 }] }) },
  "a cross-platform attachment": { op: "create", options: createOptions({ authenticatorSelection: { authenticatorAttachment: "cross-platform" } }) },
  "enterprise attestation": { op: "create", options: createOptions({ attestation: "enterprise" }) },
  "a security-key hint": { op: "get", options: getOptions({ hints: ["security-key"] }) },
  "a short challenge": { op: "get", options: getOptions({ challenge: b64u(randomBytes(15)) }) },
  "a long challenge": { op: "get", options: getOptions({ challenge: b64u(randomBytes(1025)) }) },
  "a non-canonical challenge": { op: "get", options: getOptions({ challenge: `${b64u(randomBytes(32))}=` }) },
  "a long user ID": { op: "create", options: createOptions({ user: { id: b64u(randomBytes(65)), name: "a", displayName: "" } }) },
  "an empty user ID": { op: "create", options: createOptions({ user: { id: "", name: "a", displayName: "" } }) },
  "a long user name": { op: "create", options: createOptions({ user: { id: b64u(randomBytes(8)), name: "x".repeat(257), displayName: "" } }) },
  "an empty user name": { op: "create", options: createOptions({ user: { id: b64u(randomBytes(8)), name: "‮", displayName: "" } }) },
  "65 allowed credentials": { op: "get", options: getOptions({ allowCredentials: Array.from({ length: 65 }, () => ({ type: "public-key", id: b64u(randomBytes(16)) })) }) },
  "a long credential ID": { op: "get", options: getOptions({ allowCredentials: [{ type: "public-key", id: b64u(randomBytes(1024)) }] }) },
  "a string timeout": { op: "get", options: getOptions({ timeout: "60000" }) },
  "an unknown op": { op: "sign", options: getOptions() },
  "no options": { op: "get" },
  "a message over 64 KiB": { op: "create", options: createOptions({ rp: { id: "example.com", name: "n".repeat(70000) } }) },
};

for (const [name, message] of Object.entries(UNSUPPORTED)) {
  test(`${name}: a fallback to the browser, nothing to the app`, async () => {
    const bg = setup();
    const port = await request(bg, message);
    assert.deepEqual(port.received, [{ kind: "fallback" }]);
    assert.equal(bg.natives.length, 0);
  });
}

test("no request within 10 s: a fallback", async () => {
  const bg = setup();
  const port = bg.connect(senderFor(ORIGIN));
  await bg.clock.advance(9_999);
  assert.equal(port.received.length, 0);
  await bg.clock.advance(1);
  assert.deepEqual(port.received, [{ kind: "fallback" }]);
  assert.equal(port.closed, true);
});

// --- answers of the app --------------------------------------------------------------

test("a signed answer reaches the page as base64url, and both ports close", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  const native = bg.natives[0];
  const wire = native.sent[0];
  const answer = getAnswer(wire);
  native.port.postMessage(answer);
  await flush();
  assert.equal(port.received.length, 1);
  const [reply] = port.received;
  assert.equal(reply.kind, "result");
  assert.equal(reply.op, "get");
  assert.deepEqual(reply.credential, {
    id: b64u(Buffer.from("credential-one")),
    clientDataJSON: b64u(Buffer.from(wire.client_data_json, "base64")),
    authenticatorData: b64u(Buffer.from(answer.data.authenticator_data, "base64")),
    signature: b64u(Buffer.from(answer.data.signature, "base64")),
    userHandle: b64u(Buffer.from("user-handle")),
    clientExtensionResults: {},
  });
  assert.equal(port.closed, true);
  assert.equal(native.disconnected, true);
});

const FALLBACK_CODES = ["not_running", "none_open", "vault_locked", "no_match", "unsupported", "bad_request", "bad_version"];
for (const code of FALLBACK_CODES) {
  test(`app answer ${code} (before any owner check): a fallback`, async () => {
    const bg = setup();
    const port = await request(bg, { op: "get", options: getOptions() });
    bg.natives[0].port.postMessage(fail(code));
    await flush();
    assert.deepEqual(port.received, [{ kind: "fallback" }]);
  });
}

for (const code of ["cancelled", "owner_check_failed", "refused", "busy", "timeout", "stopped", "something_new"]) {
  test(`app answer ${code}: NotAllowedError, never a fallback`, async () => {
    const bg = setup();
    const port = await request(bg, { op: "create", options: createOptions() });
    bg.natives[0].port.postMessage(fail(code));
    await flush();
    assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  });
}

test("excluded: InvalidStateError for create, NotAllowedError for get", async () => {
  const bg = setup();
  const create = await request(bg, { op: "create", options: createOptions() });
  bg.natives[0].port.postMessage(fail("excluded"));
  await flush();
  assert.deepEqual(create.received, [{ kind: "error", name: "InvalidStateError" }]);
  const get = await request(bg, { op: "get", options: getOptions() });
  bg.natives[1].port.postMessage(fail("excluded"));
  await flush();
  assert.deepEqual(get.received, [{ kind: "error", name: "NotAllowedError" }]);
});

const BAD_ANSWERS = {
  "another rid": (wire) => getAnswer(wire, { rid: "00000000-0000-4000-8000-000000000000" }),
  "no rid": (wire) => getAnswer(wire, { rid: undefined }),
  "other client data": (wire) => getAnswer(wire, { client_data_json: b64(Buffer.from('{"type":"webauthn.get"}')) }),
  "another RP ID hash": (wire) => getAnswer(wire, { authenticator_data: b64(authDataFor("evil.example")) }),
  "no user verification flag": (wire) => getAnswer(wire, { authenticator_data: b64(authDataFor(wire.rp_id, 0x01)) }),
  "no user presence flag": (wire) => getAnswer(wire, { authenticator_data: b64(authDataFor(wire.rp_id, 0x04)) }),
  "base64 without padding": (wire) => getAnswer(wire, { credential_id: b64(Buffer.from("credential-on")).replace(/=+$/, "") }),
  "base64url instead of base64": (wire) => getAnswer(wire, { signature: b64u(Buffer.from([0xfb, 0xff, 0xfe, 0xfb, 0xff, 0xfe, 0xfb, 0xff, 0xfe])) }),
  "a created type for get": (wire) => ok({ ...getAnswer(wire).data, type: "passkey_created" }),
  "a short signature": (wire) => getAnswer(wire, { signature: b64(Buffer.from("1234")) }),
  "a long user handle": (wire) => getAnswer(wire, { user_handle: b64(randomBytes(65)) }),
  "data that is not an object": () => ({ ok: true, code: "ok", message: "", data: "passkey" }),
  "no ok field": (wire) => ({ data: getAnswer(wire).data }),
  "a string": () => "ok",
};

for (const [name, make] of Object.entries(BAD_ANSWERS)) {
  test(`an answer with ${name}: NotAllowedError, nothing delivered`, async () => {
    const bg = setup();
    const port = await request(bg, { op: "get", options: getOptions() });
    bg.natives[0].port.postMessage(make(bg.natives[0].sent[0]));
    await flush();
    assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  });
}

test("a credential outside the allow list is refused", async () => {
  const bg = setup();
  const allowed = randomBytes(16);
  const port = await request(bg, { op: "get", options: getOptions({ allowCredentials: [{ type: "public-key", id: b64u(allowed) }] }) });
  const wire = bg.natives[0].sent[0];
  assert.deepEqual(wire.allowed, [b64(allowed)]);
  bg.natives[0].port.postMessage(getAnswer(wire));
  await flush();
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
});

// --- create ------------------------------------------------------------------------------

test("create: the wire request, clean names, and a checked answer with credProps", async () => {
  const bg = setup();
  const userId = randomBytes(20);
  const excluded = randomBytes(16);
  const options = createOptions({
    rp: { id: "example.com", name: "Ex‮ample\u0000 Bank​" },
    user: { id: b64u(userId), name: "  user⁦@example.com\n", displayName: "Rafał W." },
    excludeCredentials: [{ type: "public-key", id: b64u(excluded) }],
    extensions: { credProps: true },
    attestation: "direct",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  const port = await request(bg, { op: "create", options });
  const wire = bg.natives[0].sent[0];
  assert.deepEqual(Object.keys(wire).sort(), [
    "algorithms", "client_data_json", "cmd", "excluded", "origin", "rid", "rp_id", "title",
    "user_display_name", "user_handle", "user_name", "v",
  ]);
  assert.equal(wire.cmd, "passkey_create");
  assert.equal(wire.user_handle, b64(userId));
  assert.deepEqual(wire.excluded, [b64(excluded)]);
  assert.deepEqual(wire.algorithms, [-7, -257]);
  assert.equal(wire.user_name, "user @example.com");
  assert.equal(wire.user_display_name, "Rafał W.");
  assert.equal(wire.title, "Ex ample Bank");
  const clientData = JSON.parse(Buffer.from(wire.client_data_json, "base64").toString("utf8"));
  assert.deepEqual(clientData, { type: "webauthn.create", challenge: options.challenge, origin: ORIGIN, crossOrigin: false });

  const authenticator = createSyntheticAuthenticator();
  bg.natives[0].port.postMessage(ok(authenticator.create(wire)));
  await flush();
  const [reply] = port.received;
  assert.equal(reply.kind, "result");
  assert.equal(reply.op, "create");
  assert.equal(reply.item, undefined, "the item ID stays in the extension");
  assert.deepEqual(reply.credential.clientExtensionResults, { credProps: { rk: true } });
  assert.equal(reply.credential.publicKeyAlgorithm, -7);
  assert.deepEqual(reply.credential.transports, ["internal"]);
});

test("create: an untitled RP gets the RP ID as title", async () => {
  const bg = setup();
  await request(bg, { op: "create", options: createOptions({ rp: { id: "example.com", name: "​ ‮" } }) });
  assert.equal(bg.natives[0].sent[0].title, "example.com");
});

test("create: an empty pubKeyCredParams means ES256 and RS256", async () => {
  const bg = setup();
  await request(bg, { op: "create", options: createOptions({ pubKeyCredParams: [] }) });
  assert.deepEqual(bg.natives[0].sent[0].algorithms, [-7, -257]);
});

const BAD_CREATED = {
  "an excluded credential": (wire, data) => {
    return { ...data, credential_id: wire.excluded[0] };
  },
  "another credential ID than in the authenticator data": (wire, data) => ({ ...data, credential_id: b64(randomBytes(16)) }),
  "another algorithm": (wire, data) => ({ ...data, algorithm: -257 }),
  "no item": (wire, data) => ({ ...data, item: undefined }),
  "authenticator data without the attested flag": (wire, data) => {
    const auth = Buffer.from(data.authenticator_data, "base64");
    auth[32] &= ~0x40;
    return { ...data, authenticator_data: b64(auth) };
  },
  "an attestation object of other data": (wire, data) => ({ ...data, attestation_object: b64(Buffer.from("not cbor")) }),
};

for (const [name, change] of Object.entries(BAD_CREATED)) {
  test(`create answer with ${name}: NotAllowedError`, async () => {
    const bg = setup();
    const excluded = randomBytes(16);
    const port = await request(bg, { op: "create", options: createOptions({ excludeCredentials: [{ type: "public-key", id: b64u(excluded) }] }) });
    const wire = bg.natives[0].sent[0];
    const created = createSyntheticAuthenticator().create(wire);
    if (name === "an excluded credential") {
      // The authenticator data must name the same ID, so build it again.
      const auth = Buffer.from(created.authenticator_data, "base64");
      excluded.copy(auth, 55);
      created.authenticator_data = b64(auth);
    }
    bg.natives[0].port.postMessage(ok(change(wire, created)));
    await flush();
    assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  });
}

// --- cancel, navigation, deadline ------------------------------------------------------

test("the page closes its port: the native port closes and a late answer goes nowhere", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  const native = bg.natives[0];
  port.disconnect();
  await flush();
  assert.equal(native.disconnected, true, "the host sees the end of its input");
  // The app answers anyway (too late).
  assert.throws(() => native.port.postMessage(getAnswer(native.sent[0])));
  await flush();
  assert.equal(port.received.length, 0);
});

test("the tab went to another origin before the answer: nothing delivered", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  bg.tabs.set(5, "https://evil.example/");
  bg.natives[0].port.postMessage(getAnswer(bg.natives[0].sent[0]));
  await flush();
  assert.equal(port.received.length, 0);
  assert.equal(port.closed, true);
  assert.equal(bg.badge.text, "", "no badge for a sign-in");
});

test("the document that asked is gone (same origin, new document): nothing delivered", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  bg.documents.delete("DOC-1");
  bg.documents.set("DOC-2", ORIGIN);
  bg.natives[0].port.postMessage(getAnswer(bg.natives[0].sent[0]));
  await flush();
  assert.equal(port.received.length, 0);
  assert.equal(port.closed, true);
});

test("a created passkey that the page did not get shows a badge", async () => {
  const bg = setup();
  const port = await request(bg, { op: "create", options: createOptions() });
  const wire = bg.natives[0].sent[0];
  bg.tabs.delete(5);
  bg.natives[0].port.postMessage(ok(createSyntheticAuthenticator().create(wire)));
  await flush();
  assert.equal(port.received.length, 0);
  assert.equal(bg.badge.text, "!");
  assert.match(bg.badge.title, /passkey is in Apassy, but the page did not get it/);
});

test("the tab navigated before the request reached the app: nothing is sent", async () => {
  const bg = setup();
  bg.tabs.set(5, "https://evil.example/");
  const port = await request(bg, { op: "get", options: getOptions() });
  assert.equal(bg.natives.length, 0);
  assert.equal(port.closed, true);
});

test("the deadline: the page timeout is clamped to 30 s, then NotAllowedError and the native port closes", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions({ timeout: 1000 }) });
  await bg.clock.advance(29_999);
  assert.equal(port.received.length, 0);
  assert.equal(bg.natives[0].disconnected, false);
  await bg.clock.advance(1);
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  assert.equal(bg.natives[0].disconnected, true);
});

test("the deadline is at most 180 s", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions({ timeout: 3_600_000 }) });
  await bg.clock.advance(179_999);
  assert.equal(port.received.length, 0);
  await bg.clock.advance(1);
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
});

test("a new request of the same tab ends the old one", async () => {
  const bg = setup();
  const first = await request(bg, { op: "get", options: getOptions() });
  const second = await request(bg, { op: "get", options: getOptions() });
  assert.deepEqual(first.received, [{ kind: "error", name: "NotAllowedError" }]);
  assert.equal(bg.natives[0].disconnected, true);
  assert.equal(bg.natives[1].disconnected, false);
  // The old answer comes too late and the new one still works.
  bg.natives[1].port.postMessage(getAnswer(bg.natives[1].sent[0]));
  await flush();
  assert.equal(second.received[0].kind, "result");
});

test("requests of two tabs run side by side", async () => {
  const bg = setup();
  bg.tabs.set(6, `${ORIGIN}/other`);
  bg.documents.set("DOC-2", ORIGIN);
  const first = await request(bg, { op: "get", options: getOptions() });
  const second = await request(bg, { op: "get", options: getOptions() }, senderFor(ORIGIN, { tab: { id: 6, url: `${ORIGIN}/other` }, documentId: "DOC-2" }));
  assert.equal(first.received.length, 0);
  assert.equal(second.received.length, 0);
  assert.equal(bg.natives.length, 2);
});

test("a second message on the same port ends the request", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  port.postMessage({ op: "get", options: getOptions() });
  await flush();
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  assert.equal(bg.natives[0].disconnected, true);
  assert.equal(bg.natives.length, 1);
});

test("no native host: a fallback (nothing reached the app)", async () => {
  const bg = setup();
  bg.setNative("missing");
  const port = await request(bg, { op: "get", options: getOptions() });
  await flush();
  assert.deepEqual(port.received, [{ kind: "fallback" }]);
});

test("the host ends without an answer: NotAllowedError (it may have shown the owner check)", async () => {
  const bg = setup();
  const port = await request(bg, { op: "get", options: getOptions() });
  bg.natives[0].port.disconnect("Native host has exited.");
  await flush();
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
});

test("one native port per request", async () => {
  const bg = setup();
  const authenticator = createSyntheticAuthenticator();
  bg.setHost((wire, record) => record.port.postMessage(ok(authenticator.create(wire))));
  await request(bg, { op: "create", options: createOptions() });
  bg.tabs.set(5, `${ORIGIN}/login`);
  await request(bg, { op: "create", options: createOptions() });
  assert.equal(bg.natives.length, 2);
  assert.deepEqual(bg.natives.map((n) => n.sent.length), [1, 1]);
  assert.ok(bg.natives.every((n) => n.disconnected));
  assert.notEqual(bg.natives[0].sent[0].rid, bg.natives[1].sent[0].rid);
});

// --- turning passkeys on and off ----------------------------------------------------------

test("passkeys turn on only with the permission, and register MAIN + ISOLATED top-frame scripts", async () => {
  const bg = loadBackground();
  assert.deepEqual(await bg.handle({ type: "passkeys_state" }), { ok: true, code: "ok", message: "", on: false });
  // Before the grant: only the wish is noted.
  assert.equal((await bg.handle({ type: "passkeys", on: true })).on, false);
  assert.equal(bg.registered.size, 0);
  // The owner grants in the browser prompt.
  bg.granted.add("https://*/*");
  bg.granted.add("http://localhost/*");
  bg.chrome.permissions.onAdded.fire({ origins: ["https://*/*", "http://localhost/*"] });
  await flush();
  const scripts = [...bg.registered.values()].sort((a, b) => a.id.localeCompare(b.id));
  assert.deepEqual(scripts, [
    { id: "apassy-passkey-bridge", js: ["passkey-bridge.js"], world: "ISOLATED", matches: ["https://*/*", "http://localhost/*"], runAt: "document_start", allFrames: false, matchOriginAsFallback: false, persistAcrossSessions: true },
    { id: "apassy-passkey-page", js: ["passkey-page.js"], world: "MAIN", matches: ["https://*/*", "http://localhost/*"], runAt: "document_start", allFrames: false, matchOriginAsFallback: false, persistAcrossSessions: true },
  ]);
  assert.equal((await bg.handle({ type: "passkeys_state" })).on, true);
  assert.equal((await bg.handle({ type: "passkeys", on: false })).on, false);
  assert.equal(bg.registered.size, 0);
});

test("a grant without a wish from the popup does not turn passkeys on", async () => {
  const bg = loadBackground();
  bg.granted.add("https://*/*");
  bg.chrome.permissions.onAdded.fire({ origins: ["https://*/*"] });
  await flush();
  assert.equal(bg.registered.size, 0);
});

test("removing the site access in the browser turns passkeys off", async () => {
  const bg = loadBackground({ permissions: ["https://*/*"] });
  assert.equal((await bg.handle({ type: "passkeys", on: true })).on, true);
  assert.deepEqual([...bg.registered.values()][0].matches, ["https://*/*"]);
  bg.granted.clear();
  bg.chrome.permissions.onRemoved.fire({ origins: ["https://*/*"] });
  await flush();
  assert.equal(bg.registered.size, 0);
});

test("turning off ends an open passkey request", async () => {
  const bg = setup({ permissions: ["https://*/*"] });
  await bg.handle({ type: "passkeys", on: true });
  const port = await request(bg, { op: "get", options: getOptions() });
  await bg.handle({ type: "passkeys", on: false });
  await flush();
  assert.deepEqual(port.received, [{ kind: "error", name: "NotAllowedError" }]);
  assert.equal(bg.natives[0].disconnected, true);
});

test("the manifest asks for the passkey site access only as optional", async () => {
  const manifest = loadBackground().chrome.runtime.getManifest();
  assert.deepEqual(manifest.optional_host_permissions, ["https://*/*", "http://localhost/*"]);
  assert.deepEqual(manifest.permissions, ["nativeMessaging", "activeTab", "scripting"]);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.content_scripts, undefined);
  assert.ok(!JSON.stringify(manifest).includes("webAuthenticationProxy"));
});

// --- passwords unchanged, one-time codes ------------------------------------------------

function loginHost(bg, answers) {
  bg.setHost((request, record) => {
    const answer = answers[request.cmd];
    record.port.postMessage(typeof answer === "function" ? answer(request) : answer);
  });
}

test("state: the popup gets hasTotp only as a flag, and the login shape is unchanged without it", async () => {
  const bg = setup();
  loginHost(bg, {
    status: ok({ type: "status", vault: "unlocked", version: "0.3.6" }),
    logins: ok({ type: "logins", origin: ORIGIN, host: "login.example.com", logins: [
      { item: 1, title: "Plain", username: "a" },
      { item: 2, title: "With code", username: "b", has_totp: true, code: "123456", seed: "JBSWY3DPEHPK3PXP" },
    ] }),
  });
  const state = await bg.handle({ type: "state" });
  assert.deepEqual(state.logins, [
    { item: 1, title: "Plain", username: "a" },
    { item: 2, title: "With code", username: "b", hasTotp: true },
  ]);
  assert.ok(!JSON.stringify(state).includes("123456"));
  assert.ok(!JSON.stringify(state).includes("JBSWY3DPEHPK3PXP"));
});

test("a password fill still sends the same request and fills with fillLogin", async () => {
  const bg = setup();
  loginHost(bg, {
    fill: (r) => ok({ type: "fill", item: r.item, origin: ORIGIN, username: "u", password: "p4ss" }),
  });
  bg.scripts.result = () => ({ ok: true, username: true, password: true });
  const reply = await bg.handle({ type: "fill", tabId: 5, url: `${ORIGIN}/login`, item: 7 });
  assert.deepEqual(reply, { ok: true, code: "ok", message: "Filled.", filled: { username: true, password: true } });
  assert.deepEqual(bg.natives[0].sent, [{ v: 1, cmd: "fill", url: `${ORIGIN}/login`, item: 7 }]);
  assert.equal(bg.scripts[0].func.name, "fillLogin");
  assert.deepEqual(bg.scripts[0].target, { tabId: 5, frameIds: [0] });
});

test("fill code: the request, the fill in frame 0 with the code, and a reply without the code", async () => {
  const bg = setup();
  loginHost(bg, { fill_code: (r) => ok({ type: "code", item: r.item, origin: ORIGIN, code: "246810", remaining: 17 }) });
  bg.scripts.result = () => ({ ok: true, reason: "", fields: 1 });
  const reply = await bg.handle({ type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: 9 });
  assert.deepEqual(reply, { ok: true, code: "ok", message: "Code filled.", filled: { fields: 1 } });
  assert.deepEqual(bg.natives[0].sent, [{ v: 1, cmd: "fill_code", url: `${ORIGIN}/login`, item: 9 }]);
  assert.equal(bg.scripts[0].func.name, "fillOneTimeCode");
  assert.deepEqual(bg.scripts[0].target, { tabId: 5, frameIds: [0] });
  assert.deepEqual(bg.scripts[0].args, [ORIGIN, "246810"]);
  assert.ok(!JSON.stringify(reply).includes("246810"));
});

const BAD_CODES = {
  "another origin": { origin: "https://evil.example" },
  "another item": { item: 10 },
  "letters in the code": { code: "12ab56" },
  "a short code": { code: "12345" },
  "a long code": { code: "123456789" },
  "another type": { type: "fill" },
};

for (const [name, change] of Object.entries(BAD_CODES)) {
  test(`fill code answer with ${name}: nothing filled`, async () => {
    const bg = setup();
    loginHost(bg, { fill_code: (r) => ok({ type: "code", item: r.item, origin: ORIGIN, code: "246810", remaining: 17, ...change }) });
    const reply = await bg.handle({ type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: 9 });
    assert.equal(reply.ok, false);
    assert.equal(reply.code, "host_failed");
    assert.equal(bg.scripts.length, 0);
  });
}

test("fill code: the tab went elsewhere during the owner check, nothing filled", async () => {
  const bg = setup();
  loginHost(bg, {
    fill_code: (r) => {
      bg.tabs.set(5, "https://evil.example/");
      return ok({ type: "code", item: r.item, origin: ORIGIN, code: "246810", remaining: 17 });
    },
  });
  const reply = await bg.handle({ type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: 9 });
  assert.deepEqual(reply, { ok: false, code: "page_changed", message: "The page changed. No code was filled." });
  assert.equal(bg.scripts.length, 0);
});

test("fill code: no field on the page is a message, and a cancel is the message of the app", async () => {
  const bg = setup();
  loginHost(bg, { fill_code: (r) => ok({ type: "code", item: r.item, origin: ORIGIN, code: "246810", remaining: 17 }) });
  bg.scripts.result = () => ({ ok: false, reason: "no_fields", fields: 0 });
  const reply = await bg.handle({ type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: 9 });
  assert.deepEqual(reply, { ok: false, code: "no_code_field", message: "Apassy found no field for a one-time code on this page." });
  loginHost(bg, { fill_code: { ok: false, code: "cancelled", message: "The check was cancelled.", data: { type: "none" } } });
  const cancelled = await bg.handle({ type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: 9 });
  assert.deepEqual(cancelled, { ok: false, code: "cancelled", message: "The check was cancelled." });
});

test("fill code needs a tab, a url, and an integer item", async () => {
  const bg = setup();
  for (const message of [
    { type: "fill_code", tabId: 5, url: `${ORIGIN}/login` },
    { type: "fill_code", tabId: 5, url: `${ORIGIN}/login`, item: "9" },
    { type: "fill_code", url: `${ORIGIN}/login`, item: 9 },
  ]) {
    assert.equal((await bg.handle(message)).code, "bad_request");
  }
  assert.equal(bg.natives.length, 0);
});

test("the passkey internals are pure helpers", () => {
  const { cleanText } = setup().internals;
  assert.equal(cleanText("a‮b⁦c\u0007d\ud800e", 64), "a b c d e");
  assert.equal(cleanText("x".repeat(200), 64).length, 64);
  assert.equal(cleanText("😀".repeat(100), 64), "😀".repeat(64));
});
