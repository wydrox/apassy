// Unit checks of extension/passkey-page.js and passkey-bridge.js, end to end
// through extension/background.js, with a mock of the chrome APIs and a fake
// DOM. The "app" is the SYNTHETIC authenticator of this folder (not Apassy, not
// a vault). Every credential is verified by @simplewebauthn/server, with the
// native-style toJSON() and with a manual conversion like an older RP library.
//
//   node --test fixtures/passkey-bridge/*.unit.mjs        (from extension-tests/)

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { test } from "node:test";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { flush, loadBackground, loadPage, senderFor } from "./mock-chrome.mjs";
import { createSyntheticAuthenticator, fail, ok, syntheticPrf } from "./synthetic-authenticator.mjs";

const ORIGIN = "https://login.example.com";
const RP_ID = "example.com";
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const bytesOf = (buffer) => Buffer.from(new Uint8Array(buffer));

// scenario(wire) -> an answer, or undefined to keep the app waiting.
function pipeline({ scenario, origin = ORIGIN, bridge = true, status = true } = {}) {
  const bg = loadBackground();
  bg.tabs.set(5, `${origin}/login`);
  bg.documents.set("DOC-1", origin);
  const authenticator = createSyntheticAuthenticator();
  const app = (wire) => {
    if (wire.cmd === "passkey_create") return ok(authenticator.create(wire));
    const signed = authenticator.get(wire);
    return signed ? ok(signed) : fail("no_match");
  };
  bg.setHost((wire, record) => {
    // Status is capability negotiation, never an authenticator operation.
    if (wire.cmd === "status") {
      if (status) record.port.postMessage({ ok: true, data: { type: "status", version: "0.5.8" } });
      return;
    }
    const answer = (scenario || app)(wire, app);
    if (answer !== undefined) record.port.postMessage(answer);
  });
  const page = loadPage({ bridge, connect: (info) => bg.connect(senderFor(origin), info.name) });
  return { bg, page, authenticator, credentials: page.navigator.credentials };
}

function creationOptions(extra = {}) {
  return {
    rp: { id: RP_ID, name: "Example" },
    user: { id: new Uint8Array(randomBytes(16)), name: "synthetic@example.com", displayName: "Synthetic User" },
    challenge: new Uint8Array(randomBytes(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    ...extra,
  };
}

// Like client.js of the RP fixture with ?transform=manual.
function manualJSON(credential) {
  const r = credential.response;
  const out = {
    id: credential.id,
    rawId: b64u(bytesOf(credential.rawId)),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  };
  if (r.attestationObject) {
    out.response = {
      clientDataJSON: b64u(bytesOf(r.clientDataJSON)),
      attestationObject: b64u(bytesOf(r.attestationObject)),
      transports: r.getTransports(),
      authenticatorData: b64u(bytesOf(r.getAuthenticatorData())),
      publicKey: b64u(bytesOf(r.getPublicKey())),
      publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
    };
  } else {
    out.response = {
      clientDataJSON: b64u(bytesOf(r.clientDataJSON)),
      authenticatorData: b64u(bytesOf(r.authenticatorData)),
      signature: b64u(bytesOf(r.signature)),
    };
    if (r.userHandle) out.response.userHandle = b64u(bytesOf(r.userHandle));
  }
  return out;
}

async function register(p, extra = {}) {
  const publicKey = creationOptions(extra);
  const credential = await p.credentials.create({ publicKey });
  return { credential, publicKey };
}

for (const transform of ["toJSON", "manual"]) {
  test(`create then get, verified by @simplewebauthn/server (${transform})`, async () => {
    const p = pipeline();
    const { credential, publicKey } = await register(p, { extensions: { credProps: true } });
    const { PublicKeyCredential, Credential, AuthenticatorAttestationResponse, AuthenticatorResponse } = p.page.interfaces;
    assert.ok(credential instanceof PublicKeyCredential);
    assert.ok(credential instanceof Credential);
    assert.ok(credential.response instanceof AuthenticatorAttestationResponse);
    assert.ok(credential.response instanceof AuthenticatorResponse);
    assert.ok(credential.rawId instanceof ArrayBuffer);
    assert.equal(credential.rawId, credential.rawId, "[SameObject]");
    assert.equal(credential.id, b64u(bytesOf(credential.rawId)));
    assert.equal(credential.type, "public-key");
    assert.equal(credential.authenticatorAttachment, "platform");
    assert.deepEqual(credential.getClientExtensionResults(), { credProps: { rk: true } });
    assert.notEqual(credential.getClientExtensionResults(), credential.getClientExtensionResults());
    assert.deepEqual(credential.response.getTransports(), ["internal"]);
    assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
    assert.ok(credential.response.getPublicKey() instanceof ArrayBuffer);
    assert.equal(JSON.stringify(credential), JSON.stringify(credential.toJSON()));

    const registration = await verifyRegistrationResponse({
      response: transform === "toJSON" ? credential.toJSON() : manualJSON(credential),
      expectedChallenge: b64u(publicKey.challenge),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
    assert.equal(registration.verified, true);
    assert.equal(registration.registrationInfo.userVerified, true);
    assert.equal(registration.registrationInfo.credential.id, credential.id);

    const challenge = new Uint8Array(randomBytes(32));
    const assertion = await p.credentials.get({
      publicKey: { challenge, rpId: RP_ID, allowCredentials: [{ type: "public-key", id: credential.rawId }], userVerification: "required" },
    });
    assert.ok(assertion instanceof PublicKeyCredential);
    assert.ok(assertion.response instanceof p.page.interfaces.AuthenticatorAssertionResponse);
    assert.deepEqual(assertion.getClientExtensionResults(), {});
    assert.deepEqual(bytesOf(assertion.response.userHandle), Buffer.from(publicKey.user.id));
    const authentication = await verifyAuthenticationResponse({
      response: transform === "toJSON" ? assertion.toJSON() : manualJSON(assertion),
      expectedChallenge: b64u(challenge),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: registration.registrationInfo.credential,
      requireUserVerification: true,
    });
    assert.equal(authentication.verified, true);
    // The browser's own methods were never called.
    assert.equal(p.page.calls.length, 0);
  });
}

test("the verifier rejects the answer for another origin or challenge (the check is real)", async () => {
  const p = pipeline();
  const { credential, publicKey } = await register(p);
  await assert.rejects(verifyRegistrationResponse({
    response: credential.toJSON(), expectedChallenge: b64u(publicKey.challenge),
    expectedOrigin: "https://evil.example", expectedRPID: RP_ID,
  }));
  await assert.rejects(verifyRegistrationResponse({
    response: credential.toJSON(), expectedChallenge: b64u(randomBytes(32)),
    expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  }));
});

test("the attributes are own read-only properties; the prototype accessors are never hit", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  for (const name of ["id", "rawId", "type", "response", "authenticatorAttachment"]) {
    assert.ok(Object.hasOwn(credential, name), name);
    assert.throws(() => { "use strict"; credential[name] = 1; }, TypeError);
  }
  assert.ok(Object.hasOwn(credential.response, "clientDataJSON"));
  // A copy each time: the page cannot change the next one.
  const data = credential.response.getAuthenticatorData();
  new Uint8Array(data)[0] ^= 0xff;
  assert.notDeepEqual(bytesOf(data), bytesOf(credential.response.getAuthenticatorData()));
});

test("the wrapper keeps the name and the length of the browser methods", () => {
  const p = pipeline();
  const proto = p.page.interfaces.CredentialsContainer.prototype;
  assert.equal(proto.create.name, "create");
  assert.equal(proto.get.name, "get");
  assert.equal(proto.create.length, 1);
  assert.equal(proto.get.length, 1);
});

// --- left to the browser ------------------------------------------------------

const BROWSER_CASES = {
  "no publicKey": () => ({ password: { id: "a", password: "b" } }),
  "a password next to publicKey": () => ({ publicKey: { challenge: new Uint8Array(32) }, password: {} }),
  "conditional mediation": () => ({ mediation: "conditional", publicKey: { challenge: new Uint8Array(randomBytes(32)) } }),
  "immediate mediation": () => ({ mediation: "immediate", publicKey: { challenge: new Uint8Array(randomBytes(32)) } }),
  "a prf input of 1025 bytes": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { prf: { eval: { first: new Uint8Array(1025) } } } } }),
  "a prf input that is not a buffer": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { prf: { eval: { first: "salt" } } } } }),
  "prf evalByCredential without an allow list": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { prf: { evalByCredential: { AQID: { first: new Uint8Array(32) } } } } } }),
  "prf evalByCredential of a credential outside the allow list": () => ({ publicKey: {
    challenge: new Uint8Array(randomBytes(32)), allowCredentials: [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }],
    extensions: { prf: { evalByCredential: { BAUG: { first: new Uint8Array(32) } } } },
  } }),
  "257 prf evalByCredential entries": () => ({ publicKey: {
    challenge: new Uint8Array(randomBytes(32)), allowCredentials: [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }],
    extensions: { prf: { evalByCredential: Object.fromEntries(Array.from({ length: 257 }, (_, i) => [b64u([i & 0xff, i >> 8, 7]), { first: new Uint8Array(32) }])) } },
  } }),
  "a largeBlob support member": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { largeBlob: { support: "required" } } } }),
  "a largeBlob read and write": () => ({ publicKey: {
    challenge: new Uint8Array(randomBytes(32)), allowCredentials: [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }],
    extensions: { largeBlob: { read: true, write: new Uint8Array(4) } },
  } }),
  "a largeBlob write without exactly one allowed credential": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { largeBlob: { write: new Uint8Array(4) } } } }),
  "a largeBlob write above 64 KiB": () => ({ publicKey: {
    challenge: new Uint8Array(randomBytes(32)), allowCredentials: [{ type: "public-key", id: new Uint8Array([1, 2, 3]) }],
    extensions: { largeBlob: { write: new Uint8Array(64 * 1024 + 1) } },
  } }),
  "an appid extension": () => ({ publicKey: { challenge: new Uint8Array(randomBytes(32)), extensions: { appid: "https://example.com" } } }),
  "a challenge that is not a buffer": () => ({ publicKey: { challenge: "abc" } }),
  "a shared buffer": () => ({ publicKey: { challenge: new Uint8Array(new SharedArrayBuffer(32)) } }),
  "an aborted signal": () => { const c = new AbortController(); c.abort(); return { signal: c.signal, publicKey: { challenge: new Uint8Array(randomBytes(32)) } }; },
};

for (const [name, make] of Object.entries(BROWSER_CASES)) {
  test(`get with ${name}: the browser's own method, nothing to the app`, async () => {
    const p = pipeline();
    const options = make();
    assert.equal(await p.credentials.get(options), "browser-get");
    assert.equal(p.page.calls.length, 1);
    assert.equal(p.page.calls[0].options, options, "the same options object");
    assert.equal(p.page.calls[0].self, p.credentials);
    assert.equal(p.page.requests.length, 0);
    assert.equal(p.bg.natives.length, 0);
  });
}

test("create with the defaults of the browser's JSON parser is served (empty hints and attestationFormats)", async () => {
  const p = pipeline();
  const credential = await p.credentials.create({ publicKey: creationOptions({
    hints: [], attestationFormats: [], attestation: "none",
    extensions: { credProps: true, enforceCredentialProtectionPolicy: false },
  }) });
  assert.ok(credential instanceof p.page.interfaces.PublicKeyCredential);
  assert.deepEqual(credential.getClientExtensionResults(), { credProps: { rk: true } });
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ attestationFormats: ["packed"] }) }), "browser-create");
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ extensions: { enforceCredentialProtectionPolicy: true } }) }), "browser-create");
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ extensions: { credentialProtectionPolicy: "userVerificationRequired" } }) }), "browser-create");
});

test("create without ES256 or without a user name goes to the browser before the app", async () => {
  const p = pipeline();
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ pubKeyCredParams: [{ type: "public-key", alg: -8 }] }) }), "browser-create");
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ user: { id: new Uint8Array(4), displayName: "x" } }) }), "browser-create");
  await flush();
  assert.equal(p.bg.natives.length, 0);
  assert.equal(p.page.calls.length, 2);
});

test("no passkey of the site in Apassy (before any owner check): the browser's own get", async () => {
  const p = pipeline();
  const options = { publicKey: { challenge: new Uint8Array(randomBytes(32)), rpId: RP_ID } };
  assert.equal(await p.credentials.get(options), "browser-get");
  assert.equal(p.bg.natives.length, 1);
  assert.deepEqual(p.bg.natives[0].sent.map((wire) => wire.cmd), ["status", "passkey_get"]);
  assert.equal(p.page.calls.length, 1);
  assert.equal(p.page.calls[0].options, options);
});

test("no bridge answer in 1.5 s: the browser's own method", async () => {
  const p = pipeline({ bridge: false });
  const pending = p.credentials.get({ publicKey: { challenge: new Uint8Array(randomBytes(32)) } });
  await p.page.clock.advance(1499);
  assert.equal(p.page.calls.length, 0);
  await p.page.clock.advance(1);
  assert.equal(await pending, "browser-get");
});

// --- after the owner check started: never the browser -------------------------------

for (const [code, name] of [["cancelled", "NotAllowedError"], ["owner_check_failed", "NotAllowedError"], ["refused", "NotAllowedError"]]) {
  test(`the owner ${code}: ${name}, and the browser is not asked`, async () => {
    const p = pipeline({ scenario: () => fail(code) });
    await assert.rejects(p.credentials.create({ publicKey: creationOptions() }), (error) => {
      assert.ok(error instanceof DOMException);
      assert.equal(error.name, name);
      return true;
    });
    assert.equal(p.page.calls.length, 0);
  });
}

test("an excluded credential: InvalidStateError", async () => {
  const p = pipeline({ scenario: () => fail("excluded") });
  await assert.rejects(p.credentials.create({ publicKey: creationOptions({ excludeCredentials: [{ type: "public-key", id: new Uint8Array(16) }] }) }),
    (error) => error instanceof DOMException && error.name === "InvalidStateError");
  assert.equal(p.page.calls.length, 0);
});

test("an answer with another rid: NotAllowedError, no credential", async () => {
  const p = pipeline({ scenario: (wire, app) => {
    const answer = app(wire);
    answer.data.rid = "00000000-0000-4000-8000-000000000000";
    return answer;
  } });
  await assert.rejects(p.credentials.create({ publicKey: creationOptions() }), (error) => error.name === "NotAllowedError");
});

// --- cancel and navigation ---------------------------------------------------------

test("AbortSignal: the page gets the abort reason, the native port closes, a late answer is dropped", async () => {
  let held;
  const p = pipeline({ scenario: (wire, app) => { held = { wire, app }; return undefined; } });
  const controller = new AbortController();
  const pending = p.credentials.create({ signal: controller.signal, publicKey: creationOptions() });
  await flush();
  assert.equal(p.bg.natives.length, 1);
  controller.abort();
  await assert.rejects(pending, (error) => error.name === "AbortError");
  await flush();
  assert.equal(p.bg.natives[0].disconnected, true, "the host sees the end of its input");
  assert.throws(() => p.bg.natives[0].port.postMessage(held.app(held.wire)));
  await flush();
  assert.equal(p.page.calls.length, 0);
});

test("pagehide: AbortError for the page, and the request ends in the app", async () => {
  const p = pipeline({ scenario: () => undefined });
  const pending = p.credentials.get({ publicKey: { challenge: new Uint8Array(randomBytes(32)) } });
  await flush();
  p.page.window.dispatchEvent(new Event("pagehide"));
  await assert.rejects(pending, (error) => error.name === "AbortError");
  await flush();
  assert.equal(p.bg.natives[0].disconnected, true);
});

test("the page's own deadline (200 s) ends a request that never ends", async () => {
  const p = pipeline({ scenario: () => undefined });
  const pending = p.credentials.get({ publicKey: { challenge: new Uint8Array(randomBytes(32)) } });
  await flush();
  const rejected = assert.rejects(pending, (error) => error.name === "NotAllowedError");
  await p.page.clock.advance(200_000);
  await rejected;
  await flush();
  assert.equal(p.bg.natives[0].disconnected, true);
});

test("the worker deadline gives NotAllowedError to the page", async () => {
  const p = pipeline({ scenario: () => undefined });
  const pending = p.credentials.get({ publicKey: { challenge: new Uint8Array(randomBytes(32)), timeout: 30_000 } });
  await flush();
  const rejected = assert.rejects(pending, (error) => error.name === "NotAllowedError");
  await p.bg.clock.advance(30_000);
  await rejected;
});

test("a second request ends the first with NotAllowedError", async () => {
  let calls = 0;
  const p = pipeline({ scenario: (wire, app) => (++calls === 1 ? undefined : app(wire)) });
  const first = p.credentials.create({ publicKey: creationOptions() });
  await flush();
  const second = p.credentials.create({ publicKey: creationOptions() });
  await assert.rejects(first, (error) => error.name === "NotAllowedError");
  assert.ok((await second) instanceof p.page.interfaces.PublicKeyCredential);
});

// --- a page that talks to the bridge itself ------------------------------------------

test("a page that calls the bridge itself gets only its own origin into clientDataJSON", async () => {
  const p = pipeline({ scenario: () => undefined });
  const rid = crypto.randomUUID();
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: JSON.stringify({
    rid, op: "get", origin: "https://bank.example", options: { challenge: b64u(randomBytes(32)), rpId: RP_ID, allowCredentials: [] },
  }) }));
  await flush();
  const wire = p.bg.natives[0].sent.find((wire) => wire.cmd === "passkey_get");
  assert.equal(wire.origin, ORIGIN);
  const clientData = JSON.parse(Buffer.from(wire.client_data_json, "base64").toString("utf8"));
  assert.equal(clientData.origin, ORIGIN);
});

test("forged answers for an unknown rid are ignored", async () => {
  const p = pipeline({ scenario: () => undefined });
  let settled = false;
  p.credentials.get({ publicKey: { challenge: new Uint8Array(randomBytes(32)) } }).then(() => { settled = true; }, () => { settled = true; });
  await flush();
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-response", { detail: JSON.stringify({ rid: crypto.randomUUID(), kind: "fallback" }) }));
  await flush();
  assert.equal(settled, false);
  assert.equal(p.page.calls.length, 0);
});

test("the bridge passes only options and its own browser gesture provenance", async () => {
  const p = pipeline({ scenario: () => undefined });
  const ports = [];
  const original = p.bg.chrome.runtime.onConnect.listeners[0];
  p.bg.chrome.runtime.onConnect.listeners[0] = (port) => {
    port.onMessage.addListener((m) => ports.push(m));
    original(port);
  };
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: JSON.stringify({
    rid: crypto.randomUUID(), op: "get", extra: 1, origin: "https://bank.example",
    options: { challenge: b64u(randomBytes(32)) },
  }) }));
  await flush();
  assert.deepEqual(Object.keys(ports[0]).sort(), ["op", "options", "trustedGesture"]);
});

test("an oversized or malformed request event is ignored by the bridge", async () => {
  const p = pipeline();
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: "x".repeat(140_000) }));
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: "{not json" }));
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: JSON.stringify({ rid: "short", op: "get", options: {} }) }));
  await flush();
  assert.equal(p.bg.natives.length, 0);
});


test("synthetic page event without browser user activation is refused", async () => {
  const p = pipeline();
  p.page.navigator.userActivation.isActive = false;
  p.page.window.dispatchEvent(new CustomEvent("apassy-passkey-request", { detail: JSON.stringify({
    rid: crypto.randomUUID(), op: "get", trustedGesture: true,
    options: { challenge: b64u(randomBytes(32)) },
  }) }));
  await flush();
  assert.equal(p.bg.natives.length, 0, "a page-supplied gesture cannot reach the native host");
});

// --- sign-in extensions: prf and largeBlob ---------------------------------------------

const prfOf = (authenticator, credential, input) =>
  syntheticPrf(Buffer.from(authenticator.credentials.get(bytesOf(credential.rawId).toString("base64")).prfKey, "base64"), input);
const getWire = (p) => p.bg.natives.at(-1).sent.find((wire) => wire.cmd === "passkey_get");

async function signIn(p, credential, extensions, extra = {}) {
  const challenge = new Uint8Array(randomBytes(32));
  const assertion = await p.credentials.get({ publicKey: {
    challenge, rpId: RP_ID, allowCredentials: [{ type: "public-key", id: credential.rawId }], userVerification: "required",
    extensions, ...extra,
  } });
  return { assertion, challenge };
}

test("get with prf eval: the inputs reach the app, the results are ArrayBuffers, toJSON is base64url, the assertion verifies", async () => {
  const p = pipeline();
  const { credential, publicKey } = await register(p);
  const registration = await verifyRegistrationResponse({
    response: credential.toJSON(), expectedChallenge: b64u(publicKey.challenge), expectedOrigin: ORIGIN, expectedRPID: RP_ID,
  });
  const first = new Uint8Array(randomBytes(32));
  const second = new Uint8Array(randomBytes(48));
  const { assertion, challenge } = await signIn(p, credential, { prf: { eval: { first, second: second.buffer } } });
  const wire = getWire(p);
  assert.deepEqual(wire.prf, { eval: { first: Buffer.from(first).toString("base64"), second: Buffer.from(second).toString("base64") } });
  assert.equal(wire.large_blob, undefined);

  const results = assertion.getClientExtensionResults();
  assert.deepEqual(Object.keys(results), ["prf"]);
  assert.ok(results.prf.results.first instanceof ArrayBuffer);
  assert.ok(results.prf.results.second instanceof ArrayBuffer);
  assert.deepEqual(bytesOf(results.prf.results.first), prfOf(p.authenticator, credential, first));
  assert.deepEqual(bytesOf(results.prf.results.second), prfOf(p.authenticator, credential, second));
  // A new copy each time: the page cannot change the next one.
  new Uint8Array(results.prf.results.first)[0] ^= 0xff;
  assert.deepEqual(bytesOf(assertion.getClientExtensionResults().prf.results.first), prfOf(p.authenticator, credential, first));
  assert.deepEqual(assertion.toJSON().clientExtensionResults, { prf: { results: {
    first: b64u(prfOf(p.authenticator, credential, first)), second: b64u(prfOf(p.authenticator, credential, second)),
  } } });

  const authentication = await verifyAuthenticationResponse({
    response: assertion.toJSON(), expectedChallenge: b64u(challenge), expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: registration.registrationInfo.credential, requireUserVerification: true,
  });
  assert.equal(authentication.verified, true);
  assert.equal(p.page.calls.length, 0);
});

test("get with prf evalByCredential: the inputs of the chosen credential win over eval", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const mine = new Uint8Array(randomBytes(32));
  const all = new Uint8Array(randomBytes(32));
  const { assertion } = await signIn(p, credential, { prf: { eval: { first: all }, evalByCredential: { [credential.id]: { first: mine } } } });
  assert.deepEqual(getWire(p).prf, {
    eval: { first: Buffer.from(all).toString("base64") },
    eval_by_credential: { [credential.id]: { first: Buffer.from(mine).toString("base64") } },
  });
  const results = assertion.getClientExtensionResults();
  assert.deepEqual(bytesOf(results.prf.results.first), prfOf(p.authenticator, credential, mine));
  assert.equal(results.prf.results.second, undefined);
});

test("get with prf, and an app without PRF outputs: no prf member, as for a client without the extension", async () => {
  const p = pipeline({ scenario: (wire, app) => {
    const answer = app(wire);
    if (answer.data && answer.data.prf) delete answer.data.prf;
    return answer;
  } });
  const { credential } = await register(p);
  const { assertion } = await signIn(p, credential, { prf: { eval: { first: new Uint8Array(32) } } });
  assert.deepEqual(assertion.getClientExtensionResults(), {});
  assert.deepEqual(assertion.toJSON().clientExtensionResults, {});
});

test("largeBlob: a write, then a read gives the blob; a read without a blob gives {}", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const empty = await signIn(p, credential, { largeBlob: { read: true } });
  assert.deepEqual(getWire(p).large_blob, { read: true });
  assert.deepEqual(empty.assertion.getClientExtensionResults(), { largeBlob: {} });

  const blob = new Uint8Array(randomBytes(40 * 1024));
  const written = await signIn(p, credential, { largeBlob: { write: blob } });
  assert.deepEqual(getWire(p).large_blob, { write: Buffer.from(blob).toString("base64") });
  assert.deepEqual(written.assertion.getClientExtensionResults(), { largeBlob: { written: true } });
  assert.deepEqual(written.assertion.toJSON().clientExtensionResults, { largeBlob: { written: true } });

  const read = await signIn(p, credential, { largeBlob: { read: true } });
  const results = read.assertion.getClientExtensionResults();
  assert.ok(results.largeBlob.blob instanceof ArrayBuffer);
  assert.deepEqual(bytesOf(results.largeBlob.blob), Buffer.from(blob));
  assert.deepEqual(read.assertion.toJSON().clientExtensionResults, { largeBlob: { blob: b64u(blob) } });
  assert.equal(p.page.calls.length, 0);
});

test("empty prf inputs reach the app as empty values and give results (WebAuthn sets no minimum)", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const empty = new Uint8Array(0);
  const { assertion } = await signIn(p, credential, { prf: { eval: { first: empty, second: new ArrayBuffer(0) } } });
  assert.deepEqual(getWire(p).prf, { eval: { first: "", second: "" } });
  const results = assertion.getClientExtensionResults();
  assert.deepEqual(bytesOf(results.prf.results.first), prfOf(p.authenticator, credential, empty));
  assert.deepEqual(bytesOf(results.prf.results.second), prfOf(p.authenticator, credential, empty));
});

test("an empty largeBlob write goes to Apassy, which answers written: false", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const { assertion } = await signIn(p, credential, { largeBlob: { write: new Uint8Array(0) } });
  assert.deepEqual(getWire(p).large_blob, { write: "" });
  assert.deepEqual(assertion.getClientExtensionResults(), { largeBlob: { written: false } });
  assert.deepEqual(assertion.toJSON().clientExtensionResults, { largeBlob: { written: false } });
  assert.equal(p.page.calls.length, 0);
  const read = await signIn(p, credential, { largeBlob: { read: true } });
  assert.deepEqual(read.assertion.getClientExtensionResults(), { largeBlob: {} }, "nothing was stored");
});

test("largeBlob read of false asks for nothing and is served", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const { assertion } = await signIn(p, credential, { largeBlob: { read: false } });
  assert.equal(getWire(p).large_blob, undefined);
  assert.deepEqual(assertion.getClientExtensionResults(), {});
});

test("a largeBlob write too large for the host goes to the browser before the app", async () => {
  const p = pipeline();
  const { credential } = await register(p);
  const natives = p.bg.natives.length;
  const result = await p.credentials.get({ publicKey: {
    challenge: new Uint8Array(randomBytes(32)), allowCredentials: [{ type: "public-key", id: credential.rawId }],
    extensions: { largeBlob: { write: new Uint8Array(60 * 1024) } },
  } });
  assert.equal(result, "browser-get");
  await flush();
  assert.equal(p.bg.natives.length, natives, "no native port for the request");
});

test("create with prf or largeBlob stays with the browser (no PRF at registration)", async () => {
  const p = pipeline();
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ extensions: { prf: {} } }) }), "browser-create");
  assert.equal(await p.credentials.create({ publicKey: creationOptions({ extensions: { largeBlob: { support: "preferred" } } }) }), "browser-create");
  await flush();
  assert.equal(p.bg.natives.length, 0);
  const { credential } = await register(p, { extensions: { credProps: true } });
  assert.deepEqual(credential.getClientExtensionResults(), { credProps: { rk: true } });
  assert.deepEqual(credential.toJSON().clientExtensionResults, { credProps: { rk: true } });
});

test("an EdDSA assertion (another algorithm than ES256) reaches the page and verifies", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const credentialId = randomBytes(16);
  const userHandle = randomBytes(16);
  const p = pipeline({ scenario: (wire) => {
    if (wire.cmd !== "passkey_get") return undefined;
    const data = Buffer.concat([createHash("sha256").update(RP_ID).digest(), Buffer.from([0x1d, 0, 0, 0, 1])]);
    const clientDataHash = createHash("sha256").update(Buffer.from(wire.client_data_json, "base64")).digest();
    return ok({
      type: "passkey", rid: wire.rid, credential_id: credentialId.toString("base64"), user_handle: userHandle.toString("base64"),
      authenticator_data: data.toString("base64"), signature: sign(null, Buffer.concat([data, clientDataHash]), privateKey).toString("base64"),
      algorithm: -8, client_data_json: wire.client_data_json,
    });
  } });
  const challenge = new Uint8Array(randomBytes(32));
  const assertion = await p.credentials.get({ publicKey: {
    challenge, rpId: RP_ID, allowCredentials: [{ type: "public-key", id: new Uint8Array(credentialId) }],
  } });
  assert.equal(assertion.response.signature.byteLength, 64);
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const coseKey = isoCBOR.encode(new Map([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(x)]]));
  const authentication = await verifyAuthenticationResponse({
    response: assertion.toJSON(), expectedChallenge: b64u(challenge), expectedOrigin: ORIGIN, expectedRPID: RP_ID,
    credential: { id: b64u(credentialId), publicKey: coseKey, counter: 0 }, requireUserVerification: true,
  });
  assert.equal(authentication.verified, true);
});
