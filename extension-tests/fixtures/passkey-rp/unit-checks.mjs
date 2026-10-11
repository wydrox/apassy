// RP unit checks. Run: node --test fixtures/passkey-rp/unit-checks.mjs
// (from extension-tests/), or: npm run passkey-rp:check
//
// No browser. The test authenticator signs; @simplewebauthn/server (inside the
// RP) verifies.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { createPasskeyRp } from "./rp-server.mjs";
import {
  FLAG_AT, FLAG_BE, FLAG_UP, FLAG_UV, createTestAuthenticator,
} from "./test-authenticator.mjs";

async function newRp(t, options = {}) {
  const rp = await createPasskeyRp(options);
  await rp.start();
  t.after(() => rp.stop());
  return rp;
}

async function call(rp, route, body, { method = "POST", headers = {}, raw } = {}) {
  const response = await fetch(`${rp.origin}${route}`, {
    method,
    headers: method === "POST" ? { "content-type": "application/json", ...headers } : headers,
    body: method === "POST" ? raw ?? JSON.stringify(body ?? {}) : undefined,
  });
  const text = await response.text();
  let json;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, json, text, headers: response.headers };
}

async function register(rp, authenticator, overrides = {}) {
  const { json: begin } = await call(rp, "/api/register/options");
  const credential = authenticator.register(begin.options, { origin: rp.origin, overrides });
  const result = await call(rp, "/api/register/verify", { ceremonyId: begin.ceremonyId, credential });
  return { begin, credential, result };
}

async function signIn(rp, authenticator, overrides = {}, optionsBody = {}) {
  const { json: begin } = await call(rp, "/api/authenticate/options", optionsBody);
  const credential = authenticator.authenticate(begin.options, { origin: rp.origin, overrides });
  const result = await call(rp, "/api/authenticate/verify", { ceremonyId: begin.ceremonyId, credential });
  return { begin, credential, result };
}

const rejected = (result, status = 400) => {
  assert.equal(result.status, status, result.text);
  assert.equal(result.json.ok, false);
};

// --- configuration ----------------------------------------------------------

test("origin and RP ID come from the configuration", async (t) => {
  const rp = await newRp(t);
  assert.match(rp.origin, /^http:\/\/localhost:\d+$/);
  assert.equal(rp.rpID, "localhost");
  const { json } = await call(rp, "/api/status", null, { method: "GET" });
  assert.equal(json.origin, rp.origin);
  assert.equal(json.rpID, "localhost");
});

test("a configured origin sets a deterministic port", async (t) => {
  const probe = await newRp(t);
  const port = new URL(probe.origin).port;
  await probe.stop();
  const rp = await createPasskeyRp({ origin: `http://localhost:${port}` });
  const started = await rp.start();
  t.after(() => rp.stop());
  assert.equal(started.origin, `http://localhost:${port}`);
});

test("bad configuration is refused", async () => {
  await assert.rejects(createPasskeyRp({ bindAddress: "0.0.0.0" }), /loopback/);
  await assert.rejects(createPasskeyRp({ hostname: "127.0.0.1" }), /IP address/);
  await assert.rejects(createPasskeyRp({ origin: "https://localhost:4173" }), /origin must look like/);
  await assert.rejects(createPasskeyRp({ origin: "http://localhost" }), /origin must look like/);
  await assert.rejects(createPasskeyRp({ origin: "http://example.com:4173" }), /localhost/);
});

// --- options ---------------------------------------------------------------

test("registration options are fresh and require a discoverable, verified passkey", async (t) => {
  const rp = await newRp(t);
  const first = (await call(rp, "/api/register/options")).json;
  const second = (await call(rp, "/api/register/options")).json;
  assert.notEqual(first.options.challenge, second.options.challenge);
  assert.notEqual(first.ceremonyId, second.ceremonyId);
  assert.equal(Buffer.from(first.options.challenge, "base64url").length, 32);
  assert.equal(first.options.rp.id, "localhost");
  assert.equal(first.options.user.name, "synthetic.user@example.test");
  assert.equal(first.options.user.id, rp.userHandle);
  assert.equal(first.options.authenticatorSelection.residentKey, "required");
  assert.equal(first.options.authenticatorSelection.userVerification, "required");
  assert.equal(first.options.attestation, "none");
  assert.deepEqual(first.options.pubKeyCredParams.map((p) => p.alg), [-7, -8, -257]);
  assert.deepEqual(first.options.excludeCredentials ?? [], []);
});

test("authentication options require user verification", async (t) => {
  const rp = await newRp(t);
  const { json } = await call(rp, "/api/authenticate/options");
  assert.equal(json.options.rpId, "localhost");
  assert.equal(json.options.userVerification, "required");
  assert.equal(Buffer.from(json.options.challenge, "base64url").length, 32);
  assert.deepEqual(json.options.allowCredentials ?? [], []);
});

// --- registration ----------------------------------------------------------

test("registration succeeds and the server stores the credential", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { credential, result } = await register(rp, authenticator);
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.verified, true);
  assert.equal(result.json.credentialId, credential.id);
  const [stored] = rp.credentials();
  assert.equal(stored.id, credential.id);
  assert.equal(stored.userVerified, true);
  assert.equal(stored.counter, 0);
  assert.equal(stored.deviceType, "multiDevice");
  assert.equal(rp.status().registrations, 1);
});

test("registration with a wrong challenge fails", async (t) => {
  const rp = await newRp(t);
  const wrong = Buffer.alloc(32, 7).toString("base64url");
  const { result } = await register(rp, createTestAuthenticator(), { challenge: wrong });
  rejected(result);
  assert.equal(rp.credentials().length, 0);
});

test("registration from a wrong origin fails", async (t) => {
  const rp = await newRp(t);
  const { result } = await register(rp, createTestAuthenticator(), { origin: "http://localhost:1" });
  rejected(result);
  assert.equal(rp.credentials().length, 0);
});

test("registration for a wrong RP ID fails", async (t) => {
  const rp = await newRp(t);
  const { result } = await register(rp, createTestAuthenticator(), { rpID: "example.test" });
  rejected(result);
  assert.equal(rp.credentials().length, 0);
});

test("registration without user verification fails", async (t) => {
  const rp = await newRp(t);
  const { result } = await register(rp, createTestAuthenticator(), { flags: FLAG_UP | FLAG_AT | FLAG_BE });
  rejected(result);
  assert.equal(rp.credentials().length, 0);
});

test("registration without user presence fails", async (t) => {
  const rp = await newRp(t);
  const { result } = await register(rp, createTestAuthenticator(), { flags: FLAG_UV | FLAG_AT | FLAG_BE });
  rejected(result);
});

test("registration with an authentication-type client data fails", async (t) => {
  const rp = await newRp(t);
  const { result } = await register(rp, createTestAuthenticator(), { type: "webauthn.get" });
  rejected(result);
});

test("a registered credential is excluded from the next registration", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { credential } = await register(rp, authenticator);
  const { json } = await call(rp, "/api/register/options");
  assert.deepEqual(json.options.excludeCredentials.map((c) => c.id), [credential.id]);
});

test("the server refuses a second registration of the same credential ID", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const first = await register(rp, authenticator);
  const same = Buffer.from(first.credential.id, "base64url");
  const { result } = await register(rp, createTestAuthenticator(), { credentialId: same });
  rejected(result, 409);
  assert.equal(rp.credentials().length, 1);
});

// --- challenge handling ----------------------------------------------------

test("a ceremony works once", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { json: begin } = await call(rp, "/api/register/options");
  const credential = authenticator.register(begin.options, { origin: rp.origin });
  const body = { ceremonyId: begin.ceremonyId, credential };
  assert.equal((await call(rp, "/api/register/verify", body)).status, 200);
  rejected(await call(rp, "/api/register/verify", body));
  assert.equal(rp.pendingCeremonies(), 0);
});

test("a failed attempt uses up the ceremony", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { json: begin } = await call(rp, "/api/register/options");
  const bad = authenticator.register(begin.options, { origin: rp.origin, overrides: { challenge: "AAAA" } });
  rejected(await call(rp, "/api/register/verify", { ceremonyId: begin.ceremonyId, credential: bad }));
  const good = authenticator.register(begin.options, { origin: rp.origin });
  rejected(await call(rp, "/api/register/verify", { ceremonyId: begin.ceremonyId, credential: good }));
  assert.equal(rp.credentials().length, 0);
});

test("a ceremony for registration cannot finish a sign-in", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  const { json: begin } = await call(rp, "/api/register/options");
  const credential = authenticator.authenticate(
    { ...begin.options, rpId: rp.rpID },
    { origin: rp.origin },
  );
  rejected(await call(rp, "/api/authenticate/verify", { ceremonyId: begin.ceremonyId, credential }));
});

test("an unknown ceremony ID fails", async (t) => {
  const rp = await newRp(t);
  rejected(await call(rp, "/api/register/verify", { ceremonyId: "nope", credential: {} }));
  rejected(await call(rp, "/api/register/verify", {}));
});

test("an old ceremony expires", async (t) => {
  let clock = 1_000_000;
  const rp = await newRp(t, { challengeTtlMs: 5_000, now: () => clock });
  const authenticator = createTestAuthenticator();
  const { json: begin } = await call(rp, "/api/register/options");
  const credential = authenticator.register(begin.options, { origin: rp.origin });
  clock += 5_001;
  const result = await call(rp, "/api/register/verify", { ceremonyId: begin.ceremonyId, credential });
  rejected(result);
  assert.equal(result.json.error, "expired_ceremony");
});

// --- authentication --------------------------------------------------------

test("sign-in with a discoverable credential succeeds and updates the counter", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { credential } = await register(rp, authenticator);
  const { result } = await signIn(rp, authenticator, { signCount: 1 });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.verified, true);
  assert.equal(result.json.credentialId, credential.id);
  assert.equal(rp.credentials()[0].counter, 1);
  assert.equal(rp.status().signIns, 1);
});

test("sign-in with an allowCredentials list succeeds", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  const { credential } = await register(rp, authenticator);
  const { begin, result } = await signIn(rp, authenticator, {}, { discoverable: false });
  assert.deepEqual(begin.options.allowCredentials.map((c) => c.id), [credential.id]);
  assert.equal(result.status, 200, result.text);
});

test("sign-in with a wrong challenge fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  const { result } = await signIn(rp, authenticator, { challenge: Buffer.alloc(32, 9).toString("base64url") });
  rejected(result);
  assert.equal(rp.status().signIns, 0);
});

test("sign-in from a wrong origin fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { origin: "https://evil.example" })).result);
});

test("sign-in for a wrong RP ID fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { rpID: "example.test" })).result);
});

test("sign-in without user verification fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { flags: FLAG_UP | FLAG_BE })).result);
});

test("sign-in without user presence fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { flags: FLAG_UV | FLAG_BE })).result);
});

test("sign-in with a registration-type client data fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { type: "webauthn.create" })).result);
});

test("sign-in with an unknown credential fails", async (t) => {
  const rp = await newRp(t);
  const known = createTestAuthenticator();
  await register(rp, known);
  const stranger = createTestAuthenticator();
  stranger.register({ rp: { id: "localhost" }, user: { id: rp.userHandle }, challenge: "AAAA" }, { origin: rp.origin });
  const result = (await signIn(rp, stranger)).result;
  rejected(result);
  assert.equal(result.json.error, "unknown_credential");
});

test("sign-in with a signature from another key fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  const { generateKeyPairSync } = await import("node:crypto");
  const other = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  rejected((await signIn(rp, authenticator, { signWith: other })).result);
});

test("sign-in with a damaged signature fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  rejected((await signIn(rp, authenticator, { corruptSignature: true })).result);
});

test("sign-in with another user handle fails", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  const other = Buffer.alloc(32, 1).toString("base64url");
  const result = (await signIn(rp, authenticator, { userHandle: other })).result;
  rejected(result);
  assert.equal(result.json.error, "wrong_user_handle");
});

test("a lower sign counter is refused after a higher one", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  assert.equal((await signIn(rp, authenticator, { signCount: 5 })).result.status, 200);
  rejected((await signIn(rp, authenticator, { signCount: 3 })).result);
  assert.equal(rp.credentials()[0].counter, 5);
});

test("a counter that stays at zero is accepted", async (t) => {
  const rp = await newRp(t);
  const authenticator = createTestAuthenticator();
  await register(rp, authenticator);
  assert.equal((await signIn(rp, authenticator)).result.status, 200);
  assert.equal((await signIn(rp, authenticator)).result.status, 200);
});

// --- HTTP surface ----------------------------------------------------------

test("the server refuses a foreign Host header", async (t) => {
  const rp = await newRp(t);
  const { default: http } = await import("node:http");
  const status = await new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port: new URL(rp.origin).port, path: "/api/status", headers: { host: "evil.example" } },
      (res) => { res.resume(); resolve(res.statusCode); },
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(status, 421);
});

test("POST checks Origin, content type and size", async (t) => {
  const rp = await newRp(t);
  rejected(await call(rp, "/api/register/options", {}, { headers: { origin: "https://evil.example" } }), 403);
  rejected(await call(rp, "/api/register/options", {}, { headers: { "content-type": "text/plain" } }), 415);
  rejected(await call(rp, "/api/register/options", null, { raw: "{not json" }), 400);
  rejected(await call(rp, "/api/register/verify", null, { raw: JSON.stringify({ pad: "x".repeat(70_000) }) }), 413);
  const same = await call(rp, "/api/register/options", {}, { headers: { origin: rp.origin } });
  assert.equal(same.status, 200);
});

test("unknown routes give 404", async (t) => {
  const rp = await newRp(t);
  rejected(await call(rp, "/api/nothing", null, { method: "GET" }), 404);
  rejected(await call(rp, "/api/reset", {}), 404);
});

test("the page has clear buttons, a status area and a strict policy", async (t) => {
  const rp = await newRp(t);
  const page = await call(rp, "/", null, { method: "GET" });
  assert.equal(page.status, 200);
  assert.match(page.text, /<button[^>]*id="create-passkey"[^>]*>Create passkey<\/button>/);
  assert.match(page.text, /<button[^>]*id="sign-in"[^>]*>Sign in with passkey<\/button>/);
  assert.match(page.text, /id="status"[^>]*data-state="idle"/);
  assert.doesNotMatch(page.text, /<script(?![^>]*src=)[^>]*>/, "no inline script");
  assert.match(page.headers.get("content-security-policy"), /script-src 'self'/);
  assert.equal(page.headers.get("cache-control"), "no-store");
  const script = await call(rp, "/client.js", null, { method: "GET" });
  assert.equal(script.status, 200);
  assert.match(script.text, /parseCreationOptionsFromJSON/);
  assert.match(script.text, /parseRequestOptionsFromJSON/);
  assert.match(script.text, /toJSON/);
});

test("the CLI starts, prints its address and stops", async () => {
  const child = spawn(process.execPath, [new URL("./rp-server.mjs", import.meta.url).pathname, "--port", "0"], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  try {
    const line = await new Promise((resolve, reject) => {
      let buffer = "";
      child.stdout.on("data", (chunk) => {
        buffer += chunk;
        if (buffer.includes("\n")) resolve(buffer.split("\n")[0]);
      });
      child.on("exit", () => reject(new Error("CLI exited early")));
    });
    const info = JSON.parse(line);
    assert.equal(info.ready, true);
    assert.equal(info.rpID, "localhost");
    const response = await fetch(`${info.origin}/healthz`);
    assert.deepEqual(await response.json(), { ok: true });
  } finally {
    child.removeAllListeners("exit");
    child.kill("SIGTERM");
  }
});
