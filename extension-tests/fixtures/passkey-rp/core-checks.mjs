// Independent WebAuthn verification of actual Apassy Vault responses.
// Synthetic account only. No UI, owner-gate, real-device, or browser claim.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createPasskeyRp } from "./rp-server.mjs";

const binary = process.argv[2] || fileURLToPath(new URL("../../../target/debug/examples/passkey-rp-core", import.meta.url));
const child = spawn(binary, [], { stdio: ["pipe", "pipe", "pipe"] });
const lines = createInterface({ input: child.stdout });
let pending;
let stderr = "";
let failure;
child.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-2000); });
child.on("error", (error) => { failure = error; pending?.reject(error); });
child.on("exit", (code) => {
  if (pending) pending.reject(new Error(`Synthetic core stopped (${code}): ${stderr}`));
});
lines.on("line", (line) => {
  const current = pending;
  pending = undefined;
  if (current) {
    try { current.resolve(JSON.parse(line)); } catch (error) { current.reject(error); }
  }
});
async function core(request) {
  if (failure) throw failure;
  assert.equal(pending, undefined, "fixture calls are sequential");
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending = undefined; reject(new Error("Synthetic core timeout")); }, 20_000);
    pending = {
      resolve: (answer) => { clearTimeout(timer); resolve(answer); },
      reject: (error) => { clearTimeout(timer); reject(error); },
    };
    child.stdin.write(JSON.stringify(request) + "\n");
  });
}
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const hash = (bytes) => Array.from(createHash("sha256").update(bytes).digest());
const clientData = (type, options, origin) => Buffer.from(JSON.stringify({ type, challenge: options.challenge, origin, crossOrigin: false }));
const rp = await createPasskeyRp();
let checks = 0;
async function post(route, body = {}) {
  const response = await fetch(rp.origin + route, { method: "POST", headers: { "Content-Type": "application/json", Origin: rp.origin }, body: JSON.stringify(body) });
  return { status: response.status, data: await response.json() };
}
try {
  await rp.start();
  const registration = (await post("/api/register/options")).data;
  const createData = clientData("webauthn.create", registration.options, rp.origin);
  const made = await core({ op: "create", rp_id: rp.rpID, user_handle: Array.from(Buffer.from(registration.options.user.id, "base64url")), hash: hash(createData) });
  assert.equal(made.ok, true);
  const credentialId = b64u(made.credential_id);
  const verified = await post("/api/register/verify", { ceremonyId: registration.ceremonyId, credential: {
    id: credentialId, rawId: credentialId, type: "public-key", authenticatorAttachment: "platform",
    response: { clientDataJSON: b64u(createData), attestationObject: b64u(made.attestation_object), transports: ["internal"] },
    clientExtensionResults: { credProps: { rk: true } },
  } });
  assert.equal(verified.status, 200);
  assert.equal(verified.data.verified, true);
  checks++;

  async function assertion({ discoverable = true, corruptSignature = false, wrongOrigin = false } = {}) {
    const ceremony = (await post("/api/authenticate/options", { discoverable })).data;
    const signedData = clientData("webauthn.get", ceremony.options, rp.origin);
    const signed = await core({ op: "sign", id: made.id, rp_id: rp.rpID, credential_id: made.credential_id, hash: hash(signedData) });
    assert.equal(signed.ok, true);
    const signature = Buffer.from(signed.signature);
    if (corruptSignature) signature[signature.length - 1] ^= 1;
    const presentedData = wrongOrigin ? clientData("webauthn.get", ceremony.options, "https://foreign.example") : signedData;
    return await post("/api/authenticate/verify", { ceremonyId: ceremony.ceremonyId, credential: {
      id: credentialId, rawId: credentialId, type: "public-key", authenticatorAttachment: "platform",
      response: { clientDataJSON: b64u(presentedData), authenticatorData: b64u(signed.authenticator_data), signature: b64u(signature), userHandle: b64u(signed.user_handle) },
      clientExtensionResults: {},
    } });
  }
  for (const discoverable of [true, false]) {
    const result = await assertion({ discoverable });
    assert.equal(result.status, 200);
    assert.equal(result.data.verified, true);
    checks++;
  }
  assert.equal((await core({ op: "reopen" })).ok, true);
  assert.equal((await assertion()).data.verified, true);
  checks++;
  assert.equal((await core({ op: "encrypted_roundtrip" })).ok, true);
  assert.equal((await assertion()).data.verified, true);
  checks++;
  for (const options of [{ corruptSignature: true }, { wrongOrigin: true }]) {
    const result = await assertion(options);
    assert.ok(result.status >= 400 && result.status < 500);
    checks++;
  }
  for (const [rp_id, credential_id] of [["foreign.example", made.credential_id], [rp.rpID, [1, 2, 3]]]) {
    assert.equal((await core({ op: "sign", id: made.id, rp_id, credential_id, hash: Array(32).fill(1) })).ok, false);
    checks++;
  }
  console.log(JSON.stringify({ passed: checks, verifier: "@simplewebauthn/server", scope: "real Vault crypto and encrypted persistence; synthetic account" }));
} finally {
  child.stdin.end(JSON.stringify({ op: "quit" }) + "\n");
  child.kill("SIGTERM");
  lines.close();
  await rp.stop();
}
