// Local relying party for the Linux vault acceptance kit (packaging/linux/acceptance).
//
// Synthetic accounts only: no real login, no real relying party, no network beyond
// the loopback listener. @simplewebauthn/server makes every WebAuthn decision. After
// each accepted response the server repeats the verification with a wrong origin, a
// wrong RP ID and (for sign-in) a damaged signature; each repeat must be refused.
//
//   node server.mjs --port 4174 [--log events.jsonl]
//   L4_LOGIN_PASSWORD=<synthetic password> enables the password login check.
//   L4_TOTP_SEED=<synthetic base32 seed> enables the one-time code check (otp.html):
//   RFC 6238, SHA-1, 6 digits, 30 s, the current step or one step either side.
//
// The expected origin and RP ID come from this configuration, never from a request.

import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const STATIC = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/passkey.html": ["passkey.html", "text/html; charset=utf-8"],
  "/passkey.js": ["passkey.js", "text/javascript; charset=utf-8"],
  "/login.html": ["login.html", "text/html; charset=utf-8"],
  "/login.js": ["login.js", "text/javascript; charset=utf-8"],
  "/otp.html": ["otp.html", "text/html; charset=utf-8"],
  "/otp.js": ["otp.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
};
const ES256 = -7;
const WRONG_RP_ID = "example.com";
const MAX_BODY = 64 * 1024;
export const PASSKEY_USER = Object.freeze({ name: "synthetic.passkey@example.test", displayName: "Synthetic Passkey User" });
export const LOGIN_USER = "synthetic.login@example.test";

class HttpError extends Error {
  constructor(status, code, detail) {
    super(detail ?? code);
    this.status = status;
    this.code = code;
  }
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

function base32(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of text.replace(/=+$/, "").toUpperCase()) {
    const value = alphabet.indexOf(ch);
    if (value < 0) throw new Error("L4_TOTP_SEED is not base32");
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totp(seed, unixSeconds) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const mac = createHmac("sha1", base32(seed)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

function parseArgs(argv) {
  const out = { port: 4174, log: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--port") out.port = Number(argv[++i]);
    else if (argv[i] === "--log") out.log = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  if (!Number.isInteger(out.port) || out.port < 1 || out.port > 65535) throw new Error("--port must be 1..65535");
  return out;
}

export function createRp({ port, log, loginPassword, totpSeed }) {
  const origin = `http://localhost:${port}`;
  const rpID = "localhost";
  const userID = randomBytes(32);
  const ceremonies = new Map();
  const credentials = new Map();
  const events = [];

  function record(kind, ok, detail = {}) {
    const event = { at: new Date().toISOString(), kind, ok, ...detail };
    events.push(event);
    if (log) appendFileSync(log, `${JSON.stringify(event)}\n`);
    return event;
  }

  function open(type, challenge) {
    const id = randomUUID();
    ceremonies.set(id, { type, challenge, expires: Date.now() + 180_000 });
    return id;
  }

  function take(id, type) {
    const c = typeof id === "string" ? ceremonies.get(id) : undefined;
    if (!c) throw new HttpError(400, "unknown_ceremony");
    ceremonies.delete(id);
    if (c.type !== type) throw new HttpError(400, "wrong_ceremony_type");
    if (c.expires <= Date.now()) throw new HttpError(400, "expired_ceremony");
    return c.challenge;
  }

  // A repeat that must fail. Returns "refused" or "ACCEPTED" (a defect).
  async function mustRefuse(run) {
    try {
      const result = await run();
      return result?.verified ? "ACCEPTED" : "refused";
    } catch {
      return "refused";
    }
  }

  async function registerOptions(body) {
    const wrong = body.wrongRp === true;
    const options = await generateRegistrationOptions({
      rpName: "Apassy Linux acceptance RP",
      rpID: wrong ? WRONG_RP_ID : rpID,
      userName: PASSKEY_USER.name,
      userDisplayName: PASSKEY_USER.displayName,
      userID,
      challenge: randomBytes(32),
      timeout: 180_000,
      attestationType: "none",
      supportedAlgorithmIDs: [ES256],
      excludeCredentials: [...credentials.values()].map((c) => ({ id: c.id })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    if (wrong) record("wrong_rp_create_offered", true, { rpID: WRONG_RP_ID });
    return { ceremonyId: open(wrong ? "wrong-registration" : "registration", options.challenge), options };
  }

  async function registerVerify({ ceremonyId, credential }) {
    const expectedChallenge = take(ceremonyId, "registration");
    const base = { response: credential, expectedChallenge, requireUserPresence: true, requireUserVerification: true, supportedAlgorithmIDs: [ES256] };
    const v = await verifyRegistrationResponse({ ...base, expectedOrigin: origin, expectedRPID: rpID });
    if (!v.verified || !v.registrationInfo.userVerified) throw new HttpError(400, "verification_failed");
    const info = v.registrationInfo;
    const negative = {
      wrongOrigin: await mustRefuse(() => verifyRegistrationResponse({ ...base, expectedOrigin: "http://localhost:1", expectedRPID: rpID })),
      wrongRpId: await mustRefuse(() => verifyRegistrationResponse({ ...base, expectedOrigin: origin, expectedRPID: WRONG_RP_ID })),
    };
    credentials.set(info.credential.id, { id: info.credential.id, publicKey: info.credential.publicKey, counter: info.credential.counter });
    return record("registration", true, {
      credentialId: info.credential.id,
      aaguid: info.aaguid,
      fmt: info.fmt,
      userVerified: info.userVerified,
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      attachment: credential.authenticatorAttachment ?? null,
      negative,
    });
  }

  async function authenticateOptions(body) {
    const wrong = body.wrongRp === true;
    // Discoverable: no allowCredentials, so the authenticator must find the passkey.
    const options = await generateAuthenticationOptions({ rpID: wrong ? WRONG_RP_ID : rpID, challenge: randomBytes(32), timeout: 180_000, userVerification: "required" });
    if (wrong) record("wrong_rp_get_offered", true, { rpID: WRONG_RP_ID });
    return { ceremonyId: open(wrong ? "wrong-authentication" : "authentication", options.challenge), options };
  }

  async function authenticateVerify({ ceremonyId, credential }) {
    const expectedChallenge = take(ceremonyId, "authentication");
    const stored = typeof credential?.id === "string" ? credentials.get(credential.id) : undefined;
    if (!stored) throw new HttpError(400, "unknown_credential");
    const handle = credential.response?.userHandle;
    if (handle !== b64u(userID)) throw new HttpError(400, "wrong_or_missing_user_handle");
    const base = { response: credential, expectedChallenge, requireUserVerification: true, credential: { ...stored } };
    const v = await verifyAuthenticationResponse({ ...base, expectedOrigin: origin, expectedRPID: rpID });
    if (!v.verified || !v.authenticationInfo.userVerified) throw new HttpError(400, "verification_failed");
    const sig = Buffer.from(credential.response.signature, "base64url");
    sig[sig.length - 1] ^= 0x01;
    const damaged = { ...credential, response: { ...credential.response, signature: b64u(sig) } };
    const negative = {
      wrongOrigin: await mustRefuse(() => verifyAuthenticationResponse({ ...base, expectedOrigin: "http://localhost:1", expectedRPID: rpID })),
      wrongRpId: await mustRefuse(() => verifyAuthenticationResponse({ ...base, expectedOrigin: origin, expectedRPID: WRONG_RP_ID })),
      damagedSignature: await mustRefuse(() => verifyAuthenticationResponse({ ...base, response: damaged, expectedOrigin: origin, expectedRPID: rpID })),
    };
    stored.counter = v.authenticationInfo.newCounter;
    return record("authentication", true, { credentialId: stored.id, userVerified: v.authenticationInfo.userVerified, discoverable: true, negative });
  }

  function login({ username, password }) {
    if (!loginPassword) throw new HttpError(400, "no_login_password_configured");
    const ok = username === LOGIN_USER && password === loginPassword;
    // Never log the password; only whether it matched.
    return record("password_login", ok, { usernameMatches: username === LOGIN_USER, passwordMatches: password === loginPassword, passwordLength: typeof password === "string" ? password.length : 0 });
  }

  function otpLogin({ code }) {
    if (!totpSeed) throw new HttpError(400, "no_totp_seed_configured");
    const now = Date.now() / 1000;
    const ok = typeof code === "string" && [-30, 0, 30].some((skew) => totp(totpSeed, now + skew) === code);
    // Never log the code; only whether it matched.
    return record("otp_login", ok, { codeMatches: ok, codeLength: typeof code === "string" ? code.length : 0 });
  }

  function clientEvent(body) {
    const pick = (v) => (typeof v === "string" ? v.slice(0, 300) : undefined);
    return record(`client_${pick(body.kind) ?? "event"}`, body.ok === true, { name: pick(body.name), message: pick(body.message) });
  }

  const routes = {
    "POST /api/register/options": registerOptions,
    "POST /api/register/verify": registerVerify,
    "POST /api/authenticate/options": authenticateOptions,
    "POST /api/authenticate/verify": authenticateVerify,
    "POST /api/login": login,
    "POST /api/otp": otpLogin,
    "POST /api/client-event": clientEvent,
    "GET /api/status": () => ({ origin, rpID, credentials: [...credentials.keys()], events }),
  };

  async function handle(req, res) {
    if (req.headers.host !== `localhost:${port}`) throw new HttpError(421, "bad_host");
    const url = new URL(req.url, "http://placeholder.invalid");
    if (req.method === "GET" && STATIC[url.pathname]) {
      const [file, type] = STATIC[url.pathname];
      return send(res, 200, await readFile(path.join(PUBLIC_DIR, file)), type);
    }
    const key = `${req.method} ${url.pathname}`;
    const route = routes[key];
    if (!route) throw new HttpError(404, "not_found");
    let body = {};
    if (req.method === "POST") {
      if (req.headers.origin !== undefined && req.headers.origin !== origin) throw new HttpError(403, "bad_origin");
      if (!/^application\/json(;|$)/i.test(req.headers["content-type"] ?? "")) throw new HttpError(415, "bad_content_type");
      body = await readJson(req);
    }
    try {
      return send(res, 200, JSON.stringify(await route(body)), "application/json; charset=utf-8");
    } catch (error) {
      if (key.endsWith("/verify")) record(key.includes("register") ? "registration" : "authentication", false, { error: error.code ?? "verification_failed", detail: String(error.message).slice(0, 300) });
      throw error;
    }
  }

  const server = http.createServer((req, res) => {
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    handle(req, res).catch((error) => {
      const status = error instanceof HttpError ? error.status : 400;
      send(res, status, JSON.stringify({ ok: false, error: error.code ?? "verification_failed", detail: String(error.message).slice(0, 300) }), "application/json; charset=utf-8");
    });
  });

  return {
    origin,
    start: () => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => resolve({ origin, rpID, port }));
    }),
    stop: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
  };
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "too_large");
    chunks.push(chunk);
  }
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { throw new HttpError(400, "bad_json"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "bad_request");
  return value;
}

function send(res, status, body, type) {
  res.statusCode = status;
  res.setHeader("content-type", type);
  res.end(body);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = parseArgs(process.argv.slice(2));
  const rp = createRp({ ...args, loginPassword: process.env.L4_LOGIN_PASSWORD || null, totpSeed: process.env.L4_TOTP_SEED || null });
  const info = await rp.start();
  console.log(JSON.stringify({ ready: true, ...info }));
  const quit = () => rp.stop().then(() => process.exit(0));
  process.on("SIGINT", quit);
  process.on("SIGTERM", quit);
}
