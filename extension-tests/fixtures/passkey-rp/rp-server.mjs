// Local WebAuthn relying party for passkey tests.
//
// Synthetic account only. No real login, no vault, no telemetry, no network
// beyond the loopback listener. Every WebAuthn check is made by
// @simplewebauthn/server; this file only keeps state and routes requests.
//
//   node rp-server.mjs [--port 4173 | --origin http://localhost:4173]
//
// The expected origin and RP ID come from the server's own configuration,
// never from the request.

import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import { isIP } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const STATIC_FILES = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/index.html": ["index.html", "text/html; charset=utf-8"],
  "/client.js": ["client.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
};

// COSE algorithms: ES256, EdDSA, RS256. Fixed, so the result does not depend
// on the Node runtime version.
const ALGORITHMS = [-7, -8, -257];
const MAX_BODY_BYTES = 64 * 1024;
const LOOPBACK_BIND = new Set(["127.0.0.1", "::1"]);

export const SYNTHETIC_USER = Object.freeze({
  name: "synthetic.user@example.test",
  displayName: "Synthetic Test User",
});

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

class HttpError extends Error {
  constructor(status, code, detail) {
    super(detail ?? code);
    this.status = status;
    this.code = code;
  }
}

// Reads the trusted configuration. `origin` must name localhost with an
// explicit port; otherwise the port is `port` (0 means ephemeral).
function resolveConfig({ origin, port = 0, hostname = "localhost", bindAddress = "127.0.0.1" }) {
  if (!LOOPBACK_BIND.has(bindAddress)) {
    throw new Error(`bindAddress must be loopback (127.0.0.1 or ::1), got ${bindAddress}`);
  }
  if (origin !== undefined) {
    const url = new URL(origin);
    if (url.protocol !== "http:" || url.pathname !== "/" || url.search || url.hash || !url.port) {
      throw new Error(`origin must look like http://localhost:PORT, got ${origin}`);
    }
    hostname = url.hostname;
    port = Number(url.port);
  }
  if (isIP(hostname) || hostname.includes(":")) {
    throw new Error("A WebAuthn RP ID cannot be an IP address: use a host name such as localhost");
  }
  if (hostname !== "localhost") {
    throw new Error(`hostname must be localhost, got ${hostname}`);
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port: ${port}`);
  }
  return { hostname, port, bindAddress };
}

export async function createPasskeyRp(options = {}) {
  const { rpName = "Apassy passkey test RP", challengeTtlMs = 120_000, now = Date.now } = options;
  const config = resolveConfig(options);

  let origin = null;
  let rpID = config.hostname;
  let userID = randomBytes(32);
  let ceremonies = new Map(); // ceremonyId -> { type, challenge, expiresAt }
  let credentials = new Map(); // credential id (base64url) -> stored credential
  let events = [];

  const record = (type, ok, reason) => events.push({ type, ok, reason, at: now() });

  function openCeremony(type, challenge) {
    const ceremonyId = randomUUID();
    ceremonies.set(ceremonyId, { type, challenge, expiresAt: now() + challengeTtlMs });
    return ceremonyId;
  }

  // One use: the ceremony is gone after this call, whatever the outcome.
  function takeCeremony(ceremonyId, type) {
    const ceremony = typeof ceremonyId === "string" ? ceremonies.get(ceremonyId) : undefined;
    if (!ceremony) throw new HttpError(400, "unknown_ceremony", "Unknown or used challenge");
    ceremonies.delete(ceremonyId);
    if (ceremony.type !== type) throw new HttpError(400, "wrong_ceremony_type", "Challenge is for another ceremony");
    if (ceremony.expiresAt <= now()) throw new HttpError(400, "expired_ceremony", "Challenge expired");
    return ceremony.challenge;
  }

  async function registerOptions() {
    const challenge = randomBytes(32);
    const optionsJSON = await generateRegistrationOptions({
      rpName,
      rpID,
      userName: SYNTHETIC_USER.name,
      userDisplayName: SYNTHETIC_USER.displayName,
      userID,
      challenge,
      attestationType: "none",
      supportedAlgorithmIDs: ALGORITHMS,
      excludeCredentials: [...credentials.values()].map((c) => ({ id: c.id, transports: c.transports })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    return { ceremonyId: openCeremony("registration", optionsJSON.challenge), options: optionsJSON };
  }

  async function registerVerify({ ceremonyId, credential }) {
    const expectedChallenge = takeCeremony(ceremonyId, "registration");
    requireObject(credential, "credential");
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGORITHMS,
    });
    if (!verification.verified || !verification.registrationInfo.userVerified) {
      throw new HttpError(400, "verification_failed", "Registration not verified");
    }
    const info = verification.registrationInfo;
    if (credentials.has(info.credential.id)) {
      throw new HttpError(409, "credential_exists", "Credential is already registered");
    }
    credentials.set(info.credential.id, {
      id: info.credential.id,
      publicKey: info.credential.publicKey,
      counter: info.credential.counter,
      transports: info.credential.transports,
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      aaguid: info.aaguid,
      userVerified: info.userVerified,
    });
    return { verified: true, credentialId: info.credential.id, credentialCount: credentials.size };
  }

  async function authenticateOptions({ discoverable = true } = {}) {
    const challenge = randomBytes(32);
    const optionsJSON = await generateAuthenticationOptions({
      rpID,
      challenge,
      userVerification: "required",
      allowCredentials: discoverable
        ? undefined
        : [...credentials.values()].map((c) => ({ id: c.id, transports: c.transports })),
    });
    return { ceremonyId: openCeremony("authentication", optionsJSON.challenge), options: optionsJSON };
  }

  async function authenticateVerify({ ceremonyId, credential: response }) {
    const expectedChallenge = takeCeremony(ceremonyId, "authentication");
    requireObject(response, "credential");
    const stored = typeof response.id === "string" ? credentials.get(response.id) : undefined;
    if (!stored) throw new HttpError(400, "unknown_credential", "Credential is not registered");
    const userHandle = response.response?.userHandle;
    if (userHandle !== undefined && userHandle !== b64u(userID)) {
      throw new HttpError(400, "wrong_user_handle", "User handle does not match the account");
    }
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: { id: stored.id, publicKey: stored.publicKey, counter: stored.counter, transports: stored.transports },
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.authenticationInfo.userVerified) {
      throw new HttpError(400, "verification_failed", "Sign-in not verified");
    }
    stored.counter = verification.authenticationInfo.newCounter;
    return { verified: true, credentialId: stored.id, counter: stored.counter };
  }

  function status() {
    return {
      origin,
      rpID,
      credentialCount: credentials.size,
      credentialIds: [...credentials.keys()],
      registrations: events.filter((e) => e.type === "registration" && e.ok).length,
      signIns: events.filter((e) => e.type === "authentication" && e.ok).length,
    };
  }

  const routes = {
    "POST /api/register/options": () => registerOptions(),
    "POST /api/register/verify": (body) => registerVerify(body),
    "POST /api/authenticate/options": (body) => authenticateOptions(body),
    "POST /api/authenticate/verify": (body) => authenticateVerify(body),
    "GET /api/status": () => status(),
    "GET /healthz": () => ({ ok: true }),
  };
  const verifyRoutes = {
    "POST /api/register/verify": "registration",
    "POST /api/authenticate/verify": "authentication",
  };

  async function handle(req, res) {
    const url = new URL(req.url, "http://placeholder.invalid");
    // DNS rebinding guard: only the configured host name and port are served.
    if (req.headers.host !== `${config.hostname}:${port()}`) {
      throw new HttpError(421, "bad_host", "Unexpected Host header");
    }
    if (req.method === "GET" && STATIC_FILES[url.pathname]) {
      const [file, type] = STATIC_FILES[url.pathname];
      return send(res, 200, await readFile(path.join(PUBLIC_DIR, file)), type);
    }
    const key = `${req.method} ${url.pathname}`;
    const route = routes[key];
    if (!route) throw new HttpError(404, "not_found", "No such route");
    let body = {};
    if (req.method === "POST") {
      // Same-origin requests only. Node clients send no Origin header.
      if (req.headers.origin !== undefined && req.headers.origin !== origin) {
        throw new HttpError(403, "bad_origin", "Unexpected Origin header");
      }
      if (!/^application\/json(;|$)/i.test(req.headers["content-type"] ?? "")) {
        throw new HttpError(415, "bad_content_type", "Send application/json");
      }
      body = await readJson(req);
    }
    try {
      const result = await route(body);
      if (key in verifyRoutes) record(verifyRoutes[key], true);
      return send(res, 200, JSON.stringify(result), "application/json; charset=utf-8");
    } catch (error) {
      if (key in verifyRoutes) {
        record(verifyRoutes[key], false, error instanceof HttpError ? error.code : "verification_failed");
      }
      throw error;
    }
  }

  const server = http.createServer((req, res) => {
    setSecurityHeaders(res);
    handle(req, res).catch((error) => {
      const known = error instanceof HttpError;
      const status = known ? error.status : 400;
      const payload = { ok: false, error: known ? error.code : "verification_failed", detail: error.message };
      send(res, status, JSON.stringify(payload), "application/json; charset=utf-8");
    });
  });

  const port = () => server.address().port;

  return {
    async start() {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(config.port, config.bindAddress, resolve);
      });
      origin = `http://${config.hostname}:${port()}`;
      return { origin, rpID, port: port() };
    },
    async stop() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
    get origin() { return origin; },
    get rpID() { return rpID; },
    get userHandle() { return b64u(userID); },
    status,
    credentials: () => [...credentials.values()].map((c) => ({ ...c })),
    events: () => events.map((e) => ({ ...e })),
    pendingCeremonies: () => ceremonies.size,
    // Clears all server state. The synthetic user gets a new user handle.
    reset() {
      ceremonies = new Map();
      credentials = new Map();
      events = [];
      userID = randomBytes(32);
    },
  };
}

function requireObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "bad_request", `${name} must be an object`);
  }
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "too_large", "Body is too large");
    chunks.push(chunk);
  }
  let value;
  try {
    value = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new HttpError(400, "bad_json", "Body is not valid JSON");
  }
  requireObject(value, "body");
  return value;
}

function setSecurityHeaders(res) {
  res.setHeader("cache-control", "no-store");
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader(
    "content-security-policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
}

function send(res, status, body, type = "text/plain; charset=utf-8") {
  res.statusCode = status;
  res.setHeader("content-type", type);
  res.end(body);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--port") out.port = Number(argv[++i]);
    else if (argv[i] === "--origin") out.origin = argv[++i];
    else throw new Error(`Unknown argument: ${argv[i]}`);
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rp = await createPasskeyRp(parseArgs(process.argv.slice(2)));
  const { origin, rpID, port } = await rp.start();
  // One JSON line, so scripts can read the address.
  console.log(JSON.stringify({ ready: true, origin, rpID, port }));
  const quit = () => rp.stop().then(() => process.exit(0));
  process.on("SIGINT", quit);
  process.on("SIGTERM", quit);
}
