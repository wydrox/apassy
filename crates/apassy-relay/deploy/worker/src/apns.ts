// The APNs sender of the edge Worker (SPEC 25): `POST /internal/push`. The relay calls
// it with a shared secret and a list of device tokens, and the Worker sends a push
// without content to each token. The route is handled here and never forwarded.
// Erasable TypeScript only (no enums, namespaces, or parameter properties), so
// Node can run it with type stripping in the tests.
// This is not the main module, so it may export values freely. Nothing is logged:
// tokens and keys must not reach the logs.

export const PUSH_PATH = "/internal/push";
export const PUSH_HEADER = "x-apassy-push";
/** The most device tokens in one call. */
export const MAX_PUSH_TOKENS = 50;
/** The largest request body, in bytes. */
export const MAX_PUSH_BODY = 64 * 1024;
/** Apple wants a provider token between 20 and 60 minutes old. */
export const TOKEN_LIFETIME_SECS = 50 * 60;
/** The same text for every push: the content stays on the device (SPEC 25). */
export const APNS_PAYLOAD =
  '{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}';

/** Finish before the relay's ten-second request deadline, including error bodies. */
export const APNS_TIMEOUT_MS = 8_000;
const MAX_APNS_ERROR_BODY = 4096;

const APNS_PRODUCTION = "https://api.push.apple.com/3/device/";
const APNS_SANDBOX = "https://api.sandbox.push.apple.com/3/device/";

export interface PushEnv {
  /** The shared secret of the relay's calls. A Worker secret. */
  PUSH_SECRET?: string;
  /** The text of the Apple `.p8` file (a PKCS#8 EC P-256 key in PEM). A Worker secret. */
  APNS_KEY?: string;
  /** The id of the APNs key. A var. */
  APNS_KEY_ID?: string;
  /** The Apple team id. A var. */
  APNS_TEAM_ID?: string;
  /** The bundle id of the app. A var. */
  APNS_TOPIC?: string;
}

export interface PushDeps {
  fetch: (input: string, init: RequestInit) => Promise<Response>;
  /** Unix seconds. */
  now: () => number;
}

const defaultDeps: PushDeps = {
  fetch: (input, init) => fetch(input, init),
  now: () => Math.floor(Date.now() / 1000),
};

interface CachedToken {
  iat: number;
  keyId: string;
  teamId: string;
  key: string;
  jwt: string;
}

let cached: CachedToken | undefined;

/** Forget the provider token. For the tests. */
export function resetTokenCache(): void {
  cached = undefined;
}

function text(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

/** An error in the relay's JSON envelope. */
function jsonError(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ ok: false, error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function digest(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

// Compares the SHA-256 digests, so the time does not depend on where the values differ
// or on their lengths.
async function secretMatches(given: string | null, expected: string): Promise<boolean> {
  const a = await digest(given ?? "");
  const b = await digest(expected);
  let diff = given === null ? 1 : 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END)[^-]*-----/g, "").replace(/\s+/g, "");
  const binary = atob(body);
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) der[i] = binary.charCodeAt(i);
  return der;
}

/** A provider token (ES256 JWT). It is kept while it is young and its inputs are unchanged. */
async function providerToken(key: string, keyId: string, teamId: string, now: number): Promise<string> {
  if (
    cached &&
    cached.keyId === keyId &&
    cached.teamId === teamId &&
    cached.key === key &&
    now - cached.iat < TOKEN_LIFETIME_SECS
  ) {
    return cached.jwt;
  }
  const encoder = new TextEncoder();
  const header = base64url(encoder.encode(JSON.stringify({ alg: "ES256", kid: keyId })));
  const claims = base64url(encoder.encode(JSON.stringify({ iss: teamId, iat: now })));
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(key),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  // WebCrypto gives the raw r||s form (64 bytes) that JWS needs.
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey,
    encoder.encode(`${header}.${claims}`),
  );
  const jwt = `${header}.${claims}.${base64url(new Uint8Array(signature))}`;
  cached = { iat: now, keyId, teamId, key, jwt };
  return jwt;
}

interface PushRequest {
  tokens: string[];
  environment: "development" | "production";
  collapseId: string;
  expiresAt: number;
}

function parsePush(raw: string): PushRequest | undefined {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  if (keys.join(",") !== "collapse_id,environment,expires_at,tokens") return undefined;
  const { tokens, environment, collapse_id: collapseId, expires_at: expiresAt } = object;
  if (!Array.isArray(tokens) || tokens.length < 1 || tokens.length > MAX_PUSH_TOKENS) return undefined;
  for (const token of tokens) {
    if (typeof token !== "string" || !/^[0-9a-f]{32,200}$/.test(token)) return undefined;
  }
  if (environment !== "development" && environment !== "production") return undefined;
  if (typeof collapseId !== "string" || collapseId.length > 64 || !/^[A-Za-z0-9._-]+$/.test(collapseId)) {
    return undefined;
  }
  if (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt < 0) return undefined;
  return { tokens: tokens as string[], environment, collapseId, expiresAt };
}

/** The body as text, or undefined when it is larger than MAX_PUSH_BODY bytes. */
async function readBody(request: Request | Response, maxBytes = MAX_PUSH_BODY): Promise<string | undefined> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

interface PushResult {
  token: string;
  status: number;
  reason?: string;
}

async function sendOne(
  deps: PushDeps,
  push: PushRequest,
  jwt: string,
  topic: string,
  token: string,
): Promise<PushResult> {
  const base = push.environment === "production" ? APNS_PRODUCTION : APNS_SANDBOX;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), APNS_TIMEOUT_MS);
  try {
    const response = await deps.fetch(base + token, {
      method: "POST",
      signal: controller.signal,
      headers: {
        authorization: `bearer ${jwt}`,
        "apns-topic": topic,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": String(push.expiresAt),
        "apns-collapse-id": push.collapseId,
        "content-type": "application/json",
      },
      body: APNS_PAYLOAD,
    });
    if (response.status === 200) {
      await response.body?.cancel().catch(() => undefined);
      return { token, status: 200 };
    }
    let reason = "Unknown";
    const raw = await readBody(response, MAX_APNS_ERROR_BODY);
    try {
      const body: unknown = raw === undefined ? undefined : JSON.parse(raw);
      if (typeof body === "object" && body !== null && "reason" in body &&
          typeof body.reason === "string" && /^[A-Za-z]{1,64}$/.test(body.reason)) reason = body.reason;
    } catch {
      // An empty or non-JSON body keeps the reason Unknown.
    }
    return { token, status: response.status, reason };
  } catch {
    return { token, status: 0, reason: "Unreachable" };
  } finally {
    clearTimeout(timer);
  }
}

/** Handles every request whose path starts with `/internal/`. */
export async function handleInternal(
  request: Request,
  env: PushEnv,
  deps: PushDeps = defaultDeps,
): Promise<Response> {
  const notFound = () => text(404, "not found");
  if (request.method !== "POST" || new URL(request.url).pathname !== PUSH_PATH) return notFound();
  if (!env.PUSH_SECRET || !(await secretMatches(request.headers.get(PUSH_HEADER), env.PUSH_SECRET))) {
    return notFound();
  }

  const declared = request.headers.get("content-length")?.trim() ?? "";
  if (/^[0-9]{1,20}$/.test(declared) && Number(declared) > MAX_PUSH_BODY) {
    return jsonError(413, "payload_too_large", "The body is larger than 64 KiB.");
  }
  const raw = await readBody(request);
  if (raw === undefined) return jsonError(413, "payload_too_large", "The body is larger than 64 KiB.");
  const push = parsePush(raw);
  if (!push) return jsonError(400, "invalid_request", "The push request is not valid.");

  const { APNS_KEY: key, APNS_KEY_ID: keyId, APNS_TEAM_ID: teamId, APNS_TOPIC: topic } = env;
  if (!key || !keyId || !teamId || !topic) {
    return jsonError(503, "push_unavailable", "Push is not configured.");
  }
  let jwt: string;
  try {
    jwt = await providerToken(key, keyId, teamId, deps.now());
  } catch {
    return jsonError(503, "push_unavailable", "Push is not available.");
  }

  const results = await Promise.all(push.tokens.map((token) => sendOne(deps, push, jwt, topic, token)));
  return new Response(JSON.stringify({ results }), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
