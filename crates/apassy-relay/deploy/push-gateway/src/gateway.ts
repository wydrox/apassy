// The push gateway `apassy-push` (docs/contracts/push-gateway-v1.md): `POST /v1/handles`,
// `POST /v1/push`, and `GET /healthz`. It holds the APNs key and the gateway key and
// nothing else: no storage binding, no log. A device exchanges its APNs token for a sealed
// handle and a secret; a node pushes to a handle with a proof made from the secret.
// Erasable TypeScript only, so Node can run it with type stripping in the tests. This is
// not the main module (index.ts), so it may export values freely.

import { APNS_PAYLOAD, providerToken, sendNotification } from "../../worker/src/apns.ts";
import {
  CLOCK_WINDOW_SECS,
  HANDLE_LIFETIME_SECS,
  MAX_BODY_BYTES,
  MAX_HANDLE_CHARS,
  MAX_QUESTION_SECS,
  SECRET_BYTES,
  SUMMARY_BYTES,
  SUMMARY_CHARS,
  decodeB64u,
  decodeExact,
  encodeB64u,
  hasExactly,
  importGatewayKey,
  isBundleId,
  isCollapseId,
  isEnvironment,
  isKind,
  isTime,
  isToken,
  limitKey,
  openHandle,
  parseFlat,
  proofMatches,
  proofMessage,
  sealHandle,
  type GatewayKey,
  type Kind,
} from "./handles.ts";

/** A Rate Limiting binding of Workers (section 13). */
export interface RateLimit {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}

export interface GatewayEnv {
  /** b64u of 32 random bytes: the AES-256-GCM key of new handles. A Worker secret. */
  GATEWAY_KEY?: string;
  /** 1 to 255: the key id written in each new handle. A var. */
  GATEWAY_KEY_ID?: string;
  /** The key before a rotation: its handles open until they expire. A Worker secret. */
  GATEWAY_KEY_PREVIOUS?: string;
  /** The id of GATEWAY_KEY_PREVIOUS. A var. */
  GATEWAY_KEY_PREVIOUS_ID?: string;
  /** The text of the Apple `.p8` file. A Worker secret. */
  APNS_KEY?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  /** The bundle id of the iPhone app: device kind `iphone`. */
  APNS_TOPIC?: string;
  /** The bundle id of the watch app: device kind `watch`. Optional. */
  APNS_WATCH_TOPIC?: string;
  handles_per_address?: RateLimit;
  pushes_per_handle?: RateLimit;
  pushes_per_address?: RateLimit;
}

export interface GatewayDeps {
  fetch: (input: string, init: RequestInit) => Promise<Response>;
  /** Unix seconds. */
  now: () => number;
  /** `length` random bytes. */
  random: (length: number) => Uint8Array;
}

const defaultDeps: GatewayDeps = {
  fetch: (input, init) => fetch(input, init),
  now: () => Math.floor(Date.now() / 1000),
  random: (length) => crypto.getRandomValues(new Uint8Array(length)),
};

/** The period of the Rate Limiting bindings, in seconds: the `Retry-After` of a 429. */
export const LIMIT_PERIOD_SECS = 60;

/** The payload of a push with a sealed summary (section 11), before and after the summary. */
export const SUMMARY_PAYLOAD_HEAD =
  '{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive","mutable-content":1},"s":"';
export const SUMMARY_PAYLOAD_TAIL = '"}';

const HANDLE_FIELDS = ["v", "kind", "token", "environment", "bundle_id"] as const;
const PUSH_FIELDS = ["v", "handle", "at", "expires_at", "collapse_id", "proof"] as const;
const PUSH_FIELDS_SUMMARY = [...PUSH_FIELDS, "summary"] as const;

const HEADERS = { "content-type": "application/json", "cache-control": "no-store" };

function json(body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { ...HEADERS, ...extra } });
}

/** An error in the relay's envelope. A message never holds a request value. */
function error(status: number, code: string, message: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ ok: false, error: { code, message } }), {
    status,
    headers: { ...HEADERS, ...extra },
  });
}

const invalid = () => error(400, "invalid_request", "The request is not valid.");
const tooLarge = () => error(413, "payload_too_large", "The body is larger than 4096 bytes.");
const unavailable = () => error(503, "push_unavailable", "Push is not available on this gateway.");
const limited = () =>
  error(429, "rate_limited", "Too many requests. Try again later.", { "retry-after": String(LIMIT_PERIOD_SECS) });

/** The body as text, or undefined when it is larger than MAX_BODY_BYTES bytes or not UTF-8. */
async function readBody(request: Request): Promise<string | undefined> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
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
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return "";
  }
}

type Body = { ok: true; text: string } | { ok: false; response: Response };

async function body(request: Request): Promise<Body> {
  const declared = request.headers.get("content-length")?.trim() ?? "";
  if (/^[0-9]{1,20}$/.test(declared) && Number(declared) > MAX_BODY_BYTES) {
    return { ok: false, response: tooLarge() };
  }
  const text = await readBody(request);
  if (text === undefined) return { ok: false, response: tooLarge() };
  return { ok: true, text };
}

/** The client address, the key of the per-address limits. */
function address(request: Request): string {
  return request.headers.get("cf-connecting-ip")?.trim() || "unknown";
}

/** Whether the binding lets one more request through. Undefined: no binding, or it failed. */
async function allows(binding: RateLimit | undefined, key: string): Promise<boolean | undefined> {
  if (!binding) return undefined;
  try {
    return (await binding.limit({ key: await limitKey(key) })).success;
  } catch {
    return undefined;
  }
}

/** The topic of a device kind on this gateway. */
function topicOf(env: GatewayEnv, kind: Kind): string | undefined {
  const topic = kind === "iphone" ? env.APNS_TOPIC : env.APNS_WATCH_TOPIC;
  return topic?.trim() || undefined;
}

/** The current key and, after a rotation, the previous one. Undefined: no usable current key. */
async function gatewayKeys(env: GatewayEnv): Promise<GatewayKey[] | undefined> {
  const current = await importGatewayKey(env.GATEWAY_KEY, env.GATEWAY_KEY_ID);
  if (!current) return undefined;
  const keys = [current];
  if (env.GATEWAY_KEY_PREVIOUS !== undefined || env.GATEWAY_KEY_PREVIOUS_ID !== undefined) {
    const previous = await importGatewayKey(env.GATEWAY_KEY_PREVIOUS, env.GATEWAY_KEY_PREVIOUS_ID);
    // A previous key with the current id would make old handles ambiguous: the gateway
    // then opens with the current key only.
    if (previous && previous.id !== current.id) keys.push(previous);
  }
  return keys;
}

/** `POST /v1/handles` (section 6). */
async function createHandle(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  const read = await body(request);
  if (!read.ok) return read.response;
  const flat = parseFlat(read.text);
  if (!flat || !hasExactly(flat, HANDLE_FIELDS) || flat.get("v") !== 1) return invalid();
  const kind = flat.get("kind");
  const token = flat.get("token");
  const environment = flat.get("environment");
  const bundleId = flat.get("bundle_id");
  if (!isKind(kind) || !isToken(token) || !isEnvironment(environment) || !isBundleId(bundleId)) {
    return invalid();
  }
  const allowed = await allows(env.handles_per_address, address(request));
  if (allowed === undefined) return unavailable();
  if (!allowed) return limited();
  const topic = topicOf(env, kind);
  if (!topic) {
    return kind === "watch"
      ? error(409, "kind_unavailable", "This gateway does not push to this kind of device.")
      : unavailable();
  }
  if (bundleId !== topic) {
    return error(409, "wrong_bundle", "This gateway does not push to this app. A build with another bundle id needs its own gateway.");
  }
  const keys = await gatewayKeys(env);
  if (!keys) return unavailable();
  const secret = encodeB64u(deps.random(SECRET_BYTES));
  const issuedAt = deps.now();
  const expiresAt = issuedAt + HANDLE_LIFETIME_SECS;
  const handle = await sealHandle(
    keys[0]!,
    { kind, token, environment, bundle_id: bundleId, secret, issued_at: issuedAt, expires_at: expiresAt },
    deps.random(12),
  );
  return json({ v: 1, handle, secret, expires_at: expiresAt });
}

/** `POST /v1/push` (section 7), with the checks in the contract's order. */
async function push(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  const read = await body(request);
  if (!read.ok) return read.response;

  // 1. The shape and the times.
  const flat = parseFlat(read.text);
  if (!flat || flat.get("v") !== 1) return invalid();
  const withSummary = flat.has("summary");
  if (!hasExactly(flat, withSummary ? PUSH_FIELDS_SUMMARY : PUSH_FIELDS)) return invalid();
  const handle = flat.get("handle");
  const at = flat.get("at");
  const expiresAt = flat.get("expires_at");
  const collapseId = flat.get("collapse_id");
  const proof = flat.get("proof");
  const summary = flat.get("summary");
  if (
    typeof handle !== "string" ||
    handle.length === 0 ||
    handle.length > MAX_HANDLE_CHARS ||
    !/^[A-Za-z0-9_-]+$/.test(handle) ||
    !isTime(at) ||
    !isTime(expiresAt) ||
    !isCollapseId(collapseId) ||
    !decodeExact(proof, 43, 32) ||
    (withSummary && !decodeExact(summary, SUMMARY_CHARS, SUMMARY_BYTES))
  ) {
    return invalid();
  }
  if (!(at < expiresAt && expiresAt <= at + MAX_QUESTION_SECS)) return invalid();

  // 2. The clock.
  const now = deps.now();
  if (Math.abs(at - now) > CLOCK_WINDOW_SECS) {
    return error(403, "stale_request", "The time of the request is more than 300 seconds from the gateway's clock.");
  }

  // 3. The limits: per node address, then per handle.
  const byAddress = await allows(env.pushes_per_address, address(request));
  if (byAddress === undefined) return unavailable();
  if (!byAddress) return limited();
  const byHandle = await allows(env.pushes_per_handle, handle);
  if (byHandle === undefined) return unavailable();
  if (!byHandle) return limited();

  // 4. The handle.
  const keys = await gatewayKeys(env);
  if (!keys) return unavailable();
  const opened = await openHandle(handle, keys, now);
  if (!opened.ok) {
    return opened.code === "handle_expired"
      ? error(403, "handle_expired", "The handle expired. The device makes a new one.")
      : error(403, "handle_invalid", "The handle is not valid at this gateway.");
  }
  const payload = opened.payload;

  // 5. The proof, in constant time.
  const secret = decodeB64u(payload.secret)!;
  const message = proofMessage(handle, at, expiresAt, collapseId, withSummary ? (summary as string) : undefined);
  if (!(await proofMatches(secret, message, proof as string))) {
    return error(403, "proof_invalid", "The proof does not match the handle.");
  }

  // 6. The topic of the kind and the APNs configuration.
  const topic = topicOf(env, payload.kind);
  if (!topic) {
    return payload.kind === "watch"
      ? error(409, "kind_unavailable", "This gateway does not push to this kind of device.")
      : unavailable();
  }
  const { APNS_KEY: key, APNS_KEY_ID: keyId, APNS_TEAM_ID: teamId } = env;
  if (!key || !keyId || !teamId) return unavailable();
  let jwt: string;
  try {
    jwt = await providerToken(key, keyId, teamId, now);
  } catch {
    return unavailable();
  }

  // 7. One APNs request.
  const result = await sendNotification(deps, jwt, {
    token: payload.token,
    environment: payload.environment,
    topic,
    expiresAt,
    collapseId,
    payload: withSummary ? SUMMARY_PAYLOAD_HEAD + (summary as string) + SUMMARY_PAYLOAD_TAIL : APNS_PAYLOAD,
  });
  return json(result.status === 200 ? { v: 1, status: 200 } : { v: 1, status: result.status, reason: result.reason ?? "Unknown" });
}

/** `GET /healthz` (section 8): the `Date` header is the node's clock check. */
function healthz(deps: GatewayDeps): Response {
  return json({ v: 1, ok: true }, { date: new Date(deps.now() * 1000).toUTCString() });
}

/** Every request of the gateway. */
export async function handleGateway(
  request: Request,
  env: GatewayEnv,
  deps: GatewayDeps = defaultDeps,
): Promise<Response> {
  try {
    const path = new URL(request.url).pathname;
    if (path === "/healthz" && request.method === "GET") return healthz(deps);
    if (path === "/v1/handles" && request.method === "POST") return await createHandle(request, env, deps);
    if (path === "/v1/push" && request.method === "POST") return await push(request, env, deps);
    return error(404, "not_found", "Not found.");
  } catch {
    // Nothing of the request goes into the answer or a log.
    return unavailable();
  }
}
