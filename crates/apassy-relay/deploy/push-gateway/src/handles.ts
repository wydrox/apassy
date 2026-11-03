// The handles and proofs of the push gateway (docs/contracts/push-gateway-v1.md,
// sections 3, 5, 7, and 12): base64url, the strict JSON of the bodies, sealing and
// opening a handle under the gateway key (AES-256-GCM), and the proof of a push
// (HMAC-SHA256 under the handle's secret).
// Erasable TypeScript only (no enums, namespaces, or parameter properties), so Node can
// run it with type stripping in the tests. This is not the main module, so it may export
// values freely. Nothing here logs: a token, handle, secret, proof, or summary must not
// reach a log or an error message.

/** The format byte of a handle (section 5). */
export const HANDLE_FORMAT = 0x01;
/** The domain of the handle's additional data. */
export const HANDLE_DOMAIN = "apassy-push-handle-v1";
/** The domain of the proof of a push (section 7). */
export const PROOF_DOMAIN = "apassy-push-v1";
/** 180 days. */
export const HANDLE_LIFETIME_SECS = 15_552_000;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
/** Header, nonce, and tag. */
export const MIN_HANDLE_BYTES = 2 + NONCE_BYTES + TAG_BYTES;
export const MAX_HANDLE_BYTES = 1024;
/** The longest b64u text of a handle. */
export const MAX_HANDLE_CHARS = Math.ceil((MAX_HANDLE_BYTES * 4) / 3);
export const SECRET_BYTES = 32;
export const SECRET_CHARS = 43;
export const PROOF_CHARS = 43;
/** A sealed summary (section 12): b64u of a 12-byte nonce and 512 + 16 bytes of ciphertext. */
export const SUMMARY_CHARS = 720;
export const SUMMARY_BYTES = 540;
/** The clock window of `at` (section 7, step 2). */
export const CLOCK_WINDOW_SECS = 300;
/** The longest question: `expires_at − at` (relay-questions-v1 section 10.2). */
export const MAX_QUESTION_SECS = 600;
/** The largest request body. */
export const MAX_BODY_BYTES = 4096;

export type Kind = "iphone" | "watch";
export type Environment = "development" | "production";

const TOKEN = /^[0-9a-f]{32,200}$/;
const COLLAPSE_ID = /^[A-Za-z0-9._-]{1,64}$/;
const BUNDLE_ID = /^[A-Za-z0-9.-]{1,155}$/;
const B64U = /^[A-Za-z0-9_-]*$/;

export function isToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN.test(value);
}

export function isEnvironment(value: unknown): value is Environment {
  return value === "development" || value === "production";
}

export function isKind(value: unknown): value is Kind {
  return value === "iphone" || value === "watch";
}

export function isCollapseId(value: unknown): value is string {
  return typeof value === "string" && COLLAPSE_ID.test(value);
}

export function isBundleId(value: unknown): value is string {
  return typeof value === "string" && BUNDLE_ID.test(value);
}

/** A Unix time: a non-negative safe integer. */
export function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

// ---- base64url (relay-sync-v1 section 2). ----

export function encodeB64u(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The bytes of canonical b64u without padding, else undefined. */
export function decodeB64u(text: string): Uint8Array | undefined {
  if (!B64U.test(text) || text.length % 4 === 1) return undefined;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return undefined;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  // Canonical: the last character has no padding bits set.
  if (encodeB64u(bytes) !== text) return undefined;
  return bytes;
}

/** The bytes of canonical b64u text of exactly `chars` characters and `bytes` bytes. */
export function decodeExact(value: unknown, chars: number, bytes: number): Uint8Array | undefined {
  if (typeof value !== "string" || value.length !== chars) return undefined;
  const decoded = decodeB64u(value);
  return decoded && decoded.length === bytes ? decoded : undefined;
}

// ---- Strict JSON (section 3). ----

/** A JSON object of strings and integers, with no field twice. */
export type Flat = Map<string, string | number>;

const WHITE = new Set([" ", "\t", "\n", "\r"]);
const INTEGER = /0|[1-9][0-9]*/y;

/**
 * A flat JSON object: each value a string or a non-negative integer (no fraction, no
 * exponent: no field of the contract takes one). A repeated field, a nested value,
 * `true`, `false`, `null`, or text after the object: undefined.
 */
export function parseFlat(text: string): Flat | undefined {
  let i = 0;
  const skip = () => {
    while (i < text.length && WHITE.has(text[i]!)) i++;
  };
  const string = (): string | undefined => {
    if (text[i] !== '"') return undefined;
    const start = i;
    i++;
    for (;;) {
      if (i >= text.length) return undefined;
      const c = text.charCodeAt(i);
      if (c === 0x22) break;
      if (c < 0x20) return undefined;
      i += c === 0x5c ? 2 : 1;
    }
    i++;
    try {
      const value: unknown = JSON.parse(text.slice(start, i));
      return typeof value === "string" ? value : undefined;
    } catch {
      return undefined;
    }
  };
  const out: Flat = new Map();
  skip();
  if (text[i] !== "{") return undefined;
  i++;
  skip();
  if (text[i] === "}") {
    i++;
  } else {
    for (;;) {
      skip();
      const key = string();
      if (key === undefined || out.has(key)) return undefined;
      skip();
      if (text[i] !== ":") return undefined;
      i++;
      skip();
      let value: string | number | undefined;
      if (text[i] === '"') {
        value = string();
      } else {
        INTEGER.lastIndex = i;
        const match = INTEGER.exec(text);
        if (match) {
          i += match[0].length;
          value = Number(match[0]);
        }
      }
      if (value === undefined) return undefined;
      out.set(key, value);
      skip();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        break;
      }
      return undefined;
    }
  }
  skip();
  return i === text.length ? out : undefined;
}

/** Whether `flat` has exactly the fields `names`. */
export function hasExactly(flat: Flat, names: readonly string[]): boolean {
  return flat.size === names.length && names.every((name) => flat.has(name));
}

// ---- The handle (section 5). ----

/** What a handle holds. */
export interface HandlePayload {
  kind: Kind;
  token: string;
  environment: Environment;
  bundle_id: string;
  /** b64u of 32 bytes. */
  secret: string;
  issued_at: number;
  expires_at: number;
}

const PAYLOAD_FIELDS = ["v", "kind", "token", "environment", "bundle_id", "secret", "issued_at", "expires_at"];

/** The plaintext of a handle: JSON with no white space, the fields in the contract's order. */
export function handlePlaintext(payload: HandlePayload): string {
  return JSON.stringify({
    v: 1,
    kind: payload.kind,
    token: payload.token,
    environment: payload.environment,
    bundle_id: payload.bundle_id,
    secret: payload.secret,
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
  });
}

/** The payload of a plaintext in exactly the form of handlePlaintext, else undefined. */
export function parsePlaintext(text: string): HandlePayload | undefined {
  const flat = parseFlat(text);
  if (!flat || !hasExactly(flat, PAYLOAD_FIELDS) || flat.get("v") !== 1) return undefined;
  const kind = flat.get("kind");
  const token = flat.get("token");
  const environment = flat.get("environment");
  const bundleId = flat.get("bundle_id");
  const secret = flat.get("secret");
  const issuedAt = flat.get("issued_at");
  const expiresAt = flat.get("expires_at");
  if (
    !isKind(kind) ||
    !isToken(token) ||
    !isEnvironment(environment) ||
    !isBundleId(bundleId) ||
    !decodeExact(secret, SECRET_CHARS, SECRET_BYTES) ||
    !isTime(issuedAt) ||
    !isTime(expiresAt) ||
    expiresAt !== issuedAt + HANDLE_LIFETIME_SECS
  ) {
    return undefined;
  }
  const payload: HandlePayload = {
    kind,
    token,
    environment,
    bundle_id: bundleId,
    secret: secret as string,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  // The order of the fields and no white space.
  return handlePlaintext(payload) === text ? payload : undefined;
}

/** A gateway key with its id (1 to 255). */
export interface GatewayKey {
  id: number;
  key: CryptoKey;
}

/** The key of `GATEWAY_KEY` (b64u of 32 bytes) and its id (a decimal 1 to 255), else undefined. */
export async function importGatewayKey(
  text: string | undefined,
  idText: string | undefined,
): Promise<GatewayKey | undefined> {
  if (text === undefined || idText === undefined) return undefined;
  const id = idText.trim();
  if (!/^[1-9][0-9]{0,2}$/.test(id) || Number(id) > 255) return undefined;
  const raw = decodeExact(text.trim(), 43, 32);
  if (!raw) return undefined;
  try {
    const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return { id: Number(id), key };
  } catch {
    return undefined;
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const encoder = new TextEncoder();

function additionalData(header: Uint8Array): Uint8Array {
  return concat(encoder.encode(HANDLE_DOMAIN), new Uint8Array([0]), header);
}

/** Seal `payload` under `key` with the 12-byte `nonce`: the handle text. */
export async function sealHandle(key: GatewayKey, payload: HandlePayload, nonce: Uint8Array): Promise<string> {
  if (nonce.length !== NONCE_BYTES) throw new Error("A handle nonce is 12 bytes.");
  const header = new Uint8Array([HANDLE_FORMAT, key.id]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: additionalData(header), tagLength: 128 },
      key.key,
      encoder.encode(handlePlaintext(payload)),
    ),
  );
  return encodeB64u(concat(header, nonce, sealed));
}

export type Opened =
  | { ok: true; payload: HandlePayload }
  | { ok: false; code: "handle_invalid" | "handle_expired" };

/**
 * Open a handle with the key of its header's id among `keys`. `handle_invalid` for an
 * unknown key id, another format, a wrong length, a failed open, or a plaintext out of
 * form; `handle_expired` when `expires_at` is before `now`.
 */
export async function openHandle(text: string, keys: readonly GatewayKey[], now: number): Promise<Opened> {
  const invalid: Opened = { ok: false, code: "handle_invalid" };
  if (text.length > MAX_HANDLE_CHARS) return invalid;
  const bytes = decodeB64u(text);
  if (!bytes || bytes.length < MIN_HANDLE_BYTES || bytes.length > MAX_HANDLE_BYTES) return invalid;
  if (bytes[0] !== HANDLE_FORMAT) return invalid;
  const key = keys.find((candidate) => candidate.id === bytes[1]);
  if (!key) return invalid;
  const header = bytes.subarray(0, 2);
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(2, 2 + NONCE_BYTES), additionalData: additionalData(header), tagLength: 128 },
        key.key,
        bytes.subarray(2 + NONCE_BYTES),
      ),
    );
  } catch {
    return invalid;
  }
  let textPlain: string;
  try {
    textPlain = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(plain);
  } catch {
    return invalid;
  }
  const payload = parsePlaintext(textPlain);
  if (!payload) return invalid;
  if (payload.expires_at < now) return { ok: false, code: "handle_expired" };
  return { ok: true, payload };
}

// ---- The proof (section 7). ----

/** `"apassy-push-v1" 0 handle 0 at 0 expires_at 0 collapse_id [0 summary]`. */
export function proofMessage(
  handle: string,
  at: number,
  expiresAt: number,
  collapseId: string,
  summary?: string,
): string {
  const parts = [PROOF_DOMAIN, handle, String(at), String(expiresAt), collapseId];
  if (summary !== undefined) parts.push(summary);
  return parts.join("\0");
}

async function hmacKey(secret: Uint8Array, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

/** The proof: b64u of HMAC-SHA256 under the 32-byte `secret`. */
export async function makeProof(secret: Uint8Array, message: string): Promise<string> {
  const mac = await crypto.subtle.sign("HMAC", await hmacKey(secret, "sign"), encoder.encode(message));
  return encodeB64u(new Uint8Array(mac));
}

/** Whether `proof` (canonical b64u of 32 bytes) is the proof of `message`, in constant time. */
export async function proofMatches(secret: Uint8Array, message: string, proof: string): Promise<boolean> {
  const given = decodeExact(proof, PROOF_CHARS, 32);
  if (!given) return false;
  // WebCrypto's HMAC verify compares in constant time.
  return crypto.subtle.verify("HMAC", await hmacKey(secret, "verify"), given, encoder.encode(message));
}

/** Lowercase hex of SHA-256 of `text`: the key of a rate limit (section 13). */
export async function limitKey(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  let hex = "";
  for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
  return hex;
}
