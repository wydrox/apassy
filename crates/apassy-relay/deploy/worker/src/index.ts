// The edge Worker of apassy-relay: it serves static files, limits creation
// requests (a codeless Connect team the most, by two keys: the client's /64 or IPv4 address
// and a coarser /48 or /24 prefix, which also travels to the relay in a header; nothing is
// stored) and snapshot pushes, bounds the declared length of every body, and
// forwards relay requests with the required edge secret. `/internal/` routes (the APNs
// sender, apns.ts) are handled here and never forwarded.
// Erasable TypeScript only (no enums, namespaces, or parameter properties), so
// Node can run it with type stripping in the tests.
// workerd accepts only handlers as exports of this main module, so values such as
// the length limits live in limits.ts. Type exports are fine: they are erased.

import { handleInternal, type PushEnv } from "./apns.ts";
import { MAX_JSON_LENGTH, MAX_PROXY_LENGTH, MAX_SNAPSHOT_LENGTH } from "./limits.ts";

/** A Workers VPC service binding: a tunnel from the relay's host, no public origin. */
export interface RelayService {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

export interface CreateLimiter {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}

export interface AssetService {
  fetch(request: Request): Promise<Response>;
}

export interface Env extends PushEnv {
  /** The origin of the relay, for example a quick tunnel URL. A var. */
  RELAY_ORIGIN?: string;
  /** The edge secret. A Worker secret. */
  EDGE_SECRET?: string;
  /** The relay through Workers VPC. When it is bound, RELAY_ORIGIN is not used. */
  RELAY?: RelayService;
  /** A per-IP guard for the unauthenticated creation endpoints. */
  CREATE_LIMITER?: CreateLimiter;
  /** A looser per-IP guard for device sign-in, which a waiting CLI calls every 5 s. */
  AUTH_LIMITER?: CreateLimiter;
  /** A per-IP guard for vault snapshot pushes (`PUT /v1/sync/snapshot`). */
  SYNC_LIMITER?: CreateLimiter;
  /** The strictest per-IP guard: codeless Connect teams (`POST /v1/connect`, SPEC 26). */
  CONNECT_LIMITER?: CreateLimiter;
  /** The coarser key of `POST /v1/connect`: an IPv6 /48 or an IPv4 /24. */
  CONNECT_PREFIX_LIMITER?: CreateLimiter;
  /** Static files served without the relay or its edge secret. */
  ASSETS?: AssetService;
}

const EDGE_HEADER = "x-apassy-edge";
// The coarse client prefix of `POST /v1/connect` for the relay. The relay trusts it only
// together with the edge secret; the Worker always removes the client's copy.
const CLIENT_PREFIX_HEADER = "x-apassy-client-prefix";

// The VPC service config picks the target and the port. The host of the URL only
// fills the Host header.
const VPC_ORIGIN = "http://relay";

/** The vault snapshot push, the one relay route with a body larger than the proxy's. */
const SNAPSHOT_PATH = "/v1/sync/snapshot";
/** The agent proxy prefix (SPEC 12). */
const PROXY_PREFIX = "/p/";

function text(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

/** An error in the relay's JSON envelope. */
function jsonError(status: number, code: string, message: string, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ ok: false, error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });
}

// tiny_http reads and drops the rest of a declared body after an early answer, on any
// path (an unknown path, a wrong method, a bad token, SPEC 24.10). So the edge bounds
// the declared `Content-Length` of every request with a body before the relay sees it:
// the snapshot push up to MAX_SNAPSHOT_LENGTH, the agent proxy up to MAX_PROXY_LENGTH,
// everything else up to MAX_JSON_LENGTH. A push must declare its length. Elsewhere a
// request without one has no body or a chunked one, which tiny_http does not drain.
function lengthError(request: Request, path: string): Response | undefined {
  const push = request.method === "PUT" && path === SNAPSHOT_PATH;
  if (push && request.headers.has("transfer-encoding")) {
    return jsonError(400, "invalid_request", "Send the snapshot with Content-Length, not Transfer-Encoding.");
  }
  const declared = request.headers.get("content-length");
  if (declared === null && !push) return undefined;
  const length = declared?.trim() ?? "";
  if (!/^[0-9]{1,20}$/.test(length)) {
    return jsonError(400, "invalid_request", push ? "Content-Length is required." : "Content-Length is not a number.");
  }
  if (push) {
    if (Number(length) > MAX_SNAPSHOT_LENGTH) {
      return jsonError(413, "payload_too_large", "The snapshot is larger than 64 MiB.");
    }
  } else if (path.startsWith(PROXY_PREFIX)) {
    if (Number(length) > MAX_PROXY_LENGTH) {
      return jsonError(413, "payload_too_large", "The body is larger than 8 MiB.");
    }
  } else if (Number(length) > MAX_JSON_LENGTH) {
    return jsonError(413, "payload_too_large", "The body is larger than 64 KiB.");
  }
  return undefined;
}

// The eight groups of an IPv6 address (lowercase, `::` expanded), or undefined when the
// text is not a plain IPv6 address (an IPv4 form, a double `::`, a bad group, a wrong count).
function ipv6Groups(address: string): string[] | undefined {
  if (!address.includes(":") || address.includes(".")) return undefined;
  const [head, tail, extra] = address.toLowerCase().split("::");
  if (extra !== undefined) return undefined;
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? missing !== 0 : missing < 1) return undefined;
  const groups = [...left, ...Array<string>(missing).fill("0"), ...right];
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/.test(group))) return undefined;
  return groups;
}

function trimGroup(group: string): string {
  return group.replace(/^0+(?=.)/, "");
}

// The limiter key of `POST /v1/connect`: an IPv4 address as it is, an IPv6 address as
// its /64, because one client usually holds a whole /64. There is a second, coarser key,
// connectPrefix, and the relay gets it in a header. Nothing is stored here: the keys go
// to the rate limiter bindings and to the relay only, as every other limiter key does.
function connectKey(address: string): string {
  const groups = ipv6Groups(address);
  if (!groups) return address;
  return groups.slice(0, 4).map(trimGroup).join(":") + "::/64";
}

// The coarse prefix of a client: an IPv4 /24 or an IPv6 /48. Anything else stays as it is.
function connectPrefix(address: string): string {
  if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(address)) {
    const octets = address.split(".").map(Number);
    if (octets.every((octet) => octet <= 255)) return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    return address;
  }
  const groups = ipv6Groups(address);
  if (!groups) return address;
  return groups.slice(0, 3).map(trimGroup).join(":") + "::/48";
}

function unsafeDownloadPath(path: string): boolean {
  if (/\.\.|\/\/|%2f|%5c|\\/i.test(path)) return true;
  try {
    // Encoded dots can also disappear when a URL is normalized.
    return /\.\.|\/\/|\\/.test(decodeURIComponent(path));
  } catch {
    return true;
  }
}

function staticResponse(response: Response, noStore: boolean): Response {
  const headers = new Headers(response.headers);
  headers.delete(EDGE_HEADER);
  headers.set("x-content-type-options", "nosniff");
  if (noStore) headers.set("cache-control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** The codeless team route (SPEC 26): anyone can call it, so its limiter is the strictest. */
const CONNECT_PATH = "/v1/connect";

// The per-IP limiter of a route. Creation (a team, a join, a device link) is rare;
// sign-in is frequent (a waiting CLI asks every 5 s); a snapshot push holds a relay
// thread for its whole body. A Connect team needs no code at all.
function limiterFor(method: string, path: string, env: Env): CreateLimiter | undefined {
  if (method === "PUT" && path === SNAPSHOT_PATH) return env.SYNC_LIMITER;
  if (method !== "POST") return undefined;
  switch (path) {
    case CONNECT_PATH:
      return env.CONNECT_LIMITER;
    case "/v1/join":
    case "/v1/teams":
    case "/v1/devices/link":
    case "/v1/devices/link/cancel":
      return env.CREATE_LIMITER;
    case "/v1/auth/challenge":
    case "/v1/auth/token":
      return env.AUTH_LIMITER;
    default:
      return undefined;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Check the raw path before URL parsing removes dot segments or backslashes.
    const rawPath = request.url.replace(/^[^:]+:\/\/[^/?#]+/, "").split(/[?#]/, 1)[0]!;
    const url = new URL(request.url);
    // The parsed path is checked too: `/./internal/push` parses to `/internal/push`.
    for (const path of [rawPath, url.pathname]) {
      if (path === "/internal" || path.startsWith("/internal/")) return handleInternal(request, env);
    }
    if (rawPath.startsWith("/dl/") && unsafeDownloadPath(rawPath)) {
      return staticResponse(text(404, "not found"), false);
    }
    const isDownload = url.pathname.startsWith("/dl/");
    const isStatic = url.pathname === "/install.sh" || url.pathname === "/guide" || isDownload;
    if (isStatic) {
      const noStore = !isDownload;
      if (request.method !== "GET" && request.method !== "HEAD") {
        return staticResponse(text(405, "method not allowed"), noStore);
      }
      if (!env.ASSETS) return staticResponse(text(404, "not found"), noStore);
      if (url.pathname === "/guide") url.pathname = "/guide.html";
      const headers = new Headers(request.headers);
      headers.delete(EDGE_HEADER);
      headers.delete(CLIENT_PREFIX_HEADER);
      const assetRequest = new Request(url, { method: request.method, headers });
      return staticResponse(await env.ASSETS.fetch(assetRequest), noStore);
    }

    const hasBody = request.method !== "GET" && request.method !== "HEAD";
    if (hasBody) {
      const refused = lengthError(request, url.pathname);
      if (refused) return refused;
    }

    // Connect has two guards, each on its own key: the client's /64 (or IPv4 address) first,
    // then its coarser /48 (or /24) prefix, asked only when the first one lets the call pass.
    // Every other route has one guard, keyed by the full address.
    const isConnect = request.method === "POST" && url.pathname === CONNECT_PATH;
    const limiter = limiterFor(request.method, url.pathname, env);
    if (limiter || isConnect) {
      // Fail open if a binding is missing or fails: the relay itself checks codes, keys, and
      // signatures; this limit is a guard against floods, not an authorization check.
      // For Connect the relay also caps the teams of a day for everyone.
      const address = request.headers.get("cf-connecting-ip") ?? "unknown";
      const guards: [CreateLimiter | undefined, string][] = isConnect
        ? [[env.CONNECT_LIMITER, connectKey(address)], [env.CONNECT_PREFIX_LIMITER, connectPrefix(address)]]
        : [[limiter, address]];
      for (const [guard, key] of guards) {
        if (!guard) continue;
        try {
          const { success } = await guard.limit({ key });
          if (!success) {
            return jsonError(429, "rate_limited", "Too many requests. Try again in a minute.", { "retry-after": "60" });
          }
        } catch {
          // Continue to the relay when the flood guard is unavailable.
        }
      }
    }

    if (!env.EDGE_SECRET || (!env.RELAY && !env.RELAY_ORIGIN)) {
      return text(503, "relay not configured");
    }
    let origin = VPC_ORIGIN;
    if (!env.RELAY) {
      try {
        origin = new URL(env.RELAY_ORIGIN!).origin;
      } catch {
        return text(503, "relay not configured");
      }
    }
    // Built by string. `new URL(path, origin)` would let a path such as
    // `//evil.example/x` change the host and send the edge secret there.
    const target = origin + url.pathname + url.search;

    const headers = new Headers(request.headers);
    headers.delete(EDGE_HEADER);
    headers.set(EDGE_HEADER, env.EDGE_SECRET);
    headers.delete(CLIENT_PREFIX_HEADER);
    if (request.method === "POST" && url.pathname === CONNECT_PATH) {
      headers.set(CLIENT_PREFIX_HEADER, connectPrefix(request.headers.get("cf-connecting-ip") ?? "unknown"));
    }
    if (!hasBody) {
      // No body is forwarded, so no length either: a declared one would make the
      // relay wait for bytes that never come.
      headers.delete("content-length");
      headers.delete("transfer-encoding");
    }

    // `duplex` is needed by Node's fetch for a streamed body. Workers ignore it.
    const init: RequestInit & { duplex?: "half" } = {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      duplex: "half",
    };
    try {
      // The body and the answer stream. Nothing is buffered, and no URL is logged:
      // the path holds session keys.
      return await (env.RELAY ? env.RELAY.fetch(target, init) : fetch(target, init));
    } catch {
      return text(502, "relay unreachable");
    }
  },
};
