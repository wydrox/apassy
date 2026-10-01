// The edge Worker of apassy-relay: it serves static files, limits creation
// requests, and forwards relay requests with the required edge secret.
// Erasable TypeScript only (no enums, namespaces, or parameter properties), so
// Node can run it with type stripping in the tests.

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

export interface Env {
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
  /** Static files served without the relay or its edge secret. */
  ASSETS?: AssetService;
}

const EDGE_HEADER = "x-apassy-edge";

// The VPC service config picks the target and the port. The host of the URL only
// fills the Host header.
const VPC_ORIGIN = "http://relay";

function text(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
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

// The unauthenticated POST endpoints and their per-IP limiter. Creation (a team, a
// join, a device link) is rare; sign-in is frequent (a waiting CLI asks every 5 s).
function limiterFor(path: string, env: Env): CreateLimiter | undefined {
  switch (path) {
    case "/v1/join":
    case "/v1/teams":
    case "/v1/devices/link":
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
    if (rawPath.startsWith("/dl/") && unsafeDownloadPath(rawPath)) {
      return staticResponse(text(404, "not found"), false);
    }
    const url = new URL(request.url);
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
      const assetRequest = new Request(url, { method: request.method, headers });
      return staticResponse(await env.ASSETS.fetch(assetRequest), noStore);
    }

    const limiter = request.method === "POST" ? limiterFor(url.pathname, env) : undefined;
    if (limiter) {
      // Fail open if the binding fails: the relay itself checks codes, keys, and
      // signatures; this limit is a guard against floods, not an authorization check.
      try {
        const { success } = await limiter.limit({ key: request.headers.get("cf-connecting-ip") ?? "unknown" });
        if (!success) {
          return new Response('{"ok":false,"error":{"code":"rate_limited","message":"Too many requests. Try again in a minute."}}', {
            status: 429,
            headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": "60" },
          });
        }
      } catch {
        // Continue to the relay when the flood guard is unavailable.
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

    const hasBody = request.method !== "GET" && request.method !== "HEAD";
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
