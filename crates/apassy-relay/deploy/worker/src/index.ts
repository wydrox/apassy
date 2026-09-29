// The edge Worker of apassy-relay: it forwards every request to the relay
// through the tunnel, and it adds the edge secret that the relay requires.
// Erasable TypeScript only (no enums, namespaces, or parameter properties), so
// Node can run it with type stripping in the tests.

export interface Env {
  /** The origin of the relay, for example a quick tunnel URL. A var. */
  RELAY_ORIGIN?: string;
  /** The edge secret. A Worker secret. */
  EDGE_SECRET?: string;
}

const EDGE_HEADER = "x-apassy-edge";

function text(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.RELAY_ORIGIN || !env.EDGE_SECRET) {
      return text(503, "relay not configured");
    }
    let origin: string;
    try {
      origin = new URL(env.RELAY_ORIGIN).origin;
    } catch {
      return text(503, "relay not configured");
    }
    // Built by string. `new URL(path, origin)` would let a path such as
    // `//evil.example/x` change the host and send the edge secret there.
    const url = new URL(request.url);
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
      return await fetch(target, init);
    } catch {
      return text(502, "relay unreachable");
    }
  },
};
