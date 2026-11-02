// A spike Worker: can Cloudflare's network reach APNs over HTTP/2? It posts a request
// without a provider token to the sandbox host. A reachable APNs answers 403 with
// MissingProviderToken. No key and no device token are involved.

export default {
  async fetch(): Promise<Response> {
    try {
      const response = await fetch("https://api.sandbox.push.apple.com/3/device/00", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await response.text();
      const ok = response.status === 403 && body.includes("MissingProviderToken");
      return Response.json({ status: response.status, body, ok });
    } catch (error) {
      return Response.json({ error: String(error) }, { status: 502 });
    }
  },
};
