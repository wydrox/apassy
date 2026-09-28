// The Worker of apassy.wyderka.cc. Static files in dist/ are served before it
// runs (wrangler.jsonc). It adds the latest signed build from the R2 bucket:
//
//   /download             302 to /download/Apassy.dmg
//   /download/Apassy.dmg  the disk image
//   /latest.json          version, commit, date, size, and SHA-256 of the image
//
// Any other path gets the 404 page of the site.

const FILES: Record<string, string> = {
  "/download/Apassy.dmg": "Apassy.dmg",
  "/latest.json": "latest.json",
};

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/download" || url.pathname === "/download/") {
      return Response.redirect(new URL("/download/Apassy.dmg", url).toString(), 302);
    }
    const key = FILES[url.pathname];
    if (!key) return env.ASSETS.fetch(request);

    if (request.method === "HEAD") {
      const object = await env.DOWNLOADS.head(key);
      return object ? new Response(null, { headers: headersOf(object) }) : noBuild();
    }
    if (request.method !== "GET") {
      return new Response("Method not allowed", { status: 405, headers: { allow: "GET, HEAD" } });
    }
    const object = await env.DOWNLOADS.get(key, { onlyIf: request.headers });
    if (!object) return noBuild();
    // Without a body, a condition of the request did not hold: the client has
    // this version (If-None-Match), or it asked for another one (If-Match).
    if (!hasBody(object)) {
      const cached = request.headers.has("if-none-match") || request.headers.has("if-modified-since");
      return new Response(null, { status: cached ? 304 : 412, headers: headersOf(object) });
    }
    return new Response(object.body, { headers: headersOf(object) });
  },
} satisfies ExportedHandler<Env>;

// The release workflow sets the content type, disposition, and cache control
// of each object. writeHttpMetadata copies them.
function headersOf(object: R2Object): Headers {
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("last-modified", object.uploaded.toUTCString());
  headers.set("content-length", String(object.size));
  return headers;
}

function hasBody(object: R2Object | R2ObjectBody): object is R2ObjectBody {
  return "body" in object;
}

function noBuild(): Response {
  return new Response("No build yet. Try again later.\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
