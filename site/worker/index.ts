// The Worker of apassy.wyderka.cc. Static files in dist/ are served before it
// runs (wrangler.jsonc). It adds the latest signed build from the R2 bucket:
//
//   /download                      302 to /download/Apassy-<version>.dmg of latest.json
//   /download/Apassy-<version>.dmg the disk image, from the key of the same name
//   /download/Apassy.dmg           the same image, for apps before 0.5.0
//   /latest.json                   version, commit, date, size, and SHA-256 of the image
//
// Any other path gets the 404 page of the site.

const FILES: Record<string, string> = {
  "/download/Apassy.dmg": "Apassy.dmg",
  "/latest.json": "latest.json",
};

// MAJOR.MINOR.PATCH with an optional pre-release, as scripts/build-dmg.sh allows.
const VERSION = String.raw`\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`;
const VERSIONED = new RegExp(`^/download/(Apassy-${VERSION}\\.dmg)$`);
const RELEASE_VERSION = new RegExp(`^${VERSION}$`);

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/download" || url.pathname === "/download/") {
      return redirect(new URL(await currentDownload(env), url).toString());
    }
    const key = FILES[url.pathname] ?? url.pathname.match(VERSIONED)?.[1];
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

// The versioned address of the current build, from the version in latest.json.
// Without a readable latest.json or its versioned image (a release before 0.5.0
// uploaded only Apassy.dmg), the address that every release has.
async function currentDownload(env: Env): Promise<string> {
  try {
    const object = await env.DOWNLOADS.get("latest.json");
    if (object) {
      const version: unknown = ((await object.json()) as { version?: unknown }).version;
      if (typeof version === "string" && RELEASE_VERSION.test(version)) {
        const name = `Apassy-${version}.dmg`;
        if (await env.DOWNLOADS.head(name)) return `/download/${name}`;
      }
    }
  } catch {
    // Fall through to the old address.
  }
  return "/download/Apassy.dmg";
}

// The target changes with each release, so no cache keeps the redirect.
function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { location, "cache-control": "no-store" } });
}

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
