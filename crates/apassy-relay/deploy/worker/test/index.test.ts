// Run with: node --test deploy/worker/test/   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import worker, { type RelayService } from "../src/index.ts";

const SECRET = "edge-secret-synthetic-0123456789abcdef0123";
const PUBLIC = "https://apassy-relay.wyderka.cc";

interface Seen {
  method: string;
  url: string;
  rawHeaders: string[];
  body: Buffer;
}

let server: http.Server;
let origin: string;
let seen: Seen[] = [];
let vpcTargets: string[] = [];

/** Every value of a header, as the relay would see them on the wire. */
function values(request: Seen, name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i]!.toLowerCase() === name) out.push(request.rawHeaders[i + 1]!);
  }
  return out;
}

before(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({
        method: req.method ?? "",
        url: req.url ?? "",
        rawHeaders: req.rawHeaders,
        body: Buffer.concat(chunks),
      });
      if (req.url === "/redirect") {
        res.writeHead(302, { location: "https://elsewhere.example/landing" });
        res.end();
      } else if (req.url === "/big") {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        const block = Buffer.alloc(64 * 1024, 0x61);
        for (let i = 0; i < 48; i++) res.write(block);
        res.end();
      } else {
        res.writeHead(201, { "content-type": "text/plain", "x-from-relay": "yes" });
        res.end("echo:" + Buffer.concat(chunks).toString());
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  server.closeAllConnections();
});

/** A fake Workers VPC binding. Like the real one, it ignores the host of the URL. */
function vpc(): RelayService {
  return {
    fetch(input, init) {
      vpcTargets.push(input);
      const url = new URL(input);
      return fetch(origin + url.pathname + url.search, init);
    },
  };
}

function call(path: string, init: RequestInit & { duplex?: "half" } = {}, env = {}) {
  seen = [];
  vpcTargets = [];
  const request = new Request(PUBLIC + path, { duplex: "half", ...init });
  return worker.fetch(request, { RELAY_ORIGIN: origin, EDGE_SECRET: SECRET, ...env });
}

describe("edge header", () => {
  it("is set to the secret", async () => {
    const response = await call("/v1/me");
    assert.equal(response.status, 201);
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("replaces a header sent by the client, in any case", async () => {
    await call("/v1/me", {
      headers: [
        ["X-Apassy-Edge", "attacker-one"],
        ["x-apassy-EDGE", "attacker-two"],
      ],
    });
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
    assert.ok(!seen[0]!.rawHeaders.join(" ").includes("attacker"));
  });

  it("does not put the secret in the answer", async () => {
    const response = await call("/v1/me");
    const body = await response.text();
    assert.ok(!body.includes(SECRET));
    assert.ok(![...response.headers.values()].some((v) => v.includes(SECRET)));
  });
});

describe("target", () => {
  it("keeps //evil.example/x on the relay origin", async () => {
    const response = await call("//evil.example/x?a=1");
    assert.equal(response.status, 201);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.url, "//evil.example/x?a=1");
  });

  it("keeps a path with an at sign and backslashes on the origin", async () => {
    await call("/@evil.example/x");
    assert.equal(seen[0]!.url, "/@evil.example/x");
    await call("/p/apassy_ses_k/api.example.com/v1/x%2F..%2Fy?q=a%20b&r=2");
    assert.equal(seen[0]!.url, "/p/apassy_ses_k/api.example.com/v1/x%2F..%2Fy?q=a%20b&r=2");
  });

  it("uses only the origin of RELAY_ORIGIN", async () => {
    await call("/v1/me", {}, { RELAY_ORIGIN: origin + "/some/path/?x=1" });
    assert.equal(seen[0]!.url, "/v1/me");
  });
});

describe("pass through", () => {
  it("passes method, query, headers, and body", async () => {
    const response = await call("/v1/runs?wait=25&x=%20", {
      method: "POST",
      headers: { authorization: "Bearer synthetic-token", "content-type": "application/json" },
      body: '{"items":[1]}',
    });
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("x-from-relay"), "yes");
    assert.equal(await response.text(), 'echo:{"items":[1]}');
    const request = seen[0]!;
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/v1/runs?wait=25&x=%20");
    assert.deepEqual(values(request, "authorization"), ["Bearer synthetic-token"]);
    assert.equal(request.body.toString(), '{"items":[1]}');
  });

  it("passes PUT and DELETE", async () => {
    await call("/v1/collections/2/policy", { method: "PUT", body: "{}" });
    assert.equal(seen[0]!.method, "PUT");
    assert.equal(seen[0]!.body.toString(), "{}");
    await call("/v1/members/3", { method: "DELETE" });
    assert.equal(seen[0]!.method, "DELETE");
    assert.equal(seen[0]!.body.length, 0);
  });

  it("sends no body for GET and HEAD", async () => {
    await call("/healthz");
    assert.equal(seen[0]!.method, "GET");
    assert.equal(seen[0]!.body.length, 0);
    const head = await call("/healthz", { method: "HEAD" });
    assert.equal(head.status, 201);
    assert.equal(seen[0]!.method, "HEAD");
  });

  it("does not follow a redirect", async () => {
    const response = await call("/redirect");
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://elsewhere.example/landing");
    assert.equal(seen.length, 1);
  });

  it("streams a large answer", async () => {
    const response = await call("/big");
    const bytes = (await response.arrayBuffer()).byteLength;
    assert.equal(bytes, 48 * 64 * 1024);
  });
});

describe("VPC binding", () => {
  it("is used instead of RELAY_ORIGIN", async () => {
    const response = await call("/v1/me?x=1", {}, { RELAY: vpc(), RELAY_ORIGIN: "http://127.0.0.1:1" });
    assert.equal(response.status, 201);
    assert.deepEqual(vpcTargets, ["http://relay/v1/me?x=1"]);
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("works without RELAY_ORIGIN and passes the body", async () => {
    const response = await call("/v1/runs", { method: "POST", body: "{}" }, { RELAY: vpc(), RELAY_ORIGIN: undefined });
    assert.equal(await response.text(), "echo:{}");
    assert.equal(seen[0]!.method, "POST");
  });

  it("keeps //evil.example/x on the relay host", async () => {
    await call("//evil.example/x?a=1", {}, { RELAY: vpc() });
    assert.equal(new URL(vpcTargets[0]!).host, "relay");
    assert.equal(seen[0]!.url, "//evil.example/x?a=1");
  });

  it("answers 502 when the binding fails, without the URL", async () => {
    const down: RelayService = { fetch: () => Promise.reject(new Error("tunnel down")) };
    const response = await call("/p/apassy_ses_k/api.example.com/x", {}, { RELAY: down });
    assert.equal(response.status, 502);
    assert.equal(await response.text(), "relay unreachable");
  });
});

describe("configuration and failures", () => {
  it("answers 503 when RELAY_ORIGIN or EDGE_SECRET is missing or bad", async () => {
    for (const env of [
      { RELAY_ORIGIN: undefined },
      { RELAY_ORIGIN: "" },
      { EDGE_SECRET: undefined },
      { EDGE_SECRET: "" },
      { RELAY_ORIGIN: "not a url" },
    ]) {
      const response = await call("/v1/me", {}, env);
      assert.equal(response.status, 503);
      assert.equal(await response.text(), "relay not configured");
    }
    assert.equal(seen.length, 0);
  });

  it("answers 503 for a VPC binding without EDGE_SECRET", async () => {
    const response = await call("/v1/me", {}, { RELAY: vpc(), EDGE_SECRET: undefined });
    assert.equal(response.status, 503);
    assert.equal(await response.text(), "relay not configured");
    assert.equal(seen.length, 0);
  });

  it("answers 502 when the relay is not reachable, without the URL", async () => {
    const dead = http.createServer();
    await new Promise<void>((resolve) => dead.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(dead.address() as AddressInfo).port}`;
    dead.close();
    const response = await call("/p/apassy_ses_k/api.example.com/x", {}, { RELAY_ORIGIN: url });
    assert.equal(response.status, 502);
    const body = await response.text();
    assert.equal(body, "relay unreachable");
    assert.ok(!body.includes("apassy_ses_"));
  });
});

describe("creation rate limit", () => {
  for (const path of ["/v1/join", "/v1/teams"]) {
    it(`blocks POST ${path} before the relay`, async () => {
      const keys: string[] = [];
      const response = await call(path, {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": "198.51.100.42" },
      }, {
        CREATE_LIMITER: {
          async limit({ key }: { key: string }) {
            keys.push(key);
            return { success: false };
          },
        },
        RELAY: vpc(),
      });
      assert.equal(response.status, 429);
      assert.equal(response.headers.get("content-type"), "application/json");
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.equal(response.headers.get("retry-after"), "60");
      assert.equal(await response.text(), '{"ok":false,"error":{"code":"rate_limited","message":"Too many requests. Try again in a minute."}}');
      assert.deepEqual(keys, ["198.51.100.42"]);
      assert.equal(seen.length, 0);
      assert.equal(vpcTargets.length, 0);
    });

    it(`passes allowed POST ${path} to the relay`, async () => {
      const keys: string[] = [];
      const response = await call(path + "?source=test", {
        method: "POST",
        body: '{"name":"test"}',
      }, {
        CREATE_LIMITER: {
          async limit({ key }: { key: string }) {
            keys.push(key);
            return { success: true };
          },
        },
      });
      assert.deepEqual(keys, ["unknown"]);
      assert.equal(response.status, 201);
      assert.equal(await response.text(), 'echo:{"name":"test"}');
      assert.equal(seen.length, 1);
      assert.equal(seen[0]!.url, path + "?source=test");
      assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
    });

    it(`passes POST ${path} when the limiter is missing or fails`, async () => {
      for (const CREATE_LIMITER of [
        undefined,
        { async limit() { throw new Error("limiter unavailable"); } },
      ]) {
        const response = await call(path, { method: "POST", body: "{}" }, { CREATE_LIMITER });
        assert.equal(response.status, 201);
        assert.equal(await response.text(), "echo:{}");
        assert.equal(seen.length, 1);
      }
    });
  }

  it("does not use the limiter for other methods or paths", async () => {
    let calls = 0;
    const CREATE_LIMITER = {
      async limit() {
        calls++;
        return { success: false };
      },
    };
    for (const [method, path] of [
      ["GET", "/v1/join"],
      ["HEAD", "/v1/teams"],
      ["PUT", "/v1/join"],
      ["DELETE", "/v1/teams"],
      ["OPTIONS", "/v1/join"],
      ["POST", "/v1/join/"],
      ["POST", "/v1/teams/member"],
      ["POST", "/v1/me"],
      ["POST", "/p/session/example.com/v1/join"],
    ]) {
      const response = await call(path!, { method }, { CREATE_LIMITER });
      assert.equal(response.status, 201, `${method} ${path}`);
      assert.equal(seen.length, 1, `${method} ${path}`);
    }
    assert.equal(calls, 0);
  });
});

function assets(response: (request: Request) => Response = () => new Response("asset")) {
  const requests: Request[] = [];
  return {
    requests,
    binding: {
      async fetch(request: Request) {
        requests.push(request);
        return response(request);
      },
    },
  };
}

// Node's Request constructor normalizes dot segments and backslashes. Replace
// only the URL to test the raw path that the Worker can receive from a client.
function rawCall(path: string, env = {}) {
  seen = [];
  vpcTargets = [];
  const request = new Request(PUBLIC + "/dl/file");
  Object.defineProperty(request, "url", { value: PUBLIC + path });
  return worker.fetch(request, { RELAY_ORIGIN: origin, EDGE_SECRET: SECRET, ...env });
}

describe("public assets", () => {
  for (const [path, assetPath] of [
    ["/install.sh", "/install.sh"],
    ["/guide", "/guide.html"],
    ["/dl/apassy.tar.gz", "/dl/apassy.tar.gz"],
  ]) {
    it(`serves GET ${path} without the relay or edge header`, async () => {
      const fixture = assets(() => new Response("asset body", {
        status: 206,
        headers: {
          "content-type": "application/octet-stream",
          "cache-control": "public, max-age=3600",
          "etag": '"test-asset"',
          "content-range": "bytes 0-9/10",
          "x-apassy-edge": SECRET,
        },
      }));
      let limiterCalls = 0;
      const response = await call(path! + "?version=1", {
        headers: { "x-apassy-edge": "client-value", "x-request-test": "kept" },
      }, {
        ASSETS: fixture.binding,
        RELAY: vpc(),
        CREATE_LIMITER: { async limit() { limiterCalls++; return { success: false }; } },
      });
      assert.equal(response.status, 206);
      assert.equal(await response.text(), "asset body");
      assert.equal(response.headers.get("content-type"), "application/octet-stream");
      assert.equal(response.headers.get("etag"), '"test-asset"');
      assert.equal(response.headers.get("content-range"), "bytes 0-9/10");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("cache-control"), path!.startsWith("/dl/") ? "public, max-age=3600" : "no-store");
      assert.equal(response.headers.get("x-apassy-edge"), null);
      assert.ok(![...response.headers.values()].some((value) => value.includes(SECRET)));
      assert.equal(fixture.requests.length, 1);
      const request = fixture.requests[0]!;
      assert.equal(request.method, "GET");
      assert.equal(new URL(request.url).pathname, assetPath);
      assert.equal(new URL(request.url).search, "?version=1");
      assert.equal(request.headers.get("x-apassy-edge"), null);
      assert.equal(request.headers.get("x-request-test"), "kept");
      assert.ok(![...request.headers.values()].some((value) => value.includes(SECRET)));
      assert.equal(limiterCalls, 0);
      assert.equal(seen.length, 0);
      assert.equal(vpcTargets.length, 0);
    });

    it(`serves HEAD ${path} through ASSETS`, async () => {
      const fixture = assets((request) => new Response(request.method === "HEAD" ? null : "asset", {
        headers: { "content-length": "5", "cache-control": "public, max-age=3600" },
      }));
      const response = await call(path!, { method: "HEAD" }, { ASSETS: fixture.binding });
      assert.equal(response.status, 200);
      assert.equal(await response.text(), "");
      assert.equal(response.headers.get("content-length"), "5");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("cache-control"), path!.startsWith("/dl/") ? "public, max-age=3600" : "no-store");
      assert.equal(fixture.requests.length, 1);
      assert.equal(fixture.requests[0]!.method, "HEAD");
      assert.equal(new URL(fixture.requests[0]!.url).pathname, assetPath);
      assert.equal(seen.length, 0);
    });

    it(`serves ${path} without relay configuration`, async () => {
      for (const RELAY_ORIGIN of [undefined, "not a url"]) {
        const fixture = assets();
        const response = await call(path!, {}, {
          ASSETS: fixture.binding,
          EDGE_SECRET: undefined,
          RELAY_ORIGIN,
        });
        assert.equal(response.status, 200);
        assert.equal(await response.text(), "asset");
        assert.equal(fixture.requests.length, 1);
        assert.equal(seen.length, 0);
      }
    });

    it(`answers 404 for ${path} without ASSETS`, async () => {
      const response = await call(path!, {}, { RELAY: vpc() });
      assert.equal(response.status, 404);
      assert.equal(await response.text(), "not found");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(seen.length, 0);
      assert.equal(vpcTargets.length, 0);
    });

    it(`answers 405 for other methods on ${path}`, async () => {
      const fixture = assets();
      for (const method of ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"]) {
        const response = await call(path!, { method }, { ASSETS: fixture.binding, RELAY: vpc() });
        assert.equal(response.status, 405, method);
        assert.equal(response.headers.get("x-content-type-options"), "nosniff", method);
        assert.equal(seen.length, 0, method);
        assert.equal(vpcTargets.length, 0, method);
      }
      assert.equal(fixture.requests.length, 0);
    });
  }

  it("keeps an asset error status, headers, and body", async () => {
    const fixture = assets(() => new Response("missing asset", {
      status: 404,
      headers: { "content-type": "text/plain", "cache-control": "public, max-age=30", "x-asset": "missing" },
    }));
    const response = await call("/dl/missing.zip", {}, { ASSETS: fixture.binding });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "missing asset");
    assert.equal(response.headers.get("content-type"), "text/plain");
    assert.equal(response.headers.get("cache-control"), "public, max-age=30");
    assert.equal(response.headers.get("x-asset"), "missing");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(seen.length, 0);
  });

  it("rejects unsafe raw download paths before ASSETS or the relay", async () => {
    const fixture = assets();
    for (const path of [
      "/dl/../x",
      "/dl/../v1/me",
      "/dl/a..b.zip",
      "/dl//file.zip",
      "/dl/a%2Fb",
      "/dl/a%2fb",
      "/dl/a%5Cb",
      "/dl/a%5cb",
      "/dl/a\\b",
      "/dl/%2e%2e/v1/me",
      "/dl/%2E%2E/file",
    ]) {
      const response = await rawCall(path, { ASSETS: fixture.binding, RELAY: vpc() });
      assert.equal(response.status, 404, path);
      assert.equal(await response.text(), "not found", path);
      assert.equal(response.headers.get("x-content-type-options"), "nosniff", path);
      assert.equal(fixture.requests.length, 0, path);
      assert.equal(seen.length, 0, path);
      assert.equal(vpcTargets.length, 0, path);
    }
  });
});
