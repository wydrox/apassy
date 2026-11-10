// Run with: node --test deploy/worker/test/   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import worker, { type RelayService } from "../src/index.ts";
import { MAX_FEED_LENGTH, MAX_JSON_LENGTH, MAX_PROXY_LENGTH, MAX_SNAPSHOT_LENGTH, MAX_STRIPE_WEBHOOK_LENGTH } from "../src/limits.ts";

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

describe("sign-in rate limit", () => {
  for (const path of ["/v1/auth/challenge", "/v1/auth/token"]) {
    it(`uses AUTH_LIMITER, not CREATE_LIMITER, for POST ${path}`, async () => {
      const used: string[] = [];
      const limiter = (name: string, success: boolean) => ({
        async limit({ key }: { key: string }) {
          used.push(`${name}:${key}`);
          return { success };
        },
      });
      const refused = await call(path, { method: "POST", body: "{}", headers: { "cf-connecting-ip": "203.0.113.9" } }, {
        AUTH_LIMITER: limiter("auth", false),
        CREATE_LIMITER: limiter("create", true),
      });
      assert.equal(refused.status, 429);
      assert.equal(seen.length, 0);
      assert.deepEqual(used, ["auth:203.0.113.9"]);
      used.length = 0;
      const passed = await call(path, { method: "POST", body: "{}" }, {
        AUTH_LIMITER: limiter("auth", true),
        CREATE_LIMITER: limiter("create", false),
      });
      assert.equal(passed.status, 201);
      assert.deepEqual(used, ["auth:unknown"]);
    });
  }

  for (const path of ["/v1/devices/link", "/v1/devices/link/cancel"]) {
    it(`uses CREATE_LIMITER, not AUTH_LIMITER, for POST ${path}`, async () => {
      const keys: string[] = [];
      const response = await call(path, { method: "POST", body: "{}", headers: { "cf-connecting-ip": "192.0.2.7" } }, {
        CREATE_LIMITER: { async limit({ key }: { key: string }) { keys.push(`create:${key}`); return { success: false }; } },
        AUTH_LIMITER: { async limit({ key }: { key: string }) { keys.push(`auth:${key}`); return { success: true }; } },
      });
      assert.equal(response.status, 429);
      assert.equal(response.headers.get("retry-after"), "60");
      assert.deepEqual(keys, ["create:192.0.2.7"]);
      assert.equal(seen.length, 0);
    });
  }
});

/** A relay that records the headers it is sent and does not read the body. */
function recordingRelay() {
  const forwarded: { target: string; headers: Headers }[] = [];
  const relay: RelayService = {
    async fetch(input, init) {
      forwarded.push({ target: input, headers: new Headers(init?.headers) });
      return new Response("ok", { status: 201 });
    },
  };
  return { forwarded, relay };
}

describe("body length", () => {
  const refusing = () => {
    const keys: string[] = [];
    const limiter = { async limit({ key }: { key: string }) { keys.push(key); return { success: false }; } };
    return { keys, env: { SYNC_LIMITER: limiter, CREATE_LIMITER: limiter, AUTH_LIMITER: limiter } };
  };
  // Paths near the push that the relay answers early (404, 405, 401): tiny_http then
  // reads the whole declared body, so each one must be bounded too.
  const others: [string, string][] = [
    ["PUT", "/v1/sync/snapshot/"],
    ["POST", "/v1/sync/snapshot"],
    ["PATCH", "/v1/sync/snapshot"],
    ["PUT", "/v1/sync/head"],
    ["POST", "/v1/sync/receipt"],
    ["DELETE", "/v1/sync"],
    ["PUT", "/anything"],
    ["POST", "/v1/runs"],
    ["POST", "/v1/join"],
    ["POST", "/mcp"],
  ];

  it("refuses a large declared length on every other route, before the limiter and the relay", async () => {
    const { forwarded, relay } = recordingRelay();
    const limits = refusing();
    for (const [method, path] of others) {
      for (const declared of ["99999999", String(MAX_SNAPSHOT_LENGTH), String(MAX_JSON_LENGTH + 1)]) {
        const label = `${method} ${path} ${declared}`;
        const response = await call(path, { method, body: "x", headers: { "content-length": declared } }, {
          ...limits.env,
          RELAY: relay,
        });
        assert.equal(response.status, 413, label);
        assert.equal(response.headers.get("content-type"), "application/json", label);
        assert.equal((await envelope(response)).error.code, "payload_too_large", label);
      }
    }
    assert.deepEqual(forwarded, []);
    assert.deepEqual(limits.keys, []);
  });

  it("refuses a malformed length on every other route", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const [method, path] of others) {
      for (const declared of ["", "abc", "3, 3", "-1", "1e3", "123456789012345678901"]) {
        const label = `${method} ${path} ${JSON.stringify(declared)}`;
        const response = await call(path, { method, body: "x", headers: { "content-length": declared } }, {
          RELAY: relay,
        });
        assert.equal(response.status, 400, label);
        assert.equal((await envelope(response)).error.code, "invalid_request", label);
      }
    }
    assert.deepEqual(forwarded, []);
  });

  it("passes a JSON body up to 64 KiB plus the margin", async () => {
    assert.equal(MAX_JSON_LENGTH, 128 * 1024);
    const { forwarded, relay } = recordingRelay();
    for (const [method, path] of others) {
      const response = await call(path, { method, body: "x", headers: { "content-length": String(MAX_JSON_LENGTH) } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 201, `${method} ${path}`);
    }
    assert.equal(forwarded.length, others.length);
    assert.ok(forwarded.every((f) => f.headers.get("content-length") === String(MAX_JSON_LENGTH)));
  });

  it("bounds an agent proxy body at 8 MiB plus the margin", async () => {
    assert.equal(MAX_PROXY_LENGTH, 8 * 1024 * 1024 + 64 * 1024);
    const { forwarded, relay } = recordingRelay();
    const path = "/p/apassy_ses_k/api.example.com/v1/upload";
    for (const declared of [String(MAX_PROXY_LENGTH + 1), String(MAX_SNAPSHOT_LENGTH)]) {
      const response = await call(path, { method: "POST", body: "x", headers: { "content-length": declared } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 413, declared);
      assert.equal((await envelope(response)).error.code, "payload_too_large", declared);
    }
    assert.equal(forwarded.length, 0);
    for (const declared of [String(MAX_PROXY_LENGTH), String(MAX_JSON_LENGTH + 1)]) {
      const response = await call(path, { method: "PUT", body: "x", headers: { "content-length": declared } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 201, declared);
    }
    assert.deepEqual(forwarded.map((f) => f.headers.get("content-length")), [String(MAX_PROXY_LENGTH), String(MAX_JSON_LENGTH + 1)]);
  });

  it("forwards GET and HEAD without a declared length", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const method of ["GET", "HEAD"]) {
      const response = await call("/v1/sync/snapshot/", {
        method,
        headers: { "content-length": "99999999", "transfer-encoding": "chunked" },
      }, { RELAY: relay });
      assert.equal(response.status, 201, method);
    }
    assert.equal(forwarded.length, 2);
    for (const { headers } of forwarded) {
      assert.equal(headers.get("content-length"), null);
      assert.equal(headers.get("transfer-encoding"), null);
      assert.equal(headers.get("x-apassy-edge"), SECRET);
    }
  });
});

/** The JSON error envelope of an answer. */
async function envelope(response: Response) {
  return (await response.json()) as { ok: boolean; error: { code: string; message: string } };
}

describe("snapshot push", () => {
  const counting = (success: boolean) => {
    const keys: string[] = [];
    return { keys, limiter: { async limit({ key }: { key: string }) { keys.push(key); return { success }; } } };
  };

  it("refuses a missing, non-numeric, or chunked length before the limiter and the relay", async () => {
    const sync = counting(true);
    for (const headers of [
      {},
      { "content-length": "" },
      { "content-length": "abc" },
      { "content-length": "12a" },
      { "content-length": "-1" },
      { "content-length": "1.5" },
      { "content-length": "1e3" },
      { "content-length": "0x10" },
      { "content-length": "3, 3" },
      { "content-length": "123456789012345678901" },
      { "content-length": "3", "transfer-encoding": "chunked" },
    ] as Record<string, string>[]) {
      const label = JSON.stringify(headers);
      const response = await call("/v1/sync/snapshot", { method: "PUT", body: "abc", headers }, {
        SYNC_LIMITER: sync.limiter,
        RELAY: vpc(),
      });
      assert.equal(response.status, 400, label);
      assert.equal(response.headers.get("content-type"), "application/json", label);
      assert.equal(response.headers.get("cache-control"), "no-store", label);
      assert.equal((await envelope(response)).error.code, "invalid_request", label);
      assert.equal(seen.length, 0, label);
      assert.equal(vpcTargets.length, 0, label);
    }
    assert.deepEqual(sync.keys, []);
  });

  it("refuses a length above 64 MiB plus the margin, and passes one at the limit", async () => {
    // A relay that does not read the body: the declared length is all that counts here.
    const forwarded: string[] = [];
    const relay: RelayService = {
      async fetch(input, init) {
        forwarded.push(new Headers(init?.headers).get("content-length") ?? "");
        return new Response("ok", { status: 201 });
      },
    };
    assert.equal(MAX_SNAPSHOT_LENGTH, 64 * 1024 * 1024 + 64 * 1024);
    for (const declared of [String(MAX_SNAPSHOT_LENGTH + 1), String(2 ** 40), "18446744073709551615", "99999999999999999999"]) {
      const response = await call("/v1/sync/snapshot", { method: "PUT", body: "x", headers: { "content-length": declared } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 413, declared);
      const body = await envelope(response);
      assert.equal(body.ok, false, declared);
      assert.equal(body.error.code, "payload_too_large", declared);
    }
    assert.deepEqual(forwarded, []);
    for (const declared of [String(MAX_SNAPSHOT_LENGTH), "67108864", "0", "007"]) {
      const response = await call("/v1/sync/snapshot", { method: "PUT", body: "x", headers: { "content-length": declared } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 201, declared);
    }
    assert.deepEqual(forwarded, [String(MAX_SNAPSHOT_LENGTH), "67108864", "0", "007"]);
  });

  it("uses SYNC_LIMITER per client address and passes an allowed push with its body", async () => {
    const refused = counting(false);
    const create = counting(true);
    const response = await call("/v1/sync/snapshot", {
      method: "PUT",
      body: "snapshot",
      headers: { "content-length": "8", "cf-connecting-ip": "198.51.100.8", "if-match": '"0"' },
    }, { SYNC_LIMITER: refused.limiter, CREATE_LIMITER: create.limiter, AUTH_LIMITER: create.limiter, RELAY: vpc() });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get("retry-after"), "60");
    assert.equal((await envelope(response)).error.code, "rate_limited");
    assert.deepEqual(refused.keys, ["198.51.100.8"]);
    assert.deepEqual(create.keys, []);
    assert.equal(seen.length, 0);
    assert.equal(vpcTargets.length, 0);

    const allowed = counting(true);
    const passed = await call("/v1/sync/snapshot", {
      method: "PUT",
      body: "snapshot",
      headers: { "content-length": "8", "if-match": '"0"' },
    }, { SYNC_LIMITER: allowed.limiter, RELAY: vpc() });
    assert.equal(passed.status, 201);
    assert.equal(await passed.text(), "echo:snapshot");
    assert.deepEqual(allowed.keys, ["unknown"]);
    assert.equal(seen[0]!.method, "PUT");
    assert.equal(seen[0]!.url, "/v1/sync/snapshot");
    assert.deepEqual(values(seen[0]!, "content-length"), ["8"]);
    assert.deepEqual(values(seen[0]!, "if-match"), ['"0"']);
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("passes a push when the limiter is missing or fails", async () => {
    for (const SYNC_LIMITER of [undefined, { async limit() { throw new Error("limiter unavailable"); } }]) {
      const response = await call("/v1/sync/snapshot", { method: "PUT", body: "abc", headers: { "content-length": "3" } }, {
        SYNC_LIMITER,
      });
      assert.equal(response.status, 201);
      assert.equal(await response.text(), "echo:abc");
    }
  });

  it("does not limit a snapshot download or other sync routes, nor check a body without a length", async () => {
    const sync = counting(false);
    for (const [method, path] of [
      ["GET", "/v1/sync/snapshot?version=1"],
      ["HEAD", "/v1/sync/snapshot"],
      ["GET", "/v1/sync/head?since=0&wait=25"],
      ["POST", "/v1/sync/receipt"],
      ["DELETE", "/v1/sync"],
      ["PUT", "/v1/sync/head"],
    ]) {
      const response = await call(path!, { method }, { SYNC_LIMITER: sync.limiter });
      assert.equal(response.status, 201, `${method} ${path}`);
      assert.equal(seen.length, 1, `${method} ${path}`);
    }
    assert.deepEqual(sync.keys, []);
  });
});

describe("feed put", () => {
  it("has the 352 KiB cap of the contract", () => {
    assert.equal(MAX_FEED_LENGTH, 360448);
  });

  it("passes a put of exactly the cap, with its length and body", async () => {
    const body = "f".repeat(MAX_FEED_LENGTH);
    const response = await call("/v1/feed", {
      method: "PUT",
      body,
      headers: { "content-length": String(MAX_FEED_LENGTH) },
    }, { RELAY: vpc() });
    assert.equal(response.status, 201);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.method, "PUT");
    assert.equal(seen[0]!.url, "/v1/feed");
    assert.deepEqual(values(seen[0]!, "content-length"), [String(MAX_FEED_LENGTH)]);
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
    assert.equal(seen[0]!.body.length, MAX_FEED_LENGTH);
    assert.equal(seen[0]!.body.toString(), body);
  });

  it("refuses a put above the cap before the relay", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const declared of [String(MAX_FEED_LENGTH + 1), String(MAX_SNAPSHOT_LENGTH), "99999999999999999999"]) {
      const response = await call("/v1/feed", { method: "PUT", body: "x", headers: { "content-length": declared } }, {
        RELAY: relay,
      });
      assert.equal(response.status, 413, declared);
      assert.equal(response.headers.get("content-type"), "application/json", declared);
      const body = await envelope(response);
      assert.equal(body.ok, false, declared);
      assert.equal(body.error.code, "payload_too_large", declared);
      assert.equal(body.error.message, "The feed body is larger than 352 KiB.", declared);
    }
    assert.deepEqual(forwarded, []);
  });

  it("refuses a missing, non-numeric, or chunked length before the relay", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const headers of [
      {},
      { "content-length": "" },
      { "content-length": "abc" },
      { "content-length": "3, 3" },
      { "content-length": "3", "transfer-encoding": "chunked" },
      { "transfer-encoding": "chunked" },
    ] as Record<string, string>[]) {
      const label = JSON.stringify(headers);
      const response = await call("/v1/feed", { method: "PUT", body: "abc", headers }, { RELAY: relay });
      assert.equal(response.status, 400, label);
      assert.equal(response.headers.get("content-type"), "application/json", label);
      assert.equal((await envelope(response)).error.code, "invalid_request", label);
    }
    assert.deepEqual(forwarded, []);
  });

  it("raises the cap for PUT /v1/feed only", async () => {
    const routes: [string, string][] = [
      ["PUT", "/v1/feed/"],
      ["POST", "/v1/feed"],
      ["POST", "/v1/feed/actions"],
      ["POST", "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw/settle"],
      ["PUT", "/v1/questions"],
      ["DELETE", "/v1/feed"],
    ];
    const { forwarded, relay } = recordingRelay();
    for (const [method, path] of routes) {
      const response = await call(path, {
        method,
        body: "x",
        headers: { "content-length": String(MAX_JSON_LENGTH + 1) },
      }, { RELAY: relay });
      assert.equal(response.status, 413, `${method} ${path}`);
      assert.equal((await envelope(response)).error.code, "payload_too_large", `${method} ${path}`);
    }
    assert.equal(forwarded.length, 0);
    for (const [method, path] of routes) {
      const response = await call(path, {
        method,
        body: "x",
        headers: { "content-length": String(MAX_JSON_LENGTH) },
      }, { RELAY: relay });
      assert.equal(response.status, 201, `${method} ${path}`);
    }
    assert.equal(forwarded.length, routes.length);
    assert.ok(forwarded.every((f) => f.headers.get("content-length") === String(MAX_JSON_LENGTH)));
  });

  it("forwards the feed reads with path and query unchanged", async () => {
    for (const path of [
      "/v1/feed?since=0&wait=25",
      "/v1/feed/actions?after=0&wait=25",
      "/v1/feed/actions/sLGys7S1tre4ubq7vL2-vw?wait=25",
    ]) {
      const response = await call(path, {}, { RELAY: vpc() });
      assert.equal(response.status, 201, path);
      assert.equal(seen.length, 1, path);
      assert.equal(seen[0]!.method, "GET", path);
      assert.equal(seen[0]!.url, path, path);
      assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET], path);
      assert.deepEqual(vpcTargets, ["http://relay" + path], path);
    }
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
      ["POST", "/v1/sync/snapshot"],
      ["POST", "/p/session/example.com/v1/join"],
    ]) {
      const response = await call(path!, { method }, { CREATE_LIMITER });
      assert.equal(response.status, 201, `${method} ${path}`);
      assert.equal(seen.length, 1, `${method} ${path}`);
    }
    assert.equal(calls, 0);
  });
});

describe("connect rate limit", () => {
  /** The /64 key of the addresses of the prefix table that are IPv6 hosts; others are keyed as they are. */
  const CONNECT_KEYS: Record<string, string> = {
    "2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
    "2001:0DB8:0001::": "2001:db8:1:0::/64",
    "2001:db8::1": "2001:db8:0:0::/64",
    "::1": "0:0:0:0::/64",
  };

  /**
   * Every limiter of the Worker, recording `<name>:<key>`; CONNECT_LIMITER answers `connect`,
   * CONNECT_PREFIX_LIMITER answers `prefix`.
   */
  function limiters(connect: boolean, prefix = true) {
    const used: string[] = [];
    const limiter = (name: string, success: boolean) => ({
      async limit({ key }: { key: string }) {
        used.push(`${name}:${key}`);
        return { success };
      },
    });
    return {
      used,
      env: {
        CONNECT_LIMITER: limiter("connect", connect),
        CONNECT_PREFIX_LIMITER: limiter("prefix", prefix),
        CREATE_LIMITER: limiter("create", true),
        AUTH_LIMITER: limiter("auth", true),
        SYNC_LIMITER: limiter("sync", true),
      },
    };
  }

  it("uses CONNECT_LIMITER and CONNECT_PREFIX_LIMITER, and no other, for POST /v1/connect", async () => {
    const refused = limiters(false);
    const response = await call("/v1/connect", {
      method: "POST",
      body: "{}",
      headers: { "cf-connecting-ip": "198.51.100.42" },
    }, { ...refused.env, RELAY: vpc() });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get("retry-after"), "60");
    assert.equal(await response.text(), '{"ok":false,"error":{"code":"rate_limited","message":"Too many requests. Try again in a minute."}}');
    assert.deepEqual(refused.used, ["connect:198.51.100.42"]);
    assert.equal(seen.length, 0);
    assert.equal(vpcTargets.length, 0);

    const prefixRefused = limiters(true, false);
    const byPrefix = await call("/v1/connect", {
      method: "POST",
      body: "{}",
      headers: { "cf-connecting-ip": "198.51.100.42" },
    }, { ...prefixRefused.env, RELAY: vpc() });
    assert.equal(byPrefix.status, 429);
    assert.equal(byPrefix.headers.get("retry-after"), "60");
    assert.equal(await byPrefix.text(), '{"ok":false,"error":{"code":"rate_limited","message":"Too many requests. Try again in a minute."}}');
    assert.deepEqual(prefixRefused.used, ["connect:198.51.100.42", "prefix:198.51.100.0/24"]);
    assert.equal(seen.length, 0);
    assert.equal(vpcTargets.length, 0);

    const allowed = limiters(true);
    const passed = await call("/v1/connect", { method: "POST", body: '{"v":1}' }, allowed.env);
    assert.equal(passed.status, 201);
    assert.equal(await passed.text(), 'echo:{"v":1}');
    assert.deepEqual(allowed.used, ["connect:unknown", "prefix:unknown"]);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.url, "/v1/connect");
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("keys an IPv6 client by its /64", async () => {
    for (const [address, key] of [
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
      ["2001:0DB8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"],
      ["2001:db8:1:2::7", "2001:db8:1:2::/64"],
      ["2001:db8::1", "2001:db8:0:0::/64"],
      ["2001:db8::", "2001:db8:0:0::/64"],
      ["::1", "0:0:0:0::/64"],
      ["::ffff:192.0.2.1", "::ffff:192.0.2.1"],
      ["2001:db8::1::2", "2001:db8::1::2"],
      ["2001:db8:1:2:3:4:5", "2001:db8:1:2:3:4:5"],
      ["2001:db8:1:2:3:4:5:6:7", "2001:db8:1:2:3:4:5:6:7"],
      ["2001:db8:zz::1", "2001:db8:zz::1"],
      ["192.0.2.1", "192.0.2.1"],
    ]) {
      const recorded = limiters(false);
      const response = await call("/v1/connect", {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": address! },
      }, recorded.env);
      assert.equal(response.status, 429, address);
      assert.deepEqual(recorded.used, [`connect:${key}`], address);
    }
  });

  it("keys a client by its coarse prefix for CONNECT_PREFIX_LIMITER", async () => {
    for (const [address, prefix] of [
      ["198.51.100.42", "198.51.100.0/24"],
      ["10.0.0.1", "10.0.0.0/24"],
      ["256.1.1.1", "256.1.1.1"],
      ["1.2.3", "1.2.3"],
      ["1.2.3.4.5", "1.2.3.4.5"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1::/48"],
      ["2001:0DB8:0001::", "2001:db8:1::/48"],
      ["2001:db8::1", "2001:db8:0::/48"],
      ["::1", "0:0:0::/48"],
      ["::ffff:192.0.2.1", "::ffff:192.0.2.1"],
      ["2001:db8::1::2", "2001:db8::1::2"],
      ["2001:db8:zz::1", "2001:db8:zz::1"],
      ["unknown", "unknown"],
    ]) {
      const recorded = limiters(true, false);
      const response = await call("/v1/connect", {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": address! },
      }, { ...recorded.env, RELAY: vpc() });
      assert.equal(response.status, 429, address);
      assert.deepEqual(recorded.used, [`connect:${CONNECT_KEYS[address!] ?? address}`, `prefix:${prefix}`], address);
      assert.equal(seen.length, 0, address);
    }
  });

  it("keeps the other limiters keyed by the full address", async () => {
    const recorded = limiters(true);
    await call("/v1/teams", {
      method: "POST",
      body: "{}",
      headers: { "cf-connecting-ip": "2001:db8:1:2:3:4:5:6" },
    }, recorded.env);
    assert.deepEqual(recorded.used, ["create:2001:db8:1:2:3:4:5:6"]);
  });

  it("passes POST /v1/connect when the limiter is missing or fails", async () => {
    for (const CONNECT_LIMITER of [
      undefined,
      { async limit() { throw new Error("limiter unavailable"); } },
    ]) {
      const response = await call("/v1/connect", { method: "POST", body: "{}" }, {
        CONNECT_LIMITER,
        CREATE_LIMITER: { async limit() { return { success: false }; } },
      });
      assert.equal(response.status, 201);
      assert.equal(await response.text(), "echo:{}");
      assert.equal(seen.length, 1);
    }
  });

  it("passes POST /v1/connect when CONNECT_PREFIX_LIMITER is missing or fails", async () => {
    for (const CONNECT_PREFIX_LIMITER of [
      undefined,
      { async limit() { throw new Error("limiter unavailable"); } },
    ]) {
      const used: string[] = [];
      const response = await call("/v1/connect", { method: "POST", body: "{}" }, {
        CONNECT_LIMITER: { async limit({ key }: { key: string }) { used.push(key); return { success: true }; } },
        CONNECT_PREFIX_LIMITER,
      });
      assert.equal(response.status, 201);
      assert.equal(await response.text(), "echo:{}");
      assert.equal(seen.length, 1);
      assert.deepEqual(used, ["unknown"]);
    }
  });

  it("still asks CONNECT_PREFIX_LIMITER when CONNECT_LIMITER is missing or fails", async () => {
    for (const CONNECT_LIMITER of [
      undefined,
      { async limit() { throw new Error("limiter unavailable"); } },
    ]) {
      const refused = limiters(true, false);
      const response = await call("/v1/connect", {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": "198.51.100.42" },
      }, { CONNECT_LIMITER, CONNECT_PREFIX_LIMITER: refused.env.CONNECT_PREFIX_LIMITER });
      assert.equal(response.status, 429);
      assert.deepEqual(refused.used, ["prefix:198.51.100.0/24"]);
      assert.equal(seen.length, 0);
    }
  });

  it("sends the client prefix of POST /v1/connect and its MAC to the relay, once, over any client copy", async () => {
    // Fixed vectors: HMAC-SHA256 under SECRET of "apassy-relay client prefix v1\0" + prefix,
    // computed independently of the Worker.
    for (const [address, prefix, mac] of [
      ["198.51.100.42", "198.51.100.0/24", "554af02c577b0770299175aff6f2a86f7082585a1abab1dcabcce44a54549490"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1::/48", "a5fd13e4d4baf530dab6b69b5893250bc1fd59e1959799b6c3ef27afd11bf3c7"],
      [undefined, "unknown", "c911db78ab276b0c75ee2abe45235ae0d275e3032609166865a198d978e42279"],
    ]) {
      for (const forged of [undefined, "203.0.113.0/24"]) {
        const recorded = limiters(true);
        const headers: Record<string, string> = {};
        if (address) headers["cf-connecting-ip"] = address;
        if (forged) {
          headers["X-Apassy-Client-Prefix"] = forged;
          headers["X-Apassy-Client-Prefix-Mac"] = "ffff";
        }
        const response = await call("/v1/connect", { method: "POST", body: "{}", headers }, recorded.env);
        assert.equal(response.status, 201, `${address} ${forged}`);
        assert.equal(seen.length, 1);
        assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix"), [prefix], `${address} ${forged}`);
        assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix-mac"), [mac], `${address} ${forged}`);
        assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
      }
    }
    // Without limiter bindings the prefix still travels.
    const bare = await call("/v1/connect", {
      method: "POST",
      body: "{}",
      headers: { "cf-connecting-ip": "198.51.100.42" },
    });
    assert.equal(bare.status, 201);
    assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix"), ["198.51.100.0/24"]);
    assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix-mac"), ["554af02c577b0770299175aff6f2a86f7082585a1abab1dcabcce44a54549490"]);
  });

  it("drops a client x-apassy-client-prefix and its MAC on every other request", async () => {
    for (const [method, path] of [
      ["POST", "/v1/teams"],
      ["GET", "/v1/me"],
      ["POST", "/v1/questions"],
      ["GET", "/v1/connect"],
      ["POST", "/v1/connect/"],
      ["PUT", "/v1/sync/snapshot"],
      ["POST", "/p/session/example.com/v1/connect"],
    ]) {
      const recorded = limiters(true);
      const response = await call(path!, {
        method,
        headers: {
          "cf-connecting-ip": "198.51.100.42",
          "X-Apassy-Client-Prefix": "203.0.113.0/24",
          "X-Apassy-Client-Prefix-Mac": "554af02c577b0770299175aff6f2a86f7082585a1abab1dcabcce44a54549490",
          ...(method === "PUT" ? { "content-length": "0" } : {}),
        },
      }, recorded.env);
      assert.equal(response.status, 201, `${method} ${path}`);
      assert.equal(seen.length, 1, `${method} ${path}`);
      assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix"), [], `${method} ${path}`);
      assert.deepEqual(values(seen[0]!, "x-apassy-client-prefix-mac"), [], `${method} ${path}`);
      assert.ok(!recorded.used.some((entry) => entry.startsWith("prefix:")), `${method} ${path}`);
    }
  });

  it("rate limits Connect challenges without consuming the one-per-minute creation guard", async () => {
    const used: string[] = [];
    const response = await call("/v1/connect/challenge", { method: "POST", body: "{}" }, {
      AUTH_LIMITER: { async limit({ key }: { key: string }) { used.push(key); return { success: false }; } },
      CONNECT_LIMITER: { async limit() { throw new Error("creation guard must not be used"); } },
    });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get("retry-after"), "60");
    assert.deepEqual(used, ["unknown"]);
    assert.equal(seen.length, 0);
  });

  it("does not use CONNECT_LIMITER for other methods or paths", async () => {
    for (const [method, path, other] of [
      ["GET", "/v1/connect", ""],
      ["HEAD", "/v1/connect", ""],
      ["PUT", "/v1/connect", ""],
      ["DELETE", "/v1/connect", ""],
      ["POST", "/v1/connect/", ""],
      ["POST", "/v1/connect/teams", ""],
      ["POST", "/v1/teams", "create"],
      ["POST", "/v1/join", "create"],
      ["POST", "/v1/auth/challenge", "auth"],
      ["POST", "/p/session/example.com/v1/connect", ""],
    ]) {
      const recorded = limiters(false);
      const response = await call(path!, { method }, recorded.env);
      assert.equal(response.status, 201, `${method} ${path}`);
      assert.equal(seen.length, 1, `${method} ${path}`);
      assert.deepEqual(recorded.used, other ? [`${other}:unknown`] : [], `${method} ${path}`);
    }
  });

  it("bounds the body of POST /v1/connect like any JSON route, before the limiter", async () => {
    const recorded = limiters(true);
    const response = await call("/v1/connect", {
      method: "POST",
      body: "x",
      headers: { "content-length": String(MAX_JSON_LENGTH + 1) },
    }, recorded.env);
    assert.equal(response.status, 413);
    assert.deepEqual(recorded.used, []);
    assert.equal(seen.length, 0);
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

describe("main module", () => {
  it("exports only the handler, because workerd refuses any other value there", async () => {
    const main = await import("../src/index.ts");
    assert.deepEqual(Object.keys(main), ["default"]);
  });
});

/** Every limiter of the Worker, recording `<name>:<key>`; each answers `success`. */
function everyLimiter(success: boolean) {
  const used: string[] = [];
  const limiter = (name: string) => ({
    async limit({ key }: { key: string }) {
      used.push(`${name}:${key}`);
      return { success };
    },
  });
  return {
    used,
    env: {
      CREATE_LIMITER: limiter("create"),
      AUTH_LIMITER: limiter("auth"),
      SYNC_LIMITER: limiter("sync"),
      CONNECT_LIMITER: limiter("connect"),
      CONNECT_PREFIX_LIMITER: limiter("prefix"),
      ACCOUNT_LIMITER: limiter("account"),
      TUNNEL_LIMITER: limiter("tunnel"),
    },
  };
}

describe("stripe webhook", () => {
  const PATH = "/v1/stripe/webhook";
  const SIGNATURE = "t=1790000000,v1=7557b67a768cdcbc112d10a1bfd4c9fc92476773765b4939b15f8484a8d66336";

  it("has the 256 KiB cap of the contract", () => {
    assert.equal(MAX_STRIPE_WEBHOOK_LENGTH, 262144);
    assert.ok(MAX_STRIPE_WEBHOOK_LENGTH > MAX_JSON_LENGTH);
  });

  it("passes a body of 256 KiB with its exact bytes and signature, without any limiter", async () => {
    const limits = everyLimiter(false);
    const head = Buffer.from('{"id":"evt_1","pad":"');
    const tail = Buffer.from('"}');
    const body = Buffer.concat([head, Buffer.alloc(MAX_STRIPE_WEBHOOK_LENGTH - head.length - tail.length, 0x61), tail]);
    assert.equal(body.length, MAX_STRIPE_WEBHOOK_LENGTH);
    const response = await call(PATH, {
      method: "POST",
      body,
      headers: {
        "content-length": String(body.length),
        "content-type": "application/json; charset=utf-8",
        "stripe-signature": SIGNATURE,
        "cf-connecting-ip": "3.18.12.63",
      },
    }, { ...limits.env, RELAY: vpc() });
    assert.equal(response.status, 201);
    assert.deepEqual(limits.used, []);
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.method, "POST");
    assert.equal(seen[0]!.url, PATH);
    assert.equal(Buffer.compare(seen[0]!.body, body), 0, "the signed bytes reach the relay unchanged");
    assert.deepEqual(values(seen[0]!, "stripe-signature"), [SIGNATURE]);
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("does not limit many events from one Stripe address", async () => {
    const limits = everyLimiter(false);
    for (let i = 0; i < 20; i++) {
      const response = await call(PATH, {
        method: "POST",
        body: "{}",
        headers: { "content-length": "2", "stripe-signature": SIGNATURE, "cf-connecting-ip": "3.18.12.63" },
      }, limits.env);
      assert.equal(response.status, 201, String(i));
    }
    assert.deepEqual(limits.used, []);
  });

  it("refuses a declared length above 256 KiB before the relay", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const declared of [String(MAX_STRIPE_WEBHOOK_LENGTH + 1), String(MAX_FEED_LENGTH), "99999999"]) {
      const response = await call(PATH, { method: "POST", body: "x", headers: { "content-length": declared } }, { RELAY: relay });
      assert.equal(response.status, 413, declared);
      assert.equal(response.headers.get("cache-control"), "no-store", declared);
      assert.equal((await envelope(response)).error.code, "payload_too_large", declared);
    }
    assert.deepEqual(forwarded, []);
  });

  it("refuses a missing, malformed, or chunked length", async () => {
    const { forwarded, relay } = recordingRelay();
    for (const headers of [
      {},
      { "content-length": "" },
      { "content-length": "abc" },
      { "content-length": "3, 3" },
      { "content-length": "3", "transfer-encoding": "chunked" },
    ] as Record<string, string>[]) {
      const label = JSON.stringify(headers);
      const response = await call(PATH, { method: "POST", body: "abc", headers }, { RELAY: relay });
      assert.equal(response.status, 400, label);
      assert.equal((await envelope(response)).error.code, "invalid_request", label);
    }
    assert.deepEqual(forwarded, []);
  });

  it("keeps the 64 KiB cap on every other path and method near the webhook", async () => {
    const { forwarded, relay } = recordingRelay();
    const declared = String(MAX_JSON_LENGTH + 1);
    for (const [method, path] of [
      ["POST", "/v1/stripe/webhook/"],
      ["POST", "/v1/stripe/webhooks"],
      ["POST", "/v1/stripe"],
      ["PUT", PATH],
      ["PATCH", PATH],
    ]) {
      const response = await call(path!, { method, body: "x", headers: { "content-length": declared } }, { RELAY: relay });
      assert.equal(response.status, 413, `${method} ${path}`);
    }
    assert.deepEqual(forwarded, []);
  });
});

describe("account rate limit", () => {
  it("uses ACCOUNT_LIMITER, and no other, for POST /v1/account, keyed by the address or the /64", async () => {
    for (const [address, key] of [
      ["198.51.100.7", "198.51.100.7"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
    ]) {
      const refused = everyLimiter(false);
      const response = await call("/v1/account", {
        method: "POST",
        body: "{}",
        headers: { "cf-connecting-ip": address! },
      }, { ...refused.env, RELAY: vpc() });
      assert.equal(response.status, 429, address);
      assert.equal(response.headers.get("retry-after"), "60");
      assert.equal((await envelope(response)).error.code, "rate_limited");
      assert.deepEqual(refused.used, [`account:${key}`], address);
      assert.equal(seen.length, 0);
      assert.equal(vpcTargets.length, 0);
    }
    const allowed = everyLimiter(true);
    const passed = await call("/v1/account", { method: "POST", body: '{"v":1}' }, allowed.env);
    assert.equal(passed.status, 201);
    assert.equal(await passed.text(), 'echo:{"v":1}');
    assert.deepEqual(allowed.used, ["account:unknown"]);
  });

  it("passes POST /v1/account when the limiter is missing or fails", async () => {
    for (const ACCOUNT_LIMITER of [undefined, { async limit() { throw new Error("limiter unavailable"); } }]) {
      const response = await call("/v1/account", { method: "POST", body: "{}" }, { ACCOUNT_LIMITER });
      assert.equal(response.status, 201);
    }
  });

  it("does not limit other account routes or methods", async () => {
    const refused = everyLimiter(false);
    for (const [method, path] of [
      ["GET", "/v1/account"],
      ["DELETE", "/v1/account"],
      ["POST", "/v1/account/checkout"],
      ["POST", "/v1/account/portal"],
      ["GET", "/v1/account/plan"],
      ["GET", "/v1/plans"],
    ]) {
      const response = await call(path!, { method, ...(method === "POST" ? { body: "{}" } : {}) }, refused.env);
      assert.equal(response.status, 201, `${method} ${path}`);
    }
    assert.deepEqual(refused.used, []);
  });
});

describe("tunnel", () => {
  const UPGRADE = {
    connection: "Upgrade",
    upgrade: "websocket",
    "sec-websocket-version": "13",
    "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
    "sec-websocket-protocol": "apassy-tunnel-v1",
    authorization: "Bearer apassy_act_acc_k7m2q4x3ca_00",
  };

  /** A relay that answers the upgrade: one response object, to check it comes back as it is. */
  function upgradingRelay() {
    const forwarded: { target: string; method: string; headers: Headers; body: unknown }[] = [];
    const answer = new Response(null, { status: 200, headers: { "x-switching": "yes" } });
    const relay: RelayService = {
      async fetch(input, init) {
        forwarded.push({ target: input, method: init?.method ?? "", headers: new Headers(init?.headers), body: init?.body });
        return answer;
      },
    };
    return { forwarded, relay, answer };
  }

  it("passes a WebSocket upgrade on the two tunnel routes to the relay unchanged and returns its answer", async () => {
    for (const path of ["/v1/tunnel/node", "/v1/tunnel/dial/node_k7m2q4x3ca"]) {
      const { forwarded, relay, answer } = upgradingRelay();
      const response = await call(path, { headers: { ...UPGRADE, "x-apassy-edge": "attacker", "cf-connecting-ip": "198.51.100.7" } }, { RELAY: relay });
      assert.equal(response, answer, `${path}: the relay's answer is returned as it is`);
      assert.equal(forwarded.length, 1, path);
      assert.equal(forwarded[0]!.target, "http://relay" + path);
      assert.equal(forwarded[0]!.method, "GET");
      assert.equal(forwarded[0]!.body, undefined);
      const headers = forwarded[0]!.headers;
      for (const [name, value] of Object.entries(UPGRADE)) {
        assert.equal(headers.get(name), value, `${path}: ${name}`);
      }
      assert.equal(headers.get("x-apassy-edge"), SECRET);
      assert.equal(headers.get("content-length"), null);
    }
  });

  it("refuses an upgrade on every other path or method before the relay", async () => {
    const { forwarded, relay } = upgradingRelay();
    const cases: [string, string][] = [
      ["GET", "/v1/me"],
      ["GET", "/mcp"],
      ["POST", "/mcp"],
      ["GET", "/p/apassy_ses_x/api.example.com/socket"],
      ["GET", "/v1/account"],
      ["GET", "/v1/questions"],
      ["GET", "/v1/feed"],
      ["GET", "/v1/tunnel"],
      ["POST", "/v1/tunnel/nodes"],
      ["DELETE", "/v1/tunnel/nodes/node_k7m2q4x3ca"],
      ["GET", "/v1/tunnel/../me"],
      ["GET", "/install.sh"],
      ["GET", "/dl/apassy-team"],
      ["GET", "/"],
    ];
    for (const headers of [UPGRADE, { upgrade: "h2c" }, { connection: "keep-alive, Upgrade" }] as Record<string, string>[]) {
      for (const [method, path] of cases) {
        const label = `${method} ${path} ${JSON.stringify(headers)}`;
        const response = await call(path, { method, headers, ...(method === "POST" ? { body: "{}" } : {}) }, { RELAY: relay, ASSETS: { async fetch() { return new Response("asset"); } } });
        assert.equal(response.status, 400, label);
        assert.equal((await envelope(response)).error.code, "invalid_request", label);
      }
    }
    assert.deepEqual(forwarded, []);
  });

  it("forwards the JSON tunnel routes as any other route", async () => {
    const response = await call("/v1/tunnel/nodes", { method: "POST", body: '{"name":"Mac"}' });
    assert.equal(response.status, 201);
    assert.equal(await response.text(), 'echo:{"name":"Mac"}');
    assert.equal(seen[0]!.url, "/v1/tunnel/nodes");
    assert.deepEqual(values(seen[0]!, "x-apassy-edge"), [SECRET]);
  });

  it("uses TUNNEL_LIMITER, and no other, for GET /v1/tunnel/dial/*, keyed by the address or the /64", async () => {
    for (const [address, key] of [
      ["198.51.100.7", "198.51.100.7"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
    ]) {
      const refused = everyLimiter(false);
      const { forwarded, relay } = upgradingRelay();
      const response = await call("/v1/tunnel/dial/node_k7m2q4x3ca", { headers: { ...UPGRADE, "cf-connecting-ip": address! } }, { ...refused.env, RELAY: relay });
      assert.equal(response.status, 429, address);
      assert.equal(response.headers.get("retry-after"), "60");
      assert.equal((await envelope(response)).error.code, "rate_limited");
      assert.deepEqual(refused.used, [`tunnel:${key}`], address);
      assert.deepEqual(forwarded, []);
    }
    const allowed = everyLimiter(true);
    const passed = await call("/v1/tunnel/dial/node_k7m2q4x3ca", {}, allowed.env);
    assert.equal(passed.status, 201);
    assert.deepEqual(allowed.used, ["tunnel:unknown"]);
  });

  it("does not limit the other tunnel routes, and passes a dial when the limiter is missing or fails", async () => {
    const refused = everyLimiter(false);
    for (const [method, path] of [
      ["GET", "/v1/tunnel/node"],
      ["GET", "/v1/tunnel/nodes"],
      ["POST", "/v1/tunnel/nodes"],
      ["POST", "/v1/tunnel/grants"],
      ["GET", "/v1/tunnel/grants"],
      ["DELETE", "/v1/tunnel/grants/tgr_w2x4y6z3ab"],
      ["POST", "/v1/tunnel/dial/node_k7m2q4x3ca"],
    ]) {
      const response = await call(path!, { method, ...(method === "POST" ? { body: "{}" } : {}) }, refused.env);
      assert.equal(response.status, 201, `${method} ${path}`);
    }
    assert.deepEqual(refused.used, []);
    for (const TUNNEL_LIMITER of [undefined, { async limit() { throw new Error("limiter unavailable"); } }]) {
      const response = await call("/v1/tunnel/dial/node_k7m2q4x3ca", {}, { TUNNEL_LIMITER });
      assert.equal(response.status, 201);
    }
  });
});
