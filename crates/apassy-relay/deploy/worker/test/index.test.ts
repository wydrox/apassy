// Run with: node --test deploy/worker/test/   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import worker from "../src/index.ts";

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

function call(path: string, init: RequestInit & { duplex?: "half" } = {}, env = {}) {
  seen = [];
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
