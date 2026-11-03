// The routes of the push gateway (docs/contracts/push-gateway-v1.md sections 6 to 13).
// Run with: node --test 'test/*.test.ts'   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, beforeEach, describe, it } from "node:test";

import { APNS_PAYLOAD, resetTokenCache } from "../../worker/src/apns.ts";
import {
  LIMIT_PERIOD_SECS,
  SUMMARY_PAYLOAD_HEAD,
  SUMMARY_PAYLOAD_TAIL,
  handleGateway,
  type GatewayDeps,
  type GatewayEnv,
  type RateLimit,
} from "../src/gateway.ts";
import { decodeB64u, encodeB64u, makeProof, proofMessage } from "../src/handles.ts";
import worker from "../src/index.ts";
import { V, range } from "./fixtures.ts";

const ORIGIN = "https://push.example.com";
const TOPIC = "com.wydrox.apassy.companion";
const WATCH_TOPIC = "com.wydrox.apassy.companion.watchkitapp";

let privateKeyPem = "";

before(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const base64 = Buffer.from(der).toString("base64");
  privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
});

beforeEach(() => resetTokenCache());

/** A rate limit that lets `allow` calls per key through and records the keys. */
function limiter(allow = 1000): RateLimit & { keys: string[] } {
  const counts = new Map<string, number>();
  const keys: string[] = [];
  return {
    keys,
    async limit({ key }) {
      keys.push(key);
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);
      return { success: count <= allow };
    },
  };
}

function env(extra: Partial<GatewayEnv> = {}): GatewayEnv {
  return {
    GATEWAY_KEY: V.gatewayKey,
    GATEWAY_KEY_ID: "1",
    APNS_KEY: privateKeyPem,
    APNS_KEY_ID: "ABC123DEFG",
    APNS_TEAM_ID: "7S3F9767BM",
    APNS_TOPIC: TOPIC,
    APNS_WATCH_TOPIC: WATCH_TOPIC,
    handles_per_address: limiter(),
    pushes_per_handle: limiter(),
    pushes_per_address: limiter(),
    ...extra,
  };
}

interface Call {
  url: string;
  init: RequestInit;
}

/** The fake APNs, clock, and random source. `random` gives the bytes of `fill`, counting up. */
function mock(respond: (call: Call) => Response | Promise<Response> = () => new Response("", { status: 200 })) {
  const calls: Call[] = [];
  const state = { now: V.at, next: 0x60 };
  const deps: GatewayDeps = {
    fetch: async (url, init) => {
      const call = { url, init };
      calls.push(call);
      return respond(call);
    },
    now: () => state.now,
    random: (length) => {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) out[i] = (state.next + i) & 0xff;
      state.next = (state.next + length) & 0xff;
      return out;
    },
  };
  return { calls, state, deps };
}

function post(path: string, body: string, headers: Record<string, string> = {}): Request {
  return new Request(ORIGIN + path, {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7", ...headers },
    body,
  });
}

async function answer(response: Response): Promise<{ status: number; body: any; headers: Headers }> {
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : undefined, headers: response.headers };
}

function handleBody(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ v: 1, kind: "iphone", token: V.iphoneToken, environment: "production", bundle_id: TOPIC, ...extra });
}

async function pushBody(handle: string, secretText: string, fields: Partial<Record<string, unknown>> = {}): Promise<string> {
  const at = (fields.at as number | undefined) ?? V.at;
  const expiresAt = (fields.expires_at as number | undefined) ?? V.expiresAt;
  const summary = fields.summary as string | undefined;
  const proof =
    (fields.proof as string | undefined) ??
    (await makeProof(decodeB64u(secretText)!, proofMessage(handle, at, expiresAt, V.collapseId, summary)));
  const body: Record<string, unknown> = { v: 1, handle, at, expires_at: expiresAt, collapse_id: V.collapseId, proof };
  if (summary !== undefined) body.summary = summary;
  for (const [name, value] of Object.entries(fields)) {
    if (!["at", "expires_at", "summary", "proof"].includes(name)) body[name] = value;
  }
  return JSON.stringify(body);
}

const SECRETS = ["YGFiY2Rl", V.iphoneSecret, V.watchSecret, V.iphoneToken, V.watchToken];

/** No error message holds a token, handle, secret, proof, or summary. */
function assertClean(body: unknown) {
  const text = JSON.stringify(body);
  for (const value of SECRETS) assert.ok(!text.includes(value), "the answer holds a request value");
  assert.ok(!text.includes(V.iphoneHandle.slice(0, 40)));
}

describe("POST /v1/handles", () => {
  it("makes a handle that a push opens: the round trip", async () => {
    const { calls, deps } = mock();
    const made = await answer(await handleGateway(post("/v1/handles", handleBody()), env(), deps));
    assert.equal(made.status, 200);
    assert.deepEqual(Object.keys(made.body), ["v", "handle", "secret", "expires_at"]);
    assert.equal(made.body.v, 1);
    assert.equal(made.body.expires_at, V.at + 15_552_000);
    assert.equal(made.body.secret.length, 43);
    assert.equal(made.headers.get("cache-control"), "no-store");
    const pushed = await answer(
      await handleGateway(post("/v1/push", await pushBody(made.body.handle, made.body.secret)), env(), deps),
    );
    assert.deepEqual(pushed.body, { v: 1, status: 200 });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, `https://api.push.apple.com/3/device/${V.iphoneToken}`);
  });

  it("gives two independent handles for two calls", async () => {
    const { deps } = mock();
    const a = await answer(await handleGateway(post("/v1/handles", handleBody()), env(), deps));
    const b = await answer(await handleGateway(post("/v1/handles", handleBody()), env(), deps));
    assert.notEqual(a.body.handle, b.body.handle);
    assert.notEqual(a.body.secret, b.body.secret);
  });

  it("seals a development handle that goes to the sandbox", async () => {
    const { calls, deps } = mock();
    const made = await answer(
      await handleGateway(post("/v1/handles", handleBody({ environment: "development" })), env(), deps),
    );
    await handleGateway(post("/v1/push", await pushBody(made.body.handle, made.body.secret)), env(), deps);
    assert.equal(calls[0]!.url, `https://api.sandbox.push.apple.com/3/device/${V.iphoneToken}`);
  });

  it("refuses another bundle id and a watch without its topic", async () => {
    const { deps } = mock();
    const wrong = await answer(await handleGateway(post("/v1/handles", handleBody({ bundle_id: "com.example.other" })), env(), deps));
    assert.equal(wrong.status, 409);
    assert.equal(wrong.body.error.code, "wrong_bundle");
    const watch = handleBody({ kind: "watch", token: V.watchToken, bundle_id: WATCH_TOPIC });
    const noTopic = await answer(await handleGateway(post("/v1/handles", watch), env({ APNS_WATCH_TOPIC: undefined }), deps));
    assert.equal(noTopic.status, 409);
    assert.equal(noTopic.body.error.code, "kind_unavailable");
    const ok = await answer(await handleGateway(post("/v1/handles", watch), env(), deps));
    assert.equal(ok.status, 200);
    // An iPhone bundle id for the watch kind is the wrong bundle.
    const crossed = await answer(await handleGateway(post("/v1/handles", handleBody({ kind: "watch" })), env(), deps));
    assert.equal(crossed.body.error.code, "wrong_bundle");
  });

  it("refuses bodies out of form", async () => {
    const { deps } = mock();
    const bodies = [
      handleBody({ extra: 1 }),
      handleBody({ v: 2 }),
      handleBody({ kind: "ipad" }),
      handleBody({ token: "A1".repeat(32) }),
      handleBody({ token: "a1".repeat(15) }),
      handleBody({ environment: "staging" }),
      JSON.stringify({ v: 1, kind: "iphone", token: V.iphoneToken, environment: "production" }),
      handleBody().replace('"v":1,', '"v":1,"v":1,'),
      "not json",
    ];
    for (const body of bodies) {
      const refused = await answer(await handleGateway(post("/v1/handles", body), env(), deps));
      assert.equal(refused.status, 400, body);
      assert.equal(refused.body.error.code, "invalid_request");
      assert.deepEqual(Object.keys(refused.body), ["ok", "error"]);
    }
  });

  it("limits handle creations per address, keyed by SHA-256 of the address", async () => {
    const { deps } = mock();
    const limit = limiter(2);
    const environment = env({ handles_per_address: limit });
    for (let i = 0; i < 2; i++) {
      assert.equal((await handleGateway(post("/v1/handles", handleBody()), environment, deps)).status, 200);
    }
    const third = await answer(await handleGateway(post("/v1/handles", handleBody()), environment, deps));
    assert.equal(third.status, 429);
    assert.equal(third.body.error.code, "rate_limited");
    assert.equal(third.headers.get("retry-after"), String(LIMIT_PERIOD_SECS));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("203.0.113.7")));
    assert.equal(limit.keys[0], Buffer.from(digest).toString("hex"));
    // Another address has its own count.
    const other = post("/v1/handles", handleBody(), { "cf-connecting-ip": "198.51.100.1" });
    assert.equal((await handleGateway(other, environment, deps)).status, 200);
  });

  it("is unavailable without a gateway key or a limit binding", async () => {
    const { deps } = mock();
    for (const extra of [{ GATEWAY_KEY: undefined }, { GATEWAY_KEY_ID: "0" }, { handles_per_address: undefined }]) {
      const refused = await answer(await handleGateway(post("/v1/handles", handleBody()), env(extra), deps));
      assert.equal(refused.status, 503);
      assert.equal(refused.body.error.code, "push_unavailable");
    }
  });
});

describe("POST /v1/push", () => {
  it("sends exactly today's payload, headers, and collapse id for the vector handle", async () => {
    const { calls, deps } = mock();
    const body = await pushBody(V.iphoneHandle, V.iphoneSecret);
    assert.ok(body.includes(`"proof":"${V.iphoneProof}"`));
    const pushed = await answer(await handleGateway(post("/v1/push", body), env(), deps));
    assert.equal(pushed.status, 200);
    assert.deepEqual(pushed.body, { v: 1, status: 200 });
    assert.equal(calls.length, 1);
    const call = calls[0]!;
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.body, APNS_PAYLOAD);
    assert.equal(
      call.init.body,
      '{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}',
    );
    const headers = call.init.headers as Record<string, string>;
    assert.equal(headers["apns-topic"], TOPIC);
    assert.equal(headers["apns-push-type"], "alert");
    assert.equal(headers["apns-priority"], "10");
    assert.equal(headers["apns-expiration"], String(V.expiresAt));
    assert.equal(headers["apns-collapse-id"], "apassy-question");
    assert.equal(headers["content-type"], "application/json");
    assert.match(headers.authorization!, /^bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("pushes the watch handle to the watch topic", async () => {
    const { calls, deps } = mock();
    const pushed = await answer(await handleGateway(post("/v1/push", await pushBody(V.watchHandle, V.watchSecret)), env(), deps));
    assert.deepEqual(pushed.body, { v: 1, status: 200 });
    assert.equal((calls[0]!.init.headers as Record<string, string>)["apns-topic"], WATCH_TOPIC);
    assert.equal(calls[0]!.url, `https://api.push.apple.com/3/device/${V.watchToken}`);
    // Without the watch topic, the watch handle is kind_unavailable.
    const off = await answer(
      await handleGateway(post("/v1/push", await pushBody(V.watchHandle, V.watchSecret)), env({ APNS_WATCH_TOPIC: undefined }), deps),
    );
    assert.equal(off.status, 409);
    assert.equal(off.body.error.code, "kind_unavailable");
  });

  it("copies a sealed summary into `s` with mutable content, and binds it in the proof", async () => {
    const { calls, deps } = mock();
    const body = await pushBody(V.iphoneHandle, V.iphoneSecret, { summary: V.summary });
    assert.ok(body.includes(`"proof":"${V.iphoneProofWithSummary}"`));
    const pushed = await answer(await handleGateway(post("/v1/push", body), env(), deps));
    assert.deepEqual(pushed.body, { v: 1, status: 200 });
    assert.equal(
      calls[0]!.init.body,
      `{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive","mutable-content":1},"s":"${V.summary}"}`,
    );
    assert.equal(calls[0]!.init.body, SUMMARY_PAYLOAD_HEAD + V.summary + SUMMARY_PAYLOAD_TAIL);
    // The proof without the summary does not cover a summary.
    const unbound = await pushBody(V.iphoneHandle, V.iphoneSecret, { summary: V.summary, proof: V.iphoneProof });
    const refused = await answer(await handleGateway(post("/v1/push", unbound), env(), deps));
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.code, "proof_invalid");
  });

  it("maps APNs answers: 410 Unregistered, a reason that is not a word, a throw", async () => {
    const apns410 = mock(() => new Response('{"reason":"Unregistered","timestamp":1}', { status: 410 }));
    const gone = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), apns410.deps));
    assert.equal(gone.status, 200);
    assert.deepEqual(gone.body, { v: 1, status: 410, reason: "Unregistered" });
    const odd = mock(() => new Response('{"reason":"<b>"}', { status: 400 }));
    const unknown = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), odd.deps));
    assert.deepEqual(unknown.body, { v: 1, status: 400, reason: "Unknown" });
    const down = mock(() => {
      throw new Error("down");
    });
    const unreachable = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), down.deps));
    assert.deepEqual(unreachable.body, { v: 1, status: 0, reason: "Unreachable" });
  });

  it("refuses forged, cut, altered, foreign, and expired handles with 403", async () => {
    const { calls, deps } = mock();
    const bytes = decodeB64u(V.iphoneHandle)!;
    bytes[19] = bytes[19]! ^ 0x01;
    const other = range(0x40, 0x5f);
    other[0] = 0x41;
    const cases: [string, Partial<GatewayEnv>, number, string][] = [
      [encodeB64u(bytes), {}, V.at, "handle_invalid"],
      [V.iphoneHandle.slice(0, 40), {}, V.at, "handle_invalid"],
      [V.iphoneHandle, { GATEWAY_KEY: encodeB64u(other) }, V.at, "handle_invalid"],
      [V.iphoneHandle, { GATEWAY_KEY_ID: "2" }, V.at, "handle_invalid"],
      [V.iphoneHandle, {}, V.handleExpiresAt + 1, "handle_expired"],
    ];
    for (const [handle, extra, now, code] of cases) {
      const fixed = mock();
      fixed.state.now = now;
      const body = await pushBody(handle, V.iphoneSecret, { at: now, expires_at: now + 300 });
      const refused = await answer(await handleGateway(post("/v1/push", body), env(extra), fixed.deps));
      assert.equal(refused.status, 403, code);
      assert.equal(refused.body.error.code, code);
      assertClean(refused.body);
      assert.equal(fixed.calls.length, 0);
    }
    assert.equal(calls.length, 0);
    void deps;
  });

  it("opens a handle of the previous key after a rotation", async () => {
    const { deps } = mock();
    const rotated = env({
      GATEWAY_KEY: encodeB64u(range(0xa0, 0xbf)),
      GATEWAY_KEY_ID: "2",
      GATEWAY_KEY_PREVIOUS: V.gatewayKey,
      GATEWAY_KEY_PREVIOUS_ID: "1",
    });
    const pushed = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), rotated, deps));
    assert.deepEqual(pushed.body, { v: 1, status: 200 });
    // A new handle is made under the current key: its header names id 2.
    const made = await answer(await handleGateway(post("/v1/handles", handleBody()), rotated, deps));
    assert.equal(decodeB64u(made.body.handle)![1], 2);
  });

  it("refuses a wrong proof: another time, another secret", async () => {
    const { calls, deps } = mock();
    const wrongTime = await pushBody(V.iphoneHandle, V.iphoneSecret, { proof: V.iphoneProof, at: V.at + 1 });
    const wrongSecret = await pushBody(V.iphoneHandle, V.watchSecret);
    for (const body of [wrongTime, wrongSecret]) {
      const refused = await answer(await handleGateway(post("/v1/push", body), env(), deps));
      assert.equal(refused.status, 403);
      assert.equal(refused.body.error.code, "proof_invalid");
      assertClean(refused.body);
    }
    assert.equal(calls.length, 0);
  });

  it("refuses a stale `at` with 403 and times out of bounds with 400", async () => {
    const { deps, state } = mock();
    state.now = V.at + 301;
    const stale = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), deps));
    assert.equal(stale.status, 403);
    assert.equal(stale.body.error.code, "stale_request");
    state.now = V.at - 301;
    assert.equal((await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), deps)).status, 403);
    state.now = V.at + 300;
    assert.equal((await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(), deps)).status, 200);
    state.now = V.at;
    for (const times of [
      { expires_at: V.at },
      { expires_at: V.at - 1 },
      { expires_at: V.at + 601 },
    ]) {
      const refused = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret, times)), env(), deps));
      assert.equal(refused.status, 400);
      assert.equal(refused.body.error.code, "invalid_request");
    }
    const longest = await pushBody(V.iphoneHandle, V.iphoneSecret, { expires_at: V.at + 600 });
    assert.equal((await handleGateway(post("/v1/push", longest), env(), deps)).status, 200);
  });

  it("checks the shape first: a token field, a short summary, a repeated field, v 2", async () => {
    const { calls, deps } = mock();
    const base = await pushBody(V.iphoneHandle, V.iphoneSecret);
    const bodies = [
      await pushBody(V.iphoneHandle, V.iphoneSecret, { token: V.iphoneToken }),
      await pushBody(V.iphoneHandle, V.iphoneSecret, { summary: V.summary.slice(0, 719) }),
      base.replace('"v":1,', '"v":1,"v":1,'),
      base.replace('"v":1,', '"v":2,'),
      base.replace(`"collapse_id":"apassy-question"`, `"collapse_id":"apassy question"`),
      base.replace(`"proof":"${V.iphoneProof}"`, `"proof":"${V.iphoneProof.slice(0, 42)}"`),
      base.replace(`"at":${V.at}`, `"at":"${V.at}"`),
      base.replace(`"at":${V.at}`, `"at":${V.at}.0`),
    ];
    for (const body of bodies) {
      const refused = await answer(await handleGateway(post("/v1/push", body), env(), deps));
      assert.equal(refused.status, 400, body.slice(0, 80));
      assert.equal(refused.body.error.code, "invalid_request");
    }
    assert.equal(calls.length, 0);
  });

  it("limits pushes per handle and per node address", async () => {
    const { calls, deps } = mock();
    const perHandle = limiter(3);
    const environment = env({ pushes_per_handle: perHandle });
    for (let i = 0; i < 3; i++) {
      const body = await pushBody(V.iphoneHandle, V.iphoneSecret);
      assert.equal((await handleGateway(post("/v1/push", body), environment, deps)).status, 200);
    }
    const fourth = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), environment, deps));
    assert.equal(fourth.status, 429);
    assert.equal(fourth.headers.get("retry-after"), "60");
    // Another handle is not limited by this one.
    assert.equal((await handleGateway(post("/v1/push", await pushBody(V.watchHandle, V.watchSecret)), environment, deps)).status, 200);
    assert.equal(calls.length, 4);
    const handleDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(V.iphoneHandle)));
    assert.equal(perHandle.keys[0], Buffer.from(handleDigest).toString("hex"));

    const perAddress = limiter(1);
    const byAddress = env({ pushes_per_address: perAddress });
    assert.equal((await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), byAddress, deps)).status, 200);
    const second = await answer(await handleGateway(post("/v1/push", await pushBody(V.watchHandle, V.watchSecret)), byAddress, deps));
    assert.equal(second.status, 429);
  });

  it("is unavailable without the APNs configuration or with a key that does not import", async () => {
    const { calls, deps } = mock();
    for (const extra of [{ APNS_KEY: undefined }, { APNS_KEY_ID: "" }, { APNS_TEAM_ID: undefined }, { APNS_KEY: "not a key" }, { APNS_TOPIC: undefined }]) {
      resetTokenCache();
      const refused = await answer(await handleGateway(post("/v1/push", await pushBody(V.iphoneHandle, V.iphoneSecret)), env(extra), deps));
      assert.equal(refused.status, 503);
      assert.equal(refused.body.error.code, "push_unavailable");
    }
    assert.equal(calls.length, 0);
  });

  it("refuses a body over 4096 bytes with 413", async () => {
    const { deps } = mock();
    const big = await answer(await handleGateway(post("/v1/push", "x".repeat(4097)), env(), deps));
    assert.equal(big.status, 413);
    assert.equal(big.body.error.code, "payload_too_large");
    // A declared length above the limit, where the runtime keeps the header on a Request.
    const request = post("/v1/handles", handleBody(), { "content-length": "5000" });
    if (request.headers.get("content-length") === "5000") {
      const declared = await answer(await handleGateway(request, env(), deps));
      assert.equal(declared.status, 413);
    }
  });
});

describe("the other routes", () => {
  it("answers /healthz with its Date", async () => {
    const { deps } = mock();
    const health = await answer(await handleGateway(new Request(`${ORIGIN}/healthz`), env(), deps));
    assert.equal(health.status, 200);
    assert.deepEqual(health.body, { v: 1, ok: true });
    assert.equal(health.headers.get("date"), new Date(V.at * 1000).toUTCString());
  });

  it("answers 404 to every other path and method", async () => {
    const { deps } = mock();
    for (const [method, path] of [
      ["GET", "/"],
      ["GET", "/v1/push"],
      ["PUT", "/v1/handles"],
      ["POST", "/healthz"],
      ["POST", "/internal/push"],
      ["POST", "/v1/push/token"],
    ] as const) {
      const init: RequestInit = { method };
      if (method !== "GET") init.body = "{}";
      const refused = await answer(await handleGateway(new Request(ORIGIN + path, init), env(), deps));
      assert.equal(refused.status, 404, `${method} ${path}`);
      assert.deepEqual(refused.body, { ok: false, error: { code: "not_found", message: "Not found." } });
      assert.equal(refused.headers.get("cache-control"), "no-store");
    }
  });

  it("the main module exports only the fetch handler", () => {
    assert.deepEqual(Object.keys(worker), ["fetch"]);
  });
});

describe("the deployment", () => {
  const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf-8");
  // Comments out: only the configuration counts.
  const settings = config
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");

  it("has no storage or log binding, and observability is off", () => {
    for (const binding of [
      "kv_namespaces",
      "d1_databases",
      "r2_buckets",
      "durable_objects",
      "queues",
      "analytics_engine_datasets",
      "logpush",
      "tail_consumers",
      "services",
      "vpc_services",
      "assets",
    ]) {
      assert.ok(!settings.includes(`"${binding}"`), binding);
    }
    assert.match(settings, /"observability": \{ "enabled": false \}/);
  });

  it("names the three limits of the contract and no secret value", () => {
    for (const name of ["handles_per_address", "pushes_per_handle", "pushes_per_address"]) {
      assert.match(settings, new RegExp(`"name": "${name}"`));
    }
    assert.ok(!settings.includes('"GATEWAY_KEY"'));
    assert.ok(!settings.includes('"APNS_KEY"'));
    assert.ok(!settings.includes("PRIVATE KEY"));
  });

  it("the gateway source has no console call", () => {
    for (const file of ["../src/gateway.ts", "../src/handles.ts", "../src/index.ts"]) {
      const source = readFileSync(new URL(file, import.meta.url), "utf-8");
      assert.ok(!/console\./.test(source), file);
    }
  });
});
