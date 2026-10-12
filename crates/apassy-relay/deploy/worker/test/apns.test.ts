// Run with: node --test deploy/worker/test/   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import { beforeEach, before, describe, it } from "node:test";

import {
  APNS_PAYLOAD,
  MAX_PUSH_BODY,
  PUSH_HEADER,
  TOKEN_LIFETIME_SECS,
  handleInternal,
  resetTokenCache,
  type PushDeps,
  type PushEnv,
} from "../src/apns.ts";
import worker, { type RelayService } from "../src/index.ts";

const PUBLIC = "https://apassy-relay.wyderka.cc";
const SECRET = "push-secret-synthetic-0123456789abcdef0123";
const KEY_ID = "ABC123DEFG";
const TEAM_ID = "TEAM123456";
const TOPIC = "com.example.companion";
const TOKEN_A = "a".repeat(64);
const TOKEN_B = "0123456789abcdef".repeat(4);

let privateKeyPem = "";
let publicKey: CryptoKey;

before(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const base64 = Buffer.from(der).toString("base64");
  privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  publicKey = pair.publicKey;
});

function env(extra: Partial<PushEnv> = {}): PushEnv {
  return {
    PUSH_SECRET: SECRET,
    APNS_KEY: privateKeyPem,
    APNS_KEY_ID: KEY_ID,
    APNS_TEAM_ID: TEAM_ID,
    APNS_TOPIC: TOPIC,
    ...extra,
  };
}

interface Call {
  url: string;
  init: RequestInit;
}

/** A mock fetch and clock. `respond` decides the answer for each call. */
function mock(respond: (call: Call) => Response | Promise<Response> = () => new Response("", { status: 200 })) {
  const calls: Call[] = [];
  const state = { now: 1_000 };
  const deps: PushDeps = {
    fetch: async (url, init) => {
      const call = { url, init };
      calls.push(call);
      return respond(call);
    },
    now: () => state.now,
  };
  return { calls, state, deps };
}

function body(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    tokens: [TOKEN_A, TOKEN_B],
    environment: "production",
    collapse_id: "apassy-question",
    expires_at: 1_790_000_300,
    ...overrides,
  });
}

function push(
  payload: string | ReadableStream | null = body(),
  headers: Record<string, string> = { [PUSH_HEADER]: SECRET },
  init: RequestInit & { duplex?: "half" } = {},
  path = "/internal/push",
): Request {
  return new Request(PUBLIC + path, { method: "POST", headers, body: payload, duplex: "half", ...init });
}

function headerOf(call: Call, name: string): string | null {
  return new Headers(call.init.headers).get(name);
}

function jwtOf(call: Call): string {
  return headerOf(call, "authorization")!.replace(/^bearer /, "");
}

function decode(part: string): unknown {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

beforeEach(() => resetTokenCache());

describe("authorization", () => {
  it("answers 404 alike for every request that is not allowed", async () => {
    const { calls, deps } = mock();
    const refused: Response[] = [
      await handleInternal(push(body(), {}), env(), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: "wrong" }), env(), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: SECRET + "x" }), env(), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: SECRET }), env({ PUSH_SECRET: undefined }), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: "" }), env({ PUSH_SECRET: "" }), deps),
      await handleInternal(new Request(PUBLIC + "/internal/push", { method: "GET", headers: { [PUSH_HEADER]: SECRET } }), env(), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: SECRET }, {}, "/internal/x"), env(), deps),
      await handleInternal(push(body(), { [PUSH_HEADER]: SECRET }, {}, "/internal/push/"), env(), deps),
    ];
    for (const response of refused) {
      assert.equal(response.status, 404);
      assert.equal(await response.text(), "not found");
      assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
    assert.equal(calls.length, 0);
  });

  it("stops at 404 in the main Worker without calling the relay", async () => {
    let relayCalls = 0;
    const RELAY: RelayService = {
      async fetch() {
        relayCalls++;
        return new Response("relay");
      },
    };
    const response = await worker.fetch(push(body(), {}), { RELAY, EDGE_SECRET: "edge", PUSH_SECRET: SECRET });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), "not found");
    assert.equal(relayCalls, 0);
  });

  it("handles a call with the secret in the main Worker, 503 when APNs is not configured", async () => {
    let relayCalls = 0;
    const RELAY: RelayService = {
      async fetch() {
        relayCalls++;
        return new Response("relay");
      },
    };
    const response = await worker.fetch(push(), { RELAY, EDGE_SECRET: "edge", PUSH_SECRET: SECRET });
    assert.equal(response.status, 503);
    const parsed = (await response.json()) as { ok: boolean; error: { code: string } };
    assert.equal(parsed.ok, false);
    assert.equal(parsed.error.code, "push_unavailable");
    assert.equal(relayCalls, 0);
  });
});

describe("sending", () => {
  it("posts to each production token with the exact headers and body", async () => {
    const { calls, deps } = mock();
    const response = await handleInternal(push(), env(), deps);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/json");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      results: [
        { token: TOKEN_A, status: 200 },
        { token: TOKEN_B, status: 200 },
      ],
    });
    assert.deepEqual(
      calls.map((c) => c.url),
      [`https://api.push.apple.com/3/device/${TOKEN_A}`, `https://api.push.apple.com/3/device/${TOKEN_B}`],
    );
    for (const call of calls) {
      assert.equal(call.init.method, "POST");
      assert.equal(call.init.body, APNS_PAYLOAD);
      const headers = new Headers(call.init.headers);
      assert.deepEqual(
        [...headers.keys()].sort(),
        ["apns-collapse-id", "apns-expiration", "apns-priority", "apns-push-type", "apns-topic", "authorization", "content-type"],
      );
      assert.match(headers.get("authorization")!, /^bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
      assert.equal(headers.get("apns-topic"), TOPIC);
      assert.equal(headers.get("apns-push-type"), "alert");
      assert.equal(headers.get("apns-priority"), "10");
      assert.equal(headers.get("apns-expiration"), "1790000300");
      assert.equal(headers.get("apns-collapse-id"), "apassy-question");
      assert.equal(headers.get("content-type"), "application/json");
    }
  });

  it("sends the payload without content", () => {
    assert.deepEqual(JSON.parse(APNS_PAYLOAD), {
      aps: {
        alert: { title: "Apassy", body: "A question is waiting" },
        sound: "default",
        "interruption-level": "time-sensitive",
      },
    });
  });

  it("uses the sandbox host for development", async () => {
    const { calls, deps } = mock();
    const response = await handleInternal(push(body({ environment: "development" })), env(), deps);
    assert.equal(response.status, 200);
    assert.deepEqual(
      calls.map((c) => c.url),
      [`https://api.sandbox.push.apple.com/3/device/${TOKEN_A}`, `https://api.sandbox.push.apple.com/3/device/${TOKEN_B}`],
    );
  });
});

describe("provider token", () => {
  it("is a signed ES256 JWT", async () => {
    const { calls, state, deps } = mock();
    state.now = 1_234_567;
    await handleInternal(push(), env(), deps);
    const parts = jwtOf(calls[0]!).split(".");
    assert.equal(parts.length, 3);
    for (const part of parts) assert.match(part, /^[A-Za-z0-9_-]+$/);
    assert.deepEqual(decode(parts[0]!), { alg: "ES256", kid: KEY_ID });
    assert.deepEqual(decode(parts[1]!), { iss: TEAM_ID, iat: 1_234_567 });
    const signature = Buffer.from(parts[2]!, "base64url");
    assert.equal(signature.length, 64);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    assert.equal(valid, true);
  });

  it("is reused until it is 50 minutes old, then replaced", async () => {
    const { calls, state, deps } = mock();
    state.now = 1_000;
    await handleInternal(push(), env(), deps);
    state.now = 1_000 + 49 * 60;
    await handleInternal(push(), env(), deps);
    state.now = 1_000 + TOKEN_LIFETIME_SECS;
    await handleInternal(push(), env(), deps);
    const [first, second, third] = [0, 2, 4].map((i) => jwtOf(calls[i]!));
    assert.equal(jwtOf(calls[1]!), first);
    assert.equal(second, first);
    assert.notEqual(third, first);
    assert.deepEqual(decode(third!.split(".")[1]!), { iss: TEAM_ID, iat: 1_000 + TOKEN_LIFETIME_SECS });
  });

  it("is replaced when the key id changes", async () => {
    const { calls, deps } = mock();
    await handleInternal(push(), env(), deps);
    await handleInternal(push(), env({ APNS_KEY_ID: "OTHERKEY12" }), deps);
    assert.notEqual(jwtOf(calls[2]!), jwtOf(calls[0]!));
    assert.deepEqual(decode(jwtOf(calls[2]!).split(".")[0]!), { alg: "ES256", kid: "OTHERKEY12" });
  });
});

describe("results", () => {
  it("reports the status and reason of a refused token", async () => {
    const { deps } = mock(({ url }) =>
      url.endsWith(TOKEN_A)
        ? Response.json({ reason: "Unregistered" }, { status: 410 })
        : Response.json({ reason: "BadDeviceToken" }, { status: 400 }),
    );
    const response = await handleInternal(push(), env(), deps);
    assert.deepEqual(await response.json(), {
      results: [
        { token: TOKEN_A, status: 410, reason: "Unregistered" },
        { token: TOKEN_B, status: 400, reason: "BadDeviceToken" },
      ],
    });
  });

  it("has no reason for a 200", async () => {
    const { deps } = mock(() => Response.json({ reason: "Ignored" }, { status: 200 }));
    const response = await handleInternal(push(body({ tokens: [TOKEN_A] })), env(), deps);
    const { results } = (await response.json()) as { results: Record<string, unknown>[] };
    assert.deepEqual(results, [{ token: TOKEN_A, status: 200 }]);
    assert.equal("reason" in results[0]!, false);
  });

  it("reports status 0 and Unreachable when fetch throws", async () => {
    const { deps } = mock(() => {
      throw new Error("network down");
    });
    const response = await handleInternal(push(body({ tokens: [TOKEN_A] })), env(), deps);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { results: [{ token: TOKEN_A, status: 0, reason: "Unreachable" }] });
  });

  it("replaces a reason that is not a plain word with Unknown", async () => {
    const { deps } = mock(() => Response.json({ reason: "<script>" }, { status: 400 }));
    const response = await handleInternal(push(body({ tokens: [TOKEN_A] })), env(), deps);
    assert.deepEqual(await response.json(), { results: [{ token: TOKEN_A, status: 400, reason: "Unknown" }] });
  });

  it("uses Unknown when the body of a refusal is not JSON", async () => {
    const { deps } = mock(() => new Response("oops", { status: 500 }));
    const response = await handleInternal(push(body({ tokens: [TOKEN_A] })), env(), deps);
    assert.deepEqual(await response.json(), { results: [{ token: TOKEN_A, status: 500, reason: "Unknown" }] });
  });
});

describe("request validation", () => {
  const invalid: Array<[string, string]> = [
    ["an extra field", body({ extra: 1 })],
    ["a missing field", JSON.stringify({ tokens: [TOKEN_A], environment: "production", collapse_id: "x" })],
    ["no tokens", body({ tokens: [] })],
    ["51 tokens", body({ tokens: Array.from({ length: 51 }, () => TOKEN_A) })],
    ["an uppercase-hex token", body({ tokens: ["A".repeat(64)] })],
    ["a 31-char token", body({ tokens: ["a".repeat(31)] })],
    ["a token that is not a string", body({ tokens: [12] })],
    ["environment staging", body({ environment: "staging" })],
    ["a 65-char collapse_id", body({ collapse_id: "a".repeat(65) })],
    ["an empty collapse_id", body({ collapse_id: "" })],
    ["a collapse_id with a space", body({ collapse_id: "a b" })],
    ["expires_at -1", body({ expires_at: -1 })],
    ["expires_at as a string", body({ expires_at: "1" })],
    ["expires_at with a fraction", body({ expires_at: 1.5 })],
    ["a body that is not JSON", "not json"],
    ["a JSON array", "[]"],
    ["JSON null", "null"],
  ];
  for (const [name, payload] of invalid) {
    it(`answers 400 invalid_request for ${name}`, async () => {
      const { calls, deps } = mock();
      const response = await handleInternal(push(payload), env(), deps);
      assert.equal(response.status, 400);
      const parsed = (await response.json()) as { ok: boolean; error: { code: string } };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.error.code, "invalid_request");
      assert.equal(calls.length, 0);
    });
  }

  it("accepts 50 tokens", async () => {
    const { calls, deps } = mock();
    const response = await handleInternal(push(body({ tokens: Array.from({ length: 50 }, () => TOKEN_A) })), env(), deps);
    assert.equal(response.status, 200);
    assert.equal(calls.length, 50);
  });

  it("answers 413 for a declared length above 64 KiB", async () => {
    const { calls, deps } = mock();
    const request = push(body(), { [PUSH_HEADER]: SECRET, "content-length": String(MAX_PUSH_BODY + 1) });
    const response = await handleInternal(request, env(), deps);
    assert.equal(response.status, 413);
    const parsed = (await response.json()) as { error: { code: string } };
    assert.equal(parsed.error.code, "payload_too_large");
    assert.equal(calls.length, 0);
  });

  it("answers 413 for a body above 64 KiB without a declared length", async () => {
    const { calls, deps } = mock();
    const chunk = new TextEncoder().encode("x".repeat(MAX_PUSH_BODY));
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(chunk);
        controller.enqueue(new TextEncoder().encode("y"));
        controller.close();
      },
    });
    const response = await handleInternal(push(stream), env(), deps);
    assert.equal(response.status, 413);
    const parsed = (await response.json()) as { error: { code: string } };
    assert.equal(parsed.error.code, "payload_too_large");
    assert.equal(calls.length, 0);
  });
});

describe("configuration", () => {
  it("answers 503 push_unavailable when APNS_KEY_ID is empty", async () => {
    const { calls, deps } = mock();
    const response = await handleInternal(push(), env({ APNS_KEY_ID: "" }), deps);
    assert.equal(response.status, 503);
    const parsed = (await response.json()) as { ok: boolean; error: { code: string } };
    assert.equal(parsed.error.code, "push_unavailable");
    assert.equal(calls.length, 0);
  });

  it("answers 503 push_unavailable when the key is not valid, without key text", async () => {
    const { calls, deps } = mock();
    const bad = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----";
    const response = await handleInternal(push(), env({ APNS_KEY: bad }), deps);
    assert.equal(response.status, 503);
    const raw = await response.text();
    assert.equal((JSON.parse(raw) as { error: { code: string } }).error.code, "push_unavailable");
    assert.ok(!raw.includes("bm90IGEga2V5"));
    assert.ok(!raw.includes("PRIVATE KEY"));
    assert.equal(calls.length, 0);
  });

  it("answers 503 push_unavailable when the key is not base64", async () => {
    const { deps } = mock();
    const response = await handleInternal(push(), env({ APNS_KEY: "%%% not a key %%%" }), deps);
    assert.equal(response.status, 503);
  });
});
