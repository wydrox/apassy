// The test vectors of docs/contracts/push-gateway-v1.md section 18, checked in TypeScript.
// Run with: node --test 'test/*.test.ts'   (Node 22.18 or later, type stripping)
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  decodeB64u,
  encodeB64u,
  handlePlaintext,
  importGatewayKey,
  makeProof,
  openHandle,
  parseFlat,
  parsePlaintext,
  proofMatches,
  proofMessage,
  sealHandle,
} from "../src/handles.ts";

import { IPHONE, V, WATCH, range } from "./fixtures.ts";

async function key() {
  const imported = await importGatewayKey(V.gatewayKey, "1");
  assert.ok(imported);
  return imported;
}

describe("push-gateway-v1 vectors", () => {
  it("the key and secret texts are the given bytes", () => {
    assert.deepEqual(decodeB64u(V.gatewayKey), range(0x40, 0x5f));
    assert.deepEqual(decodeB64u(V.iphoneSecret), range(0x60, 0x7f));
    assert.deepEqual(decodeB64u(V.watchSecret), range(0x80, 0x9f));
    assert.equal(encodeB64u(range(0x40, 0x5f)), V.gatewayKey);
  });

  it("the plaintexts have the contract's form", () => {
    assert.equal(handlePlaintext(IPHONE), V.iphonePlaintext);
    assert.equal(handlePlaintext(WATCH), V.watchPlaintext);
    assert.deepEqual(parsePlaintext(V.iphonePlaintext), IPHONE);
    // Another order, white space, or a field more is out of form.
    assert.equal(parsePlaintext(V.iphonePlaintext.replace('{"v":1,', '{ "v":1,')), undefined);
    assert.equal(parsePlaintext(V.iphonePlaintext.replace('"kind":"iphone","token"', '"token"')), undefined);
    assert.equal(parsePlaintext(V.iphonePlaintext.replace("}", ',"x":1}')), undefined);
  });

  it("seals the iPhone and watch handles of the vectors", async () => {
    const gatewayKey = await key();
    assert.equal(await sealHandle(gatewayKey, IPHONE, range(0x00, 0x0b)), V.iphoneHandle);
    assert.equal(await sealHandle(gatewayKey, WATCH, range(0x10, 0x1b)), V.watchHandle);
  });

  it("opens both handles", async () => {
    const gatewayKey = await key();
    assert.deepEqual(await openHandle(V.iphoneHandle, [gatewayKey], V.at), { ok: true, payload: IPHONE });
    assert.deepEqual(await openHandle(V.watchHandle, [gatewayKey], V.at), { ok: true, payload: WATCH });
  });

  it("recomputes the proofs", async () => {
    const iphone = decodeB64u(V.iphoneSecret)!;
    const watch = decodeB64u(V.watchSecret)!;
    assert.equal(await makeProof(iphone, proofMessage(V.iphoneHandle, V.at, V.expiresAt, V.collapseId)), V.iphoneProof);
    assert.equal(await makeProof(watch, proofMessage(V.watchHandle, V.at, V.expiresAt, V.collapseId)), V.watchProof);
    assert.equal(
      await makeProof(iphone, proofMessage(V.iphoneHandle, V.at, V.expiresAt, V.collapseId, V.summary)),
      V.iphoneProofWithSummary,
    );
    assert.equal(V.summary.length, 720);
    assert.equal(decodeB64u(V.summary)!.length, 540);
    assert.deepEqual(decodeB64u(V.summary)!.subarray(0, 12), range(0x20, 0x2b));
  });

  it("the checks that must fail", async () => {
    const gatewayKey = await key();
    // The key with its first byte changed.
    const other = range(0x40, 0x5f);
    other[0] = 0x41;
    const otherKey = await importGatewayKey(encodeB64u(other), "1");
    assert.deepEqual(await openHandle(V.iphoneHandle, [otherKey!], V.at), { ok: false, code: "handle_invalid" });
    // The 20th decoded byte (in the ciphertext) flipped.
    const bytes = decodeB64u(V.iphoneHandle)!;
    bytes[19] = bytes[19]! ^ 0x01;
    assert.deepEqual(await openHandle(encodeB64u(bytes), [gatewayKey], V.at), { ok: false, code: "handle_invalid" });
    // After expires_at on the gateway's clock.
    assert.deepEqual(await openHandle(V.iphoneHandle, [gatewayKey], V.handleExpiresAt + 1), {
      ok: false,
      code: "handle_expired",
    });
    assert.equal((await openHandle(V.iphoneHandle, [gatewayKey], V.handleExpiresAt)).ok, true);
    // The proof with `at` 1790000101, and with the watch secret.
    const iphone = decodeB64u(V.iphoneSecret)!;
    const watch = decodeB64u(V.watchSecret)!;
    assert.equal(await proofMatches(iphone, proofMessage(V.iphoneHandle, V.at + 1, V.expiresAt, V.collapseId), V.iphoneProof), false);
    assert.equal(await proofMatches(watch, proofMessage(V.iphoneHandle, V.at, V.expiresAt, V.collapseId), V.iphoneProof), false);
    assert.equal(await proofMatches(iphone, proofMessage(V.iphoneHandle, V.at, V.expiresAt, V.collapseId), V.iphoneProof), true);
  });

  it("refuses handles of another key id, another format, and a wrong length", async () => {
    const gatewayKey = await key();
    const bytes = decodeB64u(V.iphoneHandle)!;
    const otherId = bytes.slice();
    otherId[1] = 2;
    assert.deepEqual(await openHandle(encodeB64u(otherId), [gatewayKey], V.at), { ok: false, code: "handle_invalid" });
    const otherFormat = bytes.slice();
    otherFormat[0] = 2;
    assert.deepEqual(await openHandle(encodeB64u(otherFormat), [gatewayKey], V.at), { ok: false, code: "handle_invalid" });
    assert.deepEqual(await openHandle(encodeB64u(bytes.subarray(0, 29)), [gatewayKey], V.at), {
      ok: false,
      code: "handle_invalid",
    });
    assert.deepEqual(await openHandle(encodeB64u(new Uint8Array(1025).fill(1)), [gatewayKey], V.at), {
      ok: false,
      code: "handle_invalid",
    });
    // A cut handle: the tag is gone.
    assert.deepEqual(await openHandle(V.iphoneHandle.slice(0, -8), [gatewayKey], V.at), {
      ok: false,
      code: "handle_invalid",
    });
    // Not canonical b64u: the last character has padding bits set.
    assert.equal(decodeB64u("AB"), undefined);
    assert.deepEqual(decodeB64u("AA"), new Uint8Array([0]));
  });

  it("the previous key opens the handles made under it", async () => {
    const previous = await importGatewayKey(V.gatewayKey, "1");
    const current = await importGatewayKey(encodeB64u(range(0xa0, 0xbf)), "2");
    assert.equal((await openHandle(V.iphoneHandle, [current!, previous!], V.at)).ok, true);
    assert.equal((await openHandle(V.iphoneHandle, [current!], V.at)).ok, false);
  });

  it("refuses keys out of form", async () => {
    assert.equal(await importGatewayKey(V.gatewayKey, "0"), undefined);
    assert.equal(await importGatewayKey(V.gatewayKey, "256"), undefined);
    assert.equal(await importGatewayKey(V.gatewayKey, "01"), undefined);
    assert.equal(await importGatewayKey(V.gatewayKey.slice(0, 42), "1"), undefined);
    assert.equal(await importGatewayKey(undefined, "1"), undefined);
    assert.ok(await importGatewayKey(V.gatewayKey, "255"));
  });
});

describe("strict JSON", () => {
  it("parses flat objects of strings and integers", () => {
    const flat = parseFlat(' {"a":"x\\u0041","b":12, "c" : 0 } ');
    assert.deepEqual([...flat!.entries()], [["a", "xA"], ["b", 12], ["c", 0]]);
    assert.deepEqual([...parseFlat("{}")!.entries()], []);
  });

  it("refuses repeated fields, nested values, and other literals", () => {
    for (const text of [
      '{"a":1,"a":2}',
      '{"a":{"b":1}}',
      '{"a":[1]}',
      '{"a":true}',
      '{"a":null}',
      '{"a":1.0}',
      '{"a":1e3}',
      '{"a":-1}',
      '{"a":01}',
      '{"a":1,}',
      '{"a":1} x',
      '{"a":"\u0001"}',
      "",
      "[]",
    ]) {
      assert.equal(parseFlat(text), undefined, text);
    }
  });
});
