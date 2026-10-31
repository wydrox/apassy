// Source-level wire tests; no native app, browser, or live vault.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = readFileSync(new URL('../../../extension/background.js', import.meta.url), 'utf8');
const transport = source.slice(source.indexOf('function supportsTrustedGesture'), source.indexOf('function localError'));
function harness(version, ok = true) {
  const sent = [];
  const context = vm.createContext({
    HOST: 'mock', WIRE_VERSION: 1, ANSWER_TIMEOUT_MS: 250000,
    setTimeout, clearTimeout, localError: (code) => ({ ok: false, code }),
    chrome: { runtime: { connectNative() {
      let answer;
      return {
        onMessage: { addListener(fn) { answer = fn; } },
        onDisconnect: { addListener() {} }, disconnect() {},
        postMessage(wire) {
          sent.push(JSON.parse(JSON.stringify(wire)));
          queueMicrotask(() => answer(wire.cmd === 'status'
            ? { ok, data: { type: 'status', version } }
            : { ok: true, data: { type: 'none' } }));
        },
      };
    } } },
  });
  vm.runInContext(transport, context);
  return { sent, ask: (wire) => context.ask(wire), adapt: (wire) => context.compatibleGestureRequest(wire) };
}
for (const cmd of ['fill', 'save', 'create', 'fill_code', 'passkey_get']) {
  test(`new extension / 0.5.7 app: ${cmd} omits unknown gesture field`, async () => {
    const h = harness('0.5.7');
    await h.ask({ cmd, trusted_gesture: true });
    assert.deepEqual(h.sent.map((w) => w.cmd), ['status', cmd]);
    assert.equal(Object.hasOwn(h.sent[1], 'trusted_gesture'), false);
  });
  test(`new extension / 0.5.8 app: ${cmd} retains trusted gesture`, async () => {
    const h = harness('0.5.8');
    await h.ask({ cmd, trusted_gesture: true });
    assert.equal(h.sent[1].trusted_gesture, true);
    assert.equal(Object.hasOwn(h.sent[1], 'owner_window_host'), false);
  });
}
test('old extension / new app wire stays flag-free for fresh authentication', async () => {
  const h = harness('0.5.8');
  await h.ask({ cmd: 'fill', item: 7 });
  assert.deepEqual(h.sent, [{ v: 1, cmd: 'fill', item: 7 }]);
});
test('untrusted gesture is never upgraded, including on new app', async () => {
  const h = harness('0.5.8');
  await h.ask({ cmd: 'fill', trusted_gesture: false });
  assert.equal(h.sent[1].trusted_gesture, false);
});
for (const version of [undefined, '', '0.5.8-beta', 'garbage', '0.4.99']) {
  test(`unknown/unsupported version ${version} falls back to fresh checks`, async () => {
    const h = harness(version);
    assert.equal(Object.hasOwn(await h.adapt({ cmd: 'passkey_get', trusted_gesture: true }), 'trusted_gesture'), false);
  });
}
test('failed status never enables window reuse', async () => {
  const h = harness('0.5.8', false);
  assert.equal(Object.hasOwn(await h.adapt({ cmd: 'fill', trusted_gesture: true }), 'trusted_gesture'), false);
});
test('passkey native path uses negotiated request', () => {
  assert.match(source, /const compatibleWire = await compatibleGestureRequest\(wire\)/);
  assert.match(source, /native\.postMessage\(compatibleWire\)/);
});
