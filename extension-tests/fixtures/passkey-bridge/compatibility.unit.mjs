// Source-level wire tests; no native app, browser, or live vault.
import assert from 'node:assert/strict';
import { flush, loadBackground, senderFor } from './mock-chrome.mjs';
import { test } from 'node:test';

function harness(version, ok = true) {
  const bg = loadBackground();
  const sent = [];
  bg.setHost((wire, record) => {
    sent.push(JSON.parse(JSON.stringify(wire)));
    // Simulate 0.5.7's deny_unknown_fields parsing at the receiving side.
    const unknownField = version === '0.5.7' && Object.hasOwn(wire, 'trusted_gesture');
    record.port.postMessage(wire.cmd === 'status'
      ? { ok, data: { type: 'status', version } }
      : { ok: !unknownField, code: unknownField ? 'bad_request' : 'ok', data: { type: 'none' } });
  });
  return { sent, ask: (wire) => bg.context.ask(wire), adapt: (wire) => bg.context.compatibleGestureRequest(wire) };
}
for (const cmd of ['fill', 'save', 'create', 'fill_code', 'passkey_get']) {
  test(`new extension / 0.5.7 app: ${cmd} omits unknown gesture field`, async () => {
    const h = harness('0.5.7');
    assert.equal((await h.ask({ cmd, trusted_gesture: true })).ok, true);
    assert.deepEqual(h.sent.map((w) => w.cmd), ['status', cmd]);
    assert.equal(Object.hasOwn(h.sent[1], 'trusted_gesture'), false);
  });
  test(`new extension / 0.5.8 app: ${cmd} retains trusted gesture`, async () => {
    const h = harness('0.5.8');
    assert.equal((await h.ask({ cmd, trusted_gesture: true })).ok, true);
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
for (const version of ['0.5.7', '0.5.8']) {
  test(`actual passkey port negotiates gesture with app ${version}`, async () => {
    const bg = loadBackground();
    const origin = 'https://login.example.com';
    bg.tabs.set(5, `${origin}/login`);
    bg.documents.set('DOC-1', origin);
    const requests = [];
    bg.setHost((wire, record) => {
      requests.push(wire);
      if (wire.cmd === 'status') record.port.postMessage({ ok: true, data: { type: 'status', version } });
    });
    const port = bg.connect(senderFor(origin));
    port.postMessage({ op: 'get', trustedGesture: true, options: {
      challenge: Buffer.alloc(32, 1).toString('base64url'), rpId: 'example.com', allowCredentials: [],
    } });
    await flush();
    assert.deepEqual(requests.map((r) => r.cmd), ['status', 'passkey_get']);
    const wire = requests[1];
    assert.equal(Object.hasOwn(wire, 'trusted_gesture'), version === '0.5.8');
    if (version === '0.5.8') assert.equal(wire.trusted_gesture, true);
    port.disconnect();
    await flush();
  });
}
