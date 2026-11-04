import assert from "node:assert/strict";
import { test } from "node:test";
import { grantWithStoppedHost } from "../../support/fixture-barrier.mjs";
import { loadBackground } from "../passkey-bridge/mock-chrome.mjs";

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

// Execute the real background state handler. Explicit gates stand in for the
// OS scheduling gap between mock-host log(request) and queue.then(answer).
// No timers decide the interleaving. Native delivery stays held even after the
// answer log, exercising a popup handler that resumes after fixture cleanup.
async function interleave(grant) {
  const bg = loadBackground();
  const url = "http://127.0.0.1/login";
  bg.tabs.set(5, url);
  const logged = deferred();
  let scenario = { vault: "unlocked" };
  let requests = [], answers = [], pending, deliver, popup;
  let closed = false, delivered = false, snapshots = 0;
  const snapshotAndWrite = () => {
    assert.equal(snapshots++, 0);
    const reply = scenario.notRunning
      ? { ok: false, code: "not_running", data: { type: "none" } }
      : { ok: true, code: "ok", data: { type: "status", vault: "unlocked" } };
    // mock-host writes the native frame, then logs the answer. Delivery of
    // that frame to the background can happen later, independently.
    deliver = () => pending.port.postMessage(reply);
    answers.push({ cmd: "status", ok: reply.ok, code: reply.code });
  };
  bg.setHost((request, record) => {
    requests.push(request);
    if (!pending) {
      assert.equal(request.cmd, "status");
      pending = record;
      logged.resolve();
      return;
    }
    // In the old fixture the queued toolbar status first reads the restored
    // scenario while the downstream state call is already in progress.
    if (!deliver) snapshotAndWrite();
    if (request.cmd === "logins") {
      if (!delivered) { delivered = true; deliver(); }
      record.port.postMessage({ ok: true, data: { type: "logins", origin: new URL(url).origin, logins: [] } });
    } else {
      assert.equal(request.cmd, "status");
      record.port.postMessage({ ok: true, data: { type: "status", vault: "unlocked" } });
    }
  });
  const h = {
    scenario: () => structuredClone(scenario),
    setScenario: (value) => { scenario = value; },
    clearRequests: () => { requests = []; answers = []; },
    requests: () => requests,
    answers: (cmd) => answers.filter((answer) => answer.cmd === cmd),
    closeRealPopup: async () => { closed = true; },
  };
  await grant(h, async () => {
    popup = bg.handle({ type: "state" });
    await logged.promise;
  }, { wait: async () => {
    assert.equal(closed, false);
    assert.equal(scenario.notRunning, true);
    snapshotAndWrite();
  } });
  assert.equal(closed, true);
  assert.deepEqual(scenario, { vault: "unlocked" });
  const downstream = await bg.handle({ type: "state" });
  const toolbar = await popup;
  return { commands: requests.map((request) => request.cmd), downstream, toolbar };
}

test("request-only boundary reproduces the CI duplicate through the real state handler", async () => {
  const oldGrant = async (h, trigger) => {
    const scenario = h.scenario();
    h.setScenario({ notRunning: true });
    h.clearRequests();
    await trigger();
    assert.equal(h.requests()[0].cmd, "status");
    await h.closeRealPopup();
    h.setScenario(scenario);
    h.clearRequests();
  };
  const result = await interleave(oldGrant);
  assert.deepEqual(result.commands, ["status", "logins", "logins"]);
  assert.equal(result.toolbar.state, "empty");
});

test("answer barrier keeps exact downstream commands despite late popup continuation", async () => {
  const result = await interleave(grantWithStoppedHost);
  assert.deepEqual(result.commands, ["status", "logins"]);
  assert.equal(result.downstream.state, "empty");
  assert.equal(result.toolbar.state, "not_running");
});

for (const answer of [null, { ok: true, code: "ok" }, { ok: false, code: "host_failed" }]) {
  test(`missing or wrong status acknowledgement fails closed: ${answer?.code || "missing"}`, async () => {
    let scenario = { vault: "unlocked" }, clears = 0, closed = false;
    const h = {
      scenario: () => scenario,
      setScenario: (value) => { scenario = value; },
      clearRequests: () => { clears++; },
      answers: () => answer ? [answer] : [],
      closeRealPopup: async () => { closed = true; },
    };
    await assert.rejects(grantWithStoppedHost(h, async () => {}, {
      attempts: 2, wait: async () => {},
    }), /toolbar setup status/);
    assert.deepEqual(scenario, { notRunning: true });
    assert.equal(clears, 1);
    assert.equal(closed, false);
  });
}
