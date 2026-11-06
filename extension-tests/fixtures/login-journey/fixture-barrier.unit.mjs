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

test("answer barrier keeps exact downstream commands despite late popup continuation", async (t) => {
  const output = t.mock.method(console, "error", () => {});
  const result = await interleave(grantWithStoppedHost);
  assert.deepEqual(result.commands, ["status", "logins"]);
  assert.equal(result.downstream.state, "empty");
  assert.equal(result.toolbar.state, "not_running");
  assert.equal(output.mock.callCount(), 0);
});

for (const answer of [null, { ok: true, code: "ok" }, { ok: false, code: "host_failed" }]) {
  test(`missing or wrong status acknowledgement fails closed: ${answer?.code || "missing"}`, async (t) => {
    t.mock.method(console, "error", () => {});
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

for (const mode of ["timeout", "wrong_ack", "partial_requests", "partial_answers", "malformed_answer"]) {
  test(`barrier failure metadata is private and keeps stopped evidence: ${mode}`, async (t) => {
    const lines = [];
    t.mock.method(console, "error", (...args) => lines.push(args.join(" ")));
    const canary = "RAW_REQUEST_ANSWER_CODE_CAUGHT_EXCEPTION";
    const readError = new SyntaxError(canary);
    let scenario = { secret: canary }, clears = 0, closes = 0, polls = 0, waits = 0;
    const answers = [
      { ok: false, code: "not_running", secret: canary },
      { ok: true, code: "ok" }, { ok: false, code: "host_failed" },
      { ok: false, code: "timeout" }, { ok: false, code: canary },
    ];
    const h = {
      scenario: () => scenario,
      setScenario: (value) => { scenario = value; },
      clearRequests: () => { clears++; },
      requests: (cmd) => {
        assert.equal(cmd, "status");
        if (mode === "partial_requests") throw readError;
        return [{ cmd, raw: canary }, { cmd, raw: canary }];
      },
      answers: (cmd) => {
        assert.equal(cmd, "status");
        polls++;
        if (mode === "partial_answers") throw readError;
        if (mode === "malformed_answer") return [null];
        return mode === "wrong_ack" ? answers : [];
      },
      closeRealPopup: async () => { closes++; },
    };
    await assert.rejects(grantWithStoppedHost(h, async () => {}, {
      attempts: 2, wait: async (ms) => { assert.equal(ms, 20); waits++; },
    }), (error) => mode === "partial_answers" ? error === readError :
      mode === "malformed_answer" ? error instanceof TypeError :
      error.message === (mode === "wrong_ack" ? "toolbar setup status did not acknowledge not_running" : "toolbar setup status answer did not arrive"));
    assert.deepEqual(scenario, { notRunning: true });
    assert.equal(clears, 1);
    assert.equal(closes, 0);
    assert.equal(polls, ["wrong_ack", "partial_answers", "malformed_answer"].includes(mode) ? 1 : 2);
    assert.equal(waits, ["timeout", "partial_requests"].includes(mode) ? 2 : 0);
    assert.equal(lines.length, 1);
    assert.ok(lines[0].startsWith("[fixture-barrier] "));
    assert.ok(!lines[0].includes(canary));
    assert.ok(lines[0].length < 400);
    const record = JSON.parse(lines[0].slice("[fixture-barrier] ".length));
    assert.deepEqual(Object.keys(record).sort(), ["codes", "elapsedMs", "reason", "statusAnswers", "statusRequests"]);
    assert.ok(Number.isInteger(record.elapsedMs) && record.elapsedMs >= 0);
    assert.equal(record.statusRequests, mode === "partial_requests" ? "unreadable" : 2);
    if (["partial_answers", "malformed_answer"].includes(mode)) {
      assert.equal(record.statusAnswers, "unreadable");
      assert.equal(record.codes, "unreadable");
      assert.equal(record.reason, "unreadable");
    } else {
      assert.equal(record.reason, mode === "wrong_ack" ? "wrong_ack" : "timeout");
      assert.equal(record.statusAnswers, mode === "wrong_ack" ? 5 : 0);
      assert.deepEqual(record.codes, mode === "wrong_ack"
        ? { not_running: 1, ok: 1, host_failed: 1, timeout: 1, other: 1 }
        : { not_running: 0, ok: 0, host_failed: 0, timeout: 0, other: 0 });
    }
  });
}

test("a broken diagnostic sink cannot replace the original barrier timeout", async (t) => {
  t.mock.method(console, "error", () => { throw new Error("private sink error"); });
  const h = {
    scenario: () => ({}), setScenario: () => {}, clearRequests: () => {},
    answers: () => [], requests: () => [],
    closeRealPopup: async () => assert.fail("must retain stopped scenario"),
  };
  await assert.rejects(grantWithStoppedHost(h, async () => {}, { attempts: 1, wait: async () => {} }),
    { message: "toolbar setup status answer did not arrive" });
});
