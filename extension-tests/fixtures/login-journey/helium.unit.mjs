// Harness navigation checks only: no Playwright import or browser process.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { goto, warmUpHelium } from "../../support/helium.mjs";

const fakePage = (navigate) => Object.assign(new EventEmitter(), { goto: navigate });
const capture = (t) => {
  const lines = [];
  t.mock.method(console, "error", (...args) => lines.push(args.join(" ")));
  return lines;
};

test("navigation retries ERR_ABORTED, but propagates other failures", async (t) => {
  const lines = capture(t);
  let attempts = 0;
  const response = {};
  assert.equal(await goto(fakePage(async () => {
    if (++attempts === 1) throw new Error("page.goto: net::ERR_ABORTED");
    return response;
  }), "http://localhost/blank"), response);
  assert.equal(attempts, 2);
  assert.deepEqual(lines, []);
  const refused = new Error("page.goto: net::ERR_CONNECTION_REFUSED");
  await assert.rejects(goto(fakePage(async () => { throw refused; }), "http://localhost/blank"), (error) => error === refused);
  assert.equal(lines.length, 1);
});

test("an interrupted navigation is bounded to three attempts", async (t) => {
  const lines = capture(t);
  let attempts = 0;
  const error = new Error("page.goto: net::ERR_ABORTED");
  await assert.rejects(goto(fakePage(async () => {
    attempts++;
    throw error;
  }), "http://localhost/blank"), /ERR_ABORTED/);
  assert.equal(attempts, 3);
  const record = JSON.parse(lines[0].slice("[fixture-goto] ".length));
  assert.equal(lines.length, 1);
  assert.equal(record.attempt, 3);
  assert.equal(record.errorType, "aborted");
});

test("startup about:blank interruption with Playwright call log retries then succeeds", async (t) => {
  const lines = capture(t);
  const url = "http://127.0.0.1:49339/signup?n=2";
  const error = new Error(`page.goto: Navigation to "${url}" is interrupted by another navigation to "about:blank"\nCall log:\n  - navigating to "${url}", waiting until "load"`);
  let attempts = 0;
  const response = {};
  const page = fakePage(async (...args) => {
    assert.deepEqual(args, [url]);
    if (++attempts === 1) throw error;
    return response;
  });
  const existing = () => {};
  page.on("load", existing);
  assert.equal(await goto(page, url), response);
  assert.equal(attempts, 2);
  assert.deepEqual(lines, []);
  assert.deepEqual(page.eventNames(), ["load"]);
  assert.deepEqual(page.listeners("load"), [existing]);
});

test("mixed startup interruptions share three attempts and preserve the final exception", async (t) => {
  const lines = capture(t);
  const url = "http://127.0.0.1:49339/signup?n=2";
  const errors = [
    new Error("page.goto: net::ERR_ABORTED"),
    new Error(`page.goto: Navigation to "${url}" is interrupted by another navigation to "about:blank"`),
    new Error(`page.goto: Navigation to "${url}" is interrupted by another navigation to "about:blank"`),
  ];
  let attempts = 0;
  const page = fakePage(async () => { throw errors[attempts++]; });
  await assert.rejects(goto(page, url), (caught) => caught === errors[2]);
  assert.equal(attempts, 3);
  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0].slice("[fixture-goto] ".length));
  assert.equal(record.attempt, 3);
  assert.equal(record.errorType, "startup_blank");
  assert.deepEqual(page.eventNames(), []);
});

for (const [label, requested, destination, prefix, name] of [
  ["same-origin destination", "http://localhost/signup", "http://localhost/login"],
  ["other-origin destination", "http://localhost/signup", "https://elsewhere.invalid/"],
  ["blank fragment", "http://localhost/signup", "about:blank#fragment"],
  ["different requested URL", "http://localhost/other", "about:blank"],
  ["arbitrary message", "http://localhost/signup", "about:blank", "unrelated: "],
  ["call-log-only wording", "http://localhost/signup", "about:blank", "page.goto: unrelated failure\n"],
  ["closed target", "http://localhost/signup", "about:blank", "", "TargetClosedError"],
  ["timeout", "http://localhost/signup", "about:blank", "", "TimeoutError"],
]) {
  test(`navigation does not retry ${label}`, async (t) => {
    const lines = capture(t);
    const error = new Error(`${prefix ?? ""}page.goto: Navigation to "${requested}" is interrupted by another navigation to "${destination}"`);
    if (name) error.name = name;
    let attempts = 0;
    const page = fakePage(async () => { attempts++; throw error; });
    await assert.rejects(goto(page, "http://localhost/signup"), (caught) => caught === error);
    assert.equal(attempts, 1);
    assert.equal(lines.length, 1);
    assert.deepEqual(page.eventNames(), []);
  });
}

for (const type of ["success", "target_closed", "timeout", "other", "startup_blank"]) {
  test(`navigation lifecycle is bounded, private, and detached: ${type}`, async (t) => {
    const lines = capture(t);
    const canary = "RAW_EXCEPTION_URL_FIELD_SECRET";
    const error = new Error(type === "target_closed" ? `Target page, context or browser has been closed ${canary}` : canary);
    if (type === "startup_blank") error.message = `page.goto: Navigation to "https://example.invalid/${canary}" is interrupted by another navigation to "about:blank"`;
    if (type === "timeout") error.name = "TimeoutError";
    const expectedAttempts = type === "startup_blank" ? 3 : 1;
    const frame = {}, child = {};
    let attempts = 0;
    const page = fakePage(async (...args) => {
      attempts++;
      assert.deepEqual(args, [`https://example.invalid/${canary}`]);
      page.emit("framenavigated", child);
      for (let i = 0; i < 1000; i++) page.emit("framenavigated", frame);
      page.emit("domcontentloaded");
      page.emit("load");
      if (type === "success") return "response";
      page.emit("crash", { secret: canary });
      page.emit("close");
      throw error;
    });
    page.mainFrame = () => frame;
    const existing = () => {};
    page.on("load", existing);
    if (type === "success") {
      assert.equal(await goto(page, `https://example.invalid/${canary}`), "response");
      assert.deepEqual(lines, []);
    } else {
      await assert.rejects(goto(page, `https://example.invalid/${canary}`), (caught) => caught === error);
      assert.equal(lines.length, 1);
      assert.ok(lines[0].startsWith("[fixture-goto] "));
      assert.ok(!lines[0].includes(canary));
      assert.ok(!lines[0].includes("https://"));
      assert.ok(!lines[0].includes("about:blank"));
      assert.ok(!lines[0].includes(error.message));
      assert.ok(lines[0].length < 600);
      const record = JSON.parse(lines[0].slice("[fixture-goto] ".length));
      assert.equal(record.errorType, type);
      assert.equal(record.attempt, expectedAttempts);
      assert.ok(Number.isInteger(record.elapsedMs) && record.elapsedMs >= 0);
      assert.deepEqual(Object.keys(record).sort(), ["attempt", "elapsedMs", "errorType", "events"]);
      assert.equal(record.events.mainFrameNavigation.count, 1000 * expectedAttempts);
      for (const name of ["domcontentloaded", "load", "close", "crash"]) assert.equal(record.events[name].count, expectedAttempts);
      for (const event of Object.values(record.events)) {
        assert.deepEqual(Object.keys(event).sort(), ["count", "lastMs"]);
        assert.ok(event.lastMs >= 0 && event.lastMs <= record.elapsedMs);
      }
    }
    assert.equal(attempts, expectedAttempts);
    assert.deepEqual(page.eventNames(), ["load"]);
    assert.deepEqual(page.listeners("load"), [existing]);
  });
}

test("failure without lifecycle events records zero counts and null offsets", async (t) => {
  const lines = capture(t);
  const error = new Error("unclassified");
  await assert.rejects(goto(fakePage(async () => { throw error; }), "http://localhost"), (caught) => caught === error);
  const record = JSON.parse(lines[0].slice("[fixture-goto] ".length));
  assert.equal(Object.keys(record.events).length, 5);
  for (const event of Object.values(record.events)) assert.deepEqual(event, { count: 0, lastMs: null });
});

test("a failing diagnostic sink preserves the navigation exception and removes listeners", async (t) => {
  t.mock.method(console, "error", () => { throw new Error("sink unavailable"); });
  const error = new Error("Target closed");
  const page = fakePage(async () => { throw error; });
  await assert.rejects(goto(page, "http://localhost"), (caught) => caught === error);
  assert.deepEqual(page.eventNames(), []);
});

test("warm-up quiet time restarts after a late main-document reload", async () => {
  const page = new EventEmitter();
  const frame = {};
  let reloadedAt, loaded = false;
  page.mainFrame = () => frame;
  page.goto = async () => {};
  page.waitForLoadState = async (state) => { assert.equal(state, "load"); loaded = true; };
  const reload = setTimeout(() => {
    reloadedAt = Date.now();
    page.emit("framenavigated", frame);
  }, 1_000);
  try {
    await warmUpHelium(page, "http://localhost/blank");
    assert.ok(Date.now() - reloadedAt >= 3_000);
    assert.equal(loaded, true);
    assert.equal(page.listenerCount("framenavigated"), 0);
  } finally { clearTimeout(reload); }
});
