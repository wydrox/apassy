// Harness navigation checks only: no Playwright import or browser process.
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { goto, warmUpHelium } from "../../support/helium.mjs";

test("navigation retries ERR_ABORTED, but propagates other failures", async () => {
  let attempts = 0;
  const response = {};
  assert.equal(await goto({ goto: async () => {
    if (++attempts === 1) throw new Error("page.goto: net::ERR_ABORTED");
    return response;
  } }, "http://localhost/blank"), response);
  assert.equal(attempts, 2);
  const refused = new Error("page.goto: net::ERR_CONNECTION_REFUSED");
  await assert.rejects(goto({ goto: async () => { throw refused; } }, "http://localhost/blank"), (error) => error === refused);
});

test("an interrupted navigation is bounded to three attempts", async () => {
  let attempts = 0;
  await assert.rejects(goto({ goto: async () => {
    attempts++;
    throw new Error("page.goto: net::ERR_ABORTED");
  } }, "http://localhost/blank"), /ERR_ABORTED/);
  assert.equal(attempts, 3);
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
