import fs from "node:fs";
import path from "node:path";
import { test, expect, EXTENSION_DIR, LOGINS, NEW_PASSWORD } from "../support/fixtures.mjs";

// "New password": create in the service worker, and the "new" mode of the
// fill function.

const FILLED = "Filled. The new login is in Apassy. Submit the form on the page.";
const SIGNUP_FIELDS = ["email", "new-password", "confirm-password", "search", "newsletter"];
const EMPTY_SIGNUP = { email: "", "new-password": "", "confirm-password": "", search: "", newsletter: "" };

const values = (page, ids) => page.evaluate((list) => Object.fromEntries(list.map((id) => [id, document.getElementById(id).value])), ids);

async function onPage(h, pathname, create = {}) {
  const page = await h.openGranted(pathname);
  h.setScenario({ vault: "unlocked", logins: LOGINS, create: { password: NEW_PASSWORD, ...create } });
  const state = await h.handle({ type: "state" });
  expect(state.state).toBe("list");
  h.clearRequests();
  return { page, state };
}

const request = (state, fields = {}) => ({
  type: "create", tabId: state.tabId, url: state.url,
  title: "Sign-up test", username: "new@example.com", length: 24, symbols: false, ...fields,
});

// Runs a page function of fill.js in the page itself (main world), as the
// existing fill test does.
function pageFunction(page, name, args) {
  const source = fs.readFileSync(path.join(EXTENSION_DIR, "fill.js"), "utf8");
  return page.evaluate(([code, fn, list]) => new Function(`${code}; return ${fn};`)()(...list), [source, name, args]);
}

test("create sends one request and fills the username and both new password fields", async ({ h }) => {
  const { page, state } = await onPage(h, "/signup");
  const reply = await h.handle(request(state, { title: " Sign-up test ", username: " new@example.com " }));
  expect(reply).toEqual({
    ok: true, code: "ok", message: FILLED, item: 13, filled: { username: true, passwords: 2 },
  });
  expect(JSON.stringify(reply)).not.toContain(NEW_PASSWORD);
  expect(h.requests()).toEqual([{
    v: 1, cmd: "create", url: page.url(), title: "Sign-up test", username: "new@example.com", length: 24, symbols: false,
  }]);
  expect(await values(page, SIGNUP_FIELDS)).toEqual({
    ...EMPTY_SIGNUP, email: "new@example.com", "new-password": NEW_PASSWORD, "confirm-password": NEW_PASSWORD,
  });
});

test("a page that goes to another origin during the owner check gets nothing", async ({ h }) => {
  const { page, state } = await onPage(h, "/signup", { delayMs: 1500 });
  const pending = h.handle(request(state, { symbols: true, length: 64 }));
  await expect.poll(() => h.requests("create").length).toBe(1);
  const otherUrl = h.url("/signup", "localhost");
  await page.evaluate((url) => { location.href = url; }, otherUrl);
  await page.waitForURL(otherUrl);
  const reply = await pending;
  expect(reply).toEqual({
    ok: false, code: "page_changed", message: "The page changed. Nothing was filled. The new login is in Apassy.", item: 13,
  });
  expect(h.requests()).toEqual([{
    v: 1, cmd: "create", url: state.url, title: "Sign-up test", username: "new@example.com", length: 64, symbols: true,
  }]);
  await page.waitForTimeout(100);
  expect(await values(page, SIGNUP_FIELDS)).toEqual(EMPTY_SIGNUP);
});

test("an answer for another origin than the tab fills nothing", async ({ h }) => {
  const { page, state } = await onPage(h, "/signup", { origin: `http://localhost:${h.server.port}` });
  const reply = await h.handle(request(state));
  expect(reply.code).toBe("page_changed");
  expect(await values(page, SIGNUP_FIELDS)).toEqual(EMPTY_SIGNUP);
});

test("a cancelled owner check fills nothing", async ({ h }) => {
  const { page, state } = await onPage(h, "/signup", { code: "cancelled" });
  const reply = await h.handle(request(state));
  expect(reply).toEqual({ ok: false, code: "cancelled", message: "The fill was cancelled. Nothing was filled." });
  expect(await values(page, SIGNUP_FIELDS)).toEqual(EMPTY_SIGNUP);
  expect(h.requests("create")).toHaveLength(1);
});

test("a page with only a current-password field gets no new password", async ({ h }) => {
  const { page, state } = await onPage(h, "/login");
  const reply = await h.handle(request(state));
  expect(reply).toEqual({
    ok: false, code: "no_fields", message: "Apassy found no field for a new password. The new login is in Apassy.", item: 13,
  });
  expect(JSON.stringify(reply)).not.toContain(NEW_PASSWORD);
  expect(await values(page, ["username", "password", "search"])).toEqual({ username: "", password: "", search: "" });
});

test("create with a bad length, symbols, title, or username is bad_request", async ({ h }) => {
  const { state } = await onPage(h, "/signup");
  for (const fields of [
    { length: 11 }, { length: 65 }, { length: 20.5 }, { length: "20" },
    { symbols: undefined }, { symbols: "yes" }, { title: "" }, { username: "  " },
  ]) {
    expect(await h.handle(request(state, fields)), JSON.stringify(fields)).toEqual({
      ok: false, code: "bad_request", message: "Apassy did not understand the request.",
    });
  }
  expect(h.requests()).toEqual([]);
});

test("fillLogin in new mode fills nothing on a page with only a current-password field", async ({ h }) => {
  const page = await h.openGranted("/login");
  const result = await pageFunction(page, "fillLogin", [new URL(page.url()).origin, "user", "secret", "new"]);
  expect(result).toEqual({ ok: false, reason: "no_fields", username: false, password: false, passwords: 0 });
  expect(await values(page, ["username", "password", "search"])).toEqual({ username: "", password: "", search: "" });
});

test("fillLogin in new mode fills the join form, not the sign-in form", async ({ h }) => {
  const page = await h.openGranted("/new-and-current");
  const result = await pageFunction(page, "fillLogin", [new URL(page.url()).origin, "user", "secret", "new"]);
  expect(result).toEqual({ ok: true, reason: "", username: true, password: true, passwords: 1 });
  expect(await values(page, ["join-email", "new-password", "username", "password"])).toEqual({
    "join-email": "user", "new-password": "secret", username: "", password: "",
  });
});

test("readLogin refuses another origin and returns the password only when asked", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#username", "typed-user");
  await page.fill("#password", "typed-secret");
  const origin = new URL(page.url()).origin;
  expect(await pageFunction(page, "readLogin", [`http://localhost:${h.server.port}`, true])).toEqual({
    ok: false, reason: "origin", username: "", hasPassword: false, passwordFields: 0, newPasswordFields: 0,
  });
  const without = await pageFunction(page, "readLogin", [origin, false]);
  expect(without).toEqual({
    ok: true, reason: "", username: "typed-user", hasPassword: true, passwordFields: 1, newPasswordFields: 1,
  });
  expect(JSON.stringify(without)).not.toContain("typed-secret");
  expect((await pageFunction(page, "readLogin", [origin, true])).password).toBe("typed-secret");
});
