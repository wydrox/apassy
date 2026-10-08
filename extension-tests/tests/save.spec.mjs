import { test, expect, LOGINS, TYPED_PASSWORD } from "../support/fixtures.mjs";

// "Save this login": peek and save in the service worker.

async function onPage(h, pathname) {
  const page = await h.openGranted(pathname);
  const state = await h.handle({ type: "state" });
  expect(state.state).toBe("list");
  h.clearRequests();
  return { page, state };
}

async function typeLogin(page, username, password) {
  await page.fill("#username", username);
  if (password) await page.fill("#password", password);
}

test("peek returns the typed username and whether a password is typed, never the password", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  const reply = await h.handle({ type: "peek", tabId: state.tabId, url: state.url });
  expect(reply).toEqual({
    ok: true, code: "ok", message: "", username: "typed-user", hasPassword: true,
    passwordFields: 1, newPasswordFields: 1,
  });
  expect(JSON.stringify(reply)).not.toContain(TYPED_PASSWORD);
  // A peek asks nothing of the app.
  expect(h.requests()).toEqual([]);
});

test("peek counts the password fields and the new password fields", async ({ h }) => {
  let { state } = await onPage(h, "/login");
  expect(await h.handle({ type: "peek", tabId: state.tabId, url: state.url })).toEqual({
    ok: true, code: "ok", message: "", username: "", hasPassword: false,
    passwordFields: 1, newPasswordFields: 0,
  });
  ({ state } = await onPage(h, "/signup"));
  expect(await h.handle({ type: "peek", tabId: state.tabId, url: state.url })).toEqual({
    ok: true, code: "ok", message: "", username: "", hasPassword: false,
    passwordFields: 2, newPasswordFields: 2,
  });
});

test("save sends one save request with the typed password and the fresh address of the tab", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  // The page changes its address on the same origin before the save.
  const fresh = `${state.url}&step=2`;
  await page.evaluate((url) => history.pushState(null, "", url), fresh);
  const worker = await h.worker();
  await expect.poll(() => worker.evaluate((id) => chrome.tabs.get(id).then((t) => t.url), state.tabId)).toBe(fresh);

  const reply = await h.handle({
    type: "save", tabId: state.tabId, url: state.url, title: "  Typed site ", username: " typed-user ",
  });
  expect(reply).toEqual({ ok: true, code: "ok", message: "Saved.", item: 12 });
  expect(JSON.stringify(reply)).not.toContain(TYPED_PASSWORD);
  expect(h.requests()).toEqual([{
    v: 1, cmd: "save", url: fresh, title: "Typed site", username: "typed-user", password: TYPED_PASSWORD,
  }]);
});

test("exists and cancelled come back as the message of the app", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  const save = { type: "save", tabId: state.tabId, url: state.url, title: "Typed site", username: "typed-user" };

  const exists = 'The login "Local test" (typed-user) is already in Apassy for this page. Nothing was saved.';
  h.setScenario({ vault: "unlocked", logins: LOGINS, save: { code: "exists", message: exists } });
  const first = await h.handle(save);
  expect(first).toEqual({ ok: false, code: "exists", message: exists });

  const cancelled = "The save was cancelled. Nothing was saved.";
  h.setScenario({ vault: "unlocked", logins: LOGINS, save: { code: "cancelled", message: cancelled } });
  const second = await h.handle(save);
  expect(second).toEqual({ ok: false, code: "cancelled", message: cancelled });

  expect(JSON.stringify([first, second])).not.toContain(TYPED_PASSWORD);
  expect(h.requests("save")).toHaveLength(2);
});

test("a save without a typed password is no_password and asks nothing", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user");
  const reply = await h.handle({ type: "save", tabId: state.tabId, url: state.url, title: "Typed site", username: "typed-user" });
  expect(reply).toEqual({ ok: false, code: "no_password", message: "Type your password on the page first." });
  expect(h.requests()).toEqual([]);
});

test("a save for a tab that went to another origin reads nothing and asks nothing", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  const otherUrl = h.url("/typed", "localhost");
  await page.goto(otherUrl);
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  const reply = await h.handle({ type: "save", tabId: state.tabId, url: state.url, title: "Typed site", username: "typed-user" });
  expect(reply).toEqual({ ok: false, code: "page_changed", message: "The page changed. Nothing was saved." });
  const peek = await h.handle({ type: "peek", tabId: state.tabId, url: state.url });
  expect(peek.code).toBe("page_changed");
  expect(h.requests()).toEqual([]);
});

test("a save or a peek with bad fields is bad_request", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  const base = { type: "save", tabId: state.tabId, url: state.url, title: "Typed site", username: "typed-user" };
  for (const message of [
    { ...base, title: "   " },
    { ...base, username: "" },
    { ...base, username: undefined },
    { ...base, title: "x".repeat(129) },
    { ...base, tabId: String(state.tabId) },
    { type: "peek", tabId: state.tabId },
  ]) {
    expect(await h.handle(message), JSON.stringify(message)).toEqual({
      ok: false, code: "bad_request", message: "Apassy did not understand the request.",
    });
  }
  expect(h.requests()).toEqual([]);
});

test("a failed save with the popup closed shows a badge", async ({ h }) => {
  const { page, state } = await onPage(h, "/typed");
  await typeLogin(page, "typed-user", TYPED_PASSWORD);
  h.setScenario({ vault: "unlocked", logins: LOGINS, save: { code: "cancelled", message: "The save was cancelled." } });
  await h.handle({ type: "save", tabId: state.tabId, url: state.url, title: "Typed site", username: "typed-user" });
  expect(await h.badge()).toEqual({ text: "!", title: "Apassy: The save was cancelled." });
});
