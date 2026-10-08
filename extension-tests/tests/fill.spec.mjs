import fs from "node:fs";
import path from "node:path";
import { test, expect, EXTENSION_DIR, LOGINS, PASSWORD, USERNAME } from "../support/fixtures.mjs";

// Asks for the state of the page, then fills the first login, as the popup does.
async function fillFirst(h, item = 7) {
  const state = await h.handle({ type: "state" });
  expect(state.state).toBe("list");
  const reply = await h.handle({ type: "fill", tabId: state.tabId, url: state.url, item });
  expect(JSON.stringify(reply)).not.toContain(PASSWORD);
  expect(JSON.stringify(reply)).not.toContain(USERNAME);
  return { state, reply };
}

const values = (page, ids) => page.evaluate((list) => Object.fromEntries(list.map((id) => [id, document.getElementById(id).value])), ids);

test("a fill on a plain form fills the username and the password", async ({ h }) => {
  const page = await h.openGranted("/login");
  const { reply } = await fillFirst(h);
  expect(reply).toEqual({ ok: true, code: "ok", message: "Filled.", filled: { username: true, password: true } });
  expect(await values(page, ["username", "password", "search", "trap", "newsletter"])).toEqual({
    username: USERNAME, password: PASSWORD, search: "", trap: "", newsletter: "",
  });
  expect(h.requests("fill")).toEqual([{ v: 1, cmd: "fill", url: page.url(), item: 7 }]);
  expect(await page.evaluate(() => document.activeElement.id)).toBe("password");
});

test("a controlled (React-style) form takes the values into its state", async ({ h }) => {
  const page = await h.openGranted("/react");
  const { reply } = await fillFirst(h);
  expect(reply.ok).toBe(true);
  // The page puts its state back into the fields after a focus. The values
  // stay only when the page state took them.
  await page.waitForTimeout(50);
  expect(await page.evaluate(() => ({ ...window.appState }))).toEqual({ email: USERNAME, pass: PASSWORD });
  expect(await values(page, ["username", "password"])).toEqual({ username: USERNAME, password: PASSWORD });
});

test("a first step with only a username field gets the username", async ({ h }) => {
  const page = await h.openGranted("/step1");
  const { reply } = await fillFirst(h);
  expect(reply.filled).toEqual({ username: true, password: false });
  expect(await values(page, ["username", "search"])).toEqual({ username: USERNAME, search: "" });
});

test("a form in an open shadow root is filled", async ({ h }) => {
  const page = await h.openGranted("/shadow");
  const { reply } = await fillFirst(h);
  expect(reply.filled).toEqual({ username: true, password: true });
  expect(await page.evaluate(() => {
    const root = document.getElementById("box").shadowRoot;
    return { username: root.getElementById("username").value, password: root.getElementById("password").value };
  })).toEqual({ username: USERNAME, password: PASSWORD });
});

test("the current-password field wins over a new-password field", async ({ h }) => {
  const page = await h.openGranted("/new-and-current");
  const { reply } = await fillFirst(h);
  expect(reply.ok).toBe(true);
  expect(await values(page, ["username", "password", "join-email", "new-password"])).toEqual({
    username: USERNAME, password: PASSWORD, "join-email": "", "new-password": "",
  });
});

test("a page that goes to another origin during the owner check gets nothing", async ({ h }) => {
  const page = await h.openGranted("/login");
  const state = await h.handle({ type: "state" });
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { delayMs: 1500 } });
  const pending = h.handle({ type: "fill", tabId: state.tabId, url: state.url, item: 7 });
  // The owner check waits; meanwhile the tab goes to another origin.
  await expect.poll(() => h.requests("fill").length).toBe(1);
  const otherUrl = h.url("/login", "localhost");
  await page.evaluate((url) => { location.href = url; }, otherUrl);
  await page.waitForURL(otherUrl);
  const reply = await pending;
  expect(reply).toEqual({ ok: false, code: "page_changed", message: "The page changed. Nothing was filled." });
  expect(h.requests("fill")).toEqual([{ v: 1, cmd: "fill", url: state.url, item: 7 }]);
  await page.waitForTimeout(100);
  expect(await values(page, ["username", "password"])).toEqual({ username: "", password: "" });
});

test("an answer for another origin than the tab fills nothing", async ({ h }) => {
  const page = await h.openGranted("/login");
  const other = `http://localhost:${h.server.port}`;
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { origin: other } });
  const { reply } = await fillFirst(h);
  expect(reply.code).toBe("page_changed");
  expect(await values(page, ["username", "password"])).toEqual({ username: "", password: "" });
});

test("the fill function itself refuses a frame of another origin", async ({ h }) => {
  const page = await h.openGranted("/login");
  const source = fs.readFileSync(path.join(EXTENSION_DIR, "fill.js"), "utf8");
  const result = await page.evaluate(([code, origin]) => {
    const fillLogin = new Function(`${code}; return fillLogin;`)();
    return fillLogin(origin, "user", "secret");
  }, [source, `http://localhost:${h.server.port}`]);
  expect(result).toEqual({ ok: false, reason: "origin", username: false, password: false });
  expect(await values(page, ["username", "password"])).toEqual({ username: "", password: "" });
});

test("a cancelled owner check fills nothing", async ({ h }) => {
  const page = await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { code: "cancelled" } });
  const { reply } = await fillFirst(h);
  expect(reply.ok).toBe(false);
  expect(reply.code).toBe("cancelled");
  expect(reply.message).toBe("The fill was cancelled. Nothing was filled.");
  expect(await values(page, ["username", "password"])).toEqual({ username: "", password: "" });
  expect(h.requests("fill")).toHaveLength(1);
});

test("busy and no_match come back as the message of the app", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { code: "busy" } });
  expect((await fillFirst(h)).reply.code).toBe("busy");
  h.setScenario({ vault: "unlocked", logins: LOGINS });
  const state = await h.handle({ type: "state" });
  const reply = await h.handle({ type: "fill", tabId: state.tabId, url: state.url, item: 9 });
  expect(reply.code).toBe("no_match");
});

test("a failed fill with the popup closed shows a badge for a short time", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { code: "cancelled" } });
  await fillFirst(h);
  expect(await h.badge()).toEqual({ text: "!", title: "Apassy: The fill was cancelled. Nothing was filled." });
  await expect.poll(() => h.badge(), { timeout: 13_000, intervals: [1_000] })
    .toEqual({ text: "", title: "Apassy" });
});

test("a page without login fields reports it", async ({ h }) => {
  await h.openGranted("/blank");
  const { reply } = await fillFirst(h);
  expect(reply).toEqual({ ok: false, code: "no_fields", message: "Apassy found no login fields on this page." });
});

test("no reply of the background holds a secret value", async ({ h }) => {
  await h.openGranted("/login");
  const replies = [];
  replies.push(await h.handle({ type: "state" }));
  const { state } = replies[0];
  for (const item of [7, 8]) {
    replies.push(await h.handle({ type: "fill", tabId: replies[0].tabId, url: replies[0].url, item }));
  }
  replies.push(await h.handle({ type: "show" }));
  const text = JSON.stringify(replies);
  expect(text).not.toContain(PASSWORD);
  expect(text).not.toContain("second-secret-value");
  expect(replies[1].ok).toBe(true);
  expect(state).toBe("list");
});
