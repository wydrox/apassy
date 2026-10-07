import { test, expect, PASSWORD, LOGINS } from "../support/fixtures.mjs";

test("state lists the logins of the page from the app", async ({ h }) => {
  const page = await h.openGranted("/login");
  h.clearRequests();
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("list");
  expect(reply.url).toBe(page.url());
  expect(reply.host).toBe(new URL(page.url()).host);
  expect(reply.origin).toBe(new URL(page.url()).origin);
  expect(reply.logins).toEqual([
    { item: 7, title: "Local test", username: LOGINS[0].username },
    { item: 8, title: "Second account", username: "second@example.com" },
  ]);
  expect(h.requests().map((r) => r.cmd)).toEqual(["status", "logins"]);
  expect(h.requests("logins")[0]).toEqual({ v: 1, cmd: "logins", url: page.url() });
  expect(JSON.stringify(reply)).not.toContain(PASSWORD);
  expect(JSON.stringify(reply)).not.toContain("secret-value");
});

test("state with no login for the page is empty", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: [LOGINS[2]] });
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("empty");
  expect(reply.logins).toEqual([]);
});

test("a locked vault asks to unlock and sends no logins request", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "locked", logins: LOGINS });
  h.clearRequests();
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("vault_locked");
  expect(reply.message).toBe("Unlock Apassy to fill logins.");
  expect(reply.logins).toEqual([]);
  expect(h.requests().map((r) => r.cmd)).toEqual(["status"]);
});

test("no open vault asks to unlock", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "none" });
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("none_open");
});

test("an app that does not run asks to open Apassy", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ notRunning: true });
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("not_running");
  expect(reply.message).toBe("Open Apassy to fill logins.");
});

test("a missing host manifest is host_missing", async ({ h }) => {
  await h.openGranted("/login");
  h.removeHost();
  h.clearRequests();
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("host_missing");
  expect(reply.message).toBe("Apassy is not connected to this browser.");
  expect(h.requests()).toEqual([]);
});

test("a page that the app does not support is unsupported_page", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: LOGINS, loginsCode: "unsupported_page" });
  const reply = await h.handle({ type: "state" });
  expect(reply.state).toBe("unsupported_page");
  expect(reply.message).toBe("Apassy fills logins on https pages only.");
});

test("show brings the app to the front", async ({ h }) => {
  const reply = await h.handle({ type: "show" });
  expect(reply.ok).toBe(true);
  expect(h.requests("show")).toEqual([{ v: 1, cmd: "show" }]);
});
