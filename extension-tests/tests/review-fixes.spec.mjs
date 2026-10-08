// Findings of the second security review of "Save this login" and "New password".

import { test, expect } from "../support/fixtures.mjs";

const SHOWN = "shown-password-canary-31";

test("a password field shown as text is never the username", async ({ h }) => {
  const page = await h.openGranted("/toggled");
  await page.fill("#uid", "me");
  await page.fill("#pw", SHOWN);
  const state = await h.handle({ type: "state" });
  h.clearRequests();
  const peek = await h.handle({ type: "peek", tabId: state.tabId, url: state.url });
  expect(JSON.stringify(peek)).not.toContain(SHOWN);
  const saved = await h.handle({
    type: "save", tabId: state.tabId, url: state.url, title: "Local", username: "me",
  });
  expect(saved.code).toBe("no_password");
  expect(JSON.stringify(saved)).not.toContain(SHOWN);
  expect(h.requests("save")).toEqual([]);
});

test("a lost create answer says that the login may be in Apassy", async ({ h }) => {
  await h.openGranted("/signup");
  const state = await h.handle({ type: "state" });
  h.setScenario({ ...h.scenario(), create: { crash: true } });
  const reply = await h.handle({
    type: "create", tabId: state.tabId, url: state.url,
    title: "Local", username: "me@example.com", length: 20, symbols: true,
  });
  expect(reply.ok).toBe(false);
  expect(reply.message).toContain("may be in Apassy");
});
