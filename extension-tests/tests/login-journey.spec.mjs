// Synthetic native-host + isolated Helium acceptance. Run with the documented test profile.
import { test, expect, LOGINS, PASSWORD } from "../support/fixtures.mjs";

test("focused form is captured before approval; same-document replacement is rejected", async ({ h }) => {
  const page = await h.openGranted("/new-and-current");
  await page.focus("#username");
  const state = await h.handle({ type: "state" });
  const barrier = h.holdReply("fill");
  const filling = h.handle({ type: "fill", tabId: state.tabId, url: state.url, item: 7, target: state.target });
  try {
    await expect.poll(() => h.requests("fill").length).toBe(1);
    await page.evaluate(() => document.querySelector("#password").replaceWith(document.querySelector("#password").cloneNode()));
  } finally {
    h.releaseReply(barrier);
  }
  const result = await filling;
  expect(result.code).toBe("page_changed");
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator("#new-password")).toHaveValue("");
});

test("second focused form receives the selected account; first form stays empty", async ({ h }) => {
  const page = await h.openGranted("/new-and-current");
  await page.focus("#username");
  const state = await h.handle({ type: "state" });
  const result = await h.handle({ type: "fill", tabId: state.tabId, url: state.url, item: 7, target: state.target });
  expect(result.ok).toBe(true);
  await expect(page.locator("#password")).toHaveValue(PASSWORD);
  await expect(page.locator("#new-password")).toHaveValue("");
  await expect(page.locator("#join-email")).toHaveValue("");
});

test("explicit update rotates only the selected synthetic password and can be reused", async ({ h }) => {
  const page = await h.openGranted("/typed");
  const preserved = { ...LOGINS[0], website: "https://synthetic.example", totp: "synthetic-seed", passkey: { id: "synthetic-id" }, notes: "keep me" };
  h.setScenario({ ...h.scenario(), logins: [preserved, LOGINS[1]] });
  await page.fill("#username", preserved.username);
  await page.fill("#password", "Rotated-Synthetic-Password-42");
  const state = await h.handle({ type: "state" });
  const updated = await h.handle({ type: "update", tabId: state.tabId, url: state.url, target: state.target, item: preserved.item, username: preserved.username });
  expect(updated.ok).toBe(true);
  expect(h.scenario().logins[0]).toEqual({ ...preserved, password: "Rotated-Synthetic-Password-42" });
  expect(h.scenario().logins[1]).toEqual(LOGINS[1]);
  await page.fill("#password", "");
  const fresh = await h.handle({ type: "state" });
  const filled = await h.handle({ type: "fill", tabId: fresh.tabId, url: fresh.url, target: fresh.target, item: preserved.item });
  expect(filled.ok).toBe(true);
  await expect(page.locator("#password")).toHaveValue("Rotated-Synthetic-Password-42");
  expect(JSON.stringify(updated)).not.toContain("Rotated-Synthetic-Password-42");
});

test("controlled site authenticates before and after website rotation plus explicit vault update", async ({ h }) => {
  const page = await h.openGranted("/journey-login");
  let state = await h.handle({ type: "state" });
  expect((await h.handle({ type: "fill", tabId: state.tabId, url: state.url, target: state.target, item: 7 })).ok).toBe(true);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator("#status")).toHaveAttribute("data-authenticated", "true");
  await page.goto(h.url("/journey-password"));
  await page.fill("#username", LOGINS[0].username);
  await page.fill("#current", PASSWORD);
  await page.fill("#password", "Rotated-Site-Password-42");
  await page.getByRole("button", { name: "Change password", exact: true }).click();
  await expect(page.locator("#status")).toHaveText("Password changed on this site");
  state = await h.handle({ type: "state" });
  expect((await h.handle({ type: "update", tabId: state.tabId, url: state.url, target: state.target, item: 7, username: LOGINS[0].username })).ok).toBe(true);
  await page.goto(h.url("/journey-login"));
  state = await h.handle({ type: "state" });
  expect((await h.handle({ type: "fill", tabId: state.tabId, url: state.url, target: state.target, item: 7 })).ok).toBe(true);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator("#status")).toHaveAttribute("data-authenticated", "true");
  await expect(page.locator("#status")).toHaveText(`Signed in as ${LOGINS[0].username}`);
});

test("popup update requires selecting and confirming the exact existing account", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#username", LOGINS[0].username);
  await page.fill("#password", "Explicit-Popup-Update-42");
  const popup = await h.openPopupPage();
  await popup.getByRole("button", { name: `Update password for ${LOGINS[0].username} in ${LOGINS[0].title}`, exact: true }).click();
  await expect(popup.locator("#note")).toContainText(LOGINS[0].username);
  expect(h.requests("update")).toEqual([]);
  await popup.getByRole("button", { name: "Update this login", exact: true }).click();
  await expect(popup.locator("#note")).toContainText("Login updated in Apassy");
  expect(h.requests("update")).toHaveLength(1);
  expect(h.scenario().logins[0].password).toBe("Explicit-Popup-Update-42");
  expect(h.scenario().logins[1]).toEqual(LOGINS[1]);
});

test("mismatched new-password confirmations block update before native mutation", async ({ h }) => {
  const page = await h.openGranted("/signup");
  await page.fill("#email", LOGINS[0].username);
  await page.fill("#new-password", "Next-Password-42");
  await page.fill("#confirm-password", "Different-Password-42");
  await page.focus("#email");
  const state = await h.handle({ type: "state" });
  const result = await h.handle({ type: "update", tabId: state.tabId, url: state.url, target: state.target, item: 7, username: LOGINS[0].username });
  expect(result.code).toBe("password_confirmation");
  expect(h.requests("update")).toEqual([]);
  expect(h.scenario().logins[0]).toEqual(LOGINS[0]);
});
