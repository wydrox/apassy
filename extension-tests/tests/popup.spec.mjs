import { test, expect, LOGINS, PASSWORD, USERNAME } from "../support/fixtures.mjs";

// popup.html runs in a tab of its own here. The background then takes the tab
// used last before it: the login page.

test("the popup lists the logins and fills one with the keyboard", async ({ h }) => {
  const page = await h.openGranted("/login");
  const host = new URL(page.url()).host;
  const popup = await h.openPopupPage();
  await expect(popup.locator("#site")).toHaveText(host);
  const rows = popup.locator("button.login");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toContainText("Local test");
  await expect(rows.nth(0)).toContainText(USERNAME);
  await expect(rows.nth(1)).toContainText("Second account");
  await expect(rows.nth(0)).toBeFocused();
  await popup.keyboard.press("ArrowDown");
  await expect(rows.nth(1)).toBeFocused();
  await popup.keyboard.press("ArrowDown");
  await expect(rows.nth(0)).toBeFocused();

  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { delayMs: 800 } });
  await popup.keyboard.press("Enter");
  await expect(popup.locator("#note")).toHaveText("Confirm with Touch ID or your passphrase in Apassy.");
  await expect(popup.locator("#note")).toHaveText("Filled.");
  expect(h.requests("fill")).toEqual([{ v: 1, cmd: "fill", url: page.url(), item: 7 }]);
  expect(await page.locator("#password").inputValue()).toBe(PASSWORD);
  expect(await popup.content()).not.toContain(PASSWORD);
});

test("the popup shows the error of a cancelled fill and keeps the list", async ({ h }) => {
  const page = await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: LOGINS, fill: { code: "cancelled" } });
  const popup = await h.openPopupPage();
  await popup.locator("button.login").nth(1).click();
  await expect(popup.locator("#note")).toHaveText("The fill was cancelled. Nothing was filled.");
  await expect(popup.locator("button.login")).toHaveCount(2);
  expect(await page.locator("#password").inputValue()).toBe("");
  // The popup was open, so no badge.
  expect((await h.badge()).text).toBe("");
});

test("the popup asks to unlock a locked vault and can open Apassy", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ vault: "locked", logins: LOGINS });
  const popup = await h.openPopupPage();
  await expect(popup.locator("#note")).toHaveText("Unlock Apassy to fill logins.");
  await expect(popup.locator("button.login")).toHaveCount(0);
  await popup.locator("#open").click();
  await expect.poll(() => h.requests("show").length).toBe(1);
});

test("the popup shows the setup command when the host is missing", async ({ h }) => {
  await h.openGranted("/login");
  h.removeHost();
  const popup = await h.openPopupPage();
  await expect(popup.locator("#note")).toHaveText("Apassy is not connected to this browser.");
  await expect(popup.locator("#command")).toHaveText("apassy setup browser");
});

test("the popup explains an empty list", async ({ h }) => {
  const page = await h.openGranted("/login");
  h.setScenario({ vault: "unlocked", logins: [LOGINS[2]] });
  const popup = await h.openPopupPage();
  const host = new URL(page.url()).host;
  await expect(popup.locator("#note")).toHaveText(
    `No login for ${host}. Add a detail named Website with this address to a login in Apassy.`);
});

test("the popup asks to open Apassy when it does not run", async ({ h }) => {
  await h.openGranted("/login");
  h.setScenario({ notRunning: true });
  const popup = await h.openPopupPage();
  await expect(popup.locator("#note")).toHaveText("Open Apassy to fill logins.");
});
