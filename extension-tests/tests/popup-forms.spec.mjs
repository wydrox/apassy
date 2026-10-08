import { test, expect, LOGINS, NEW_PASSWORD, TYPED_PASSWORD } from "../support/fixtures.mjs";

// The "Save this login" and "New password" views of the popup. popup.html runs
// in a tab of its own; the background takes the page tab used before it.

const FILLED = "Filled. The new login is in Apassy. Submit the form on the page.";

test("the list and the empty state show Save this login and New password", async ({ h }) => {
  const page = await h.openGranted("/login");
  let popup = await h.openPopupPage();
  await expect(popup.locator("button.login")).toHaveCount(2);
  await expect(popup.locator("#save-open")).toHaveText("Save this login");
  await expect(popup.locator("#new-open")).toHaveText("New password");
  await expect(popup.locator("button.login").first()).toBeFocused();
  await popup.close();

  h.setScenario({ vault: "unlocked", logins: [LOGINS[2]] });
  popup = await h.openPopupPage();
  await expect(popup.locator("#note")).toContainText(`No login for ${new URL(page.url()).host}.`);
  await expect(popup.locator("#save-open")).toBeVisible();
  await expect(popup.locator("#new-open")).toBeVisible();
  await popup.close();

  h.setScenario({ vault: "locked", logins: LOGINS });
  popup = await h.openPopupPage();
  await expect(popup.locator("#open")).toBeVisible();
  await expect(popup.locator("#save-open")).toHaveCount(0);
  await expect(popup.locator("#new-open")).toHaveCount(0);
});

test("the Save view prefills the username and disables Save without a typed password", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#username", "typed-user");
  const popup = await h.openPopupPage();
  await popup.locator("#save-open").click();
  await expect(popup.locator("#username")).toHaveValue("typed-user");
  await expect(popup.locator("#title")).toHaveValue(new URL(page.url()).host);
  await expect(popup.locator("#note")).toHaveText("Type your password on the page first.");
  await expect(popup.locator("#save")).toBeDisabled();
  await expect(popup.locator("#save-form")).toContainText("The password comes from the page.");
  // Escape goes back to the list.
  await popup.keyboard.press("Escape");
  await expect(popup.locator("button.login")).toHaveCount(2);
  expect(h.requests("save")).toEqual([]);
});

test("the Save view saves the typed login after the owner check", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#username", "typed-user");
  await page.fill("#password", TYPED_PASSWORD);
  h.setScenario({ vault: "unlocked", logins: LOGINS, save: { delayMs: 800 } });
  const popup = await h.openPopupPage();
  await popup.locator("#save-open").click();
  await expect(popup.locator("#save")).toBeEnabled();
  await popup.locator("#title").fill("Typed site");
  await popup.locator("#title").press("Enter");
  await expect(popup.locator("#note")).toHaveText("Confirm in Apassy.");
  await expect(popup.locator("#note")).toHaveText("Saved.");
  expect(h.requests("save")).toEqual([{
    v: 1, cmd: "save", url: page.url(), title: "Typed site", username: "typed-user", password: TYPED_PASSWORD,
  }]);
  expect(await popup.content()).not.toContain(TYPED_PASSWORD);
  // Back asks Apassy again for the list.
  h.clearRequests();
  await popup.locator("#back").click();
  await expect(popup.locator("button.login")).toHaveCount(2);
  expect(h.requests().map((r) => r.cmd)).toEqual(["status", "logins"]);
});

test("the Save view shows exists from the app and keeps the form", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#username", "typed-user");
  await page.fill("#password", TYPED_PASSWORD);
  const exists = 'The login "Local test" (typed-user) is already in Apassy for this page. Nothing was saved.';
  h.setScenario({ vault: "unlocked", logins: LOGINS, save: { code: "exists", message: exists } });
  const popup = await h.openPopupPage();
  await popup.locator("#save-open").click();
  await popup.locator("#save").click();
  await expect(popup.locator("#note")).toHaveText(exists);
  await expect(popup.locator("#username")).toHaveValue("typed-user");
  await expect(popup.locator("#save")).toBeEnabled();
});

test("the Save view requires a title and a username", async ({ h }) => {
  const page = await h.openGranted("/typed");
  await page.fill("#password", TYPED_PASSWORD);
  const popup = await h.openPopupPage();
  await popup.locator("#save-open").click();
  await expect(popup.locator("#username")).toBeFocused();
  await popup.locator("#username").press("Enter");
  await expect(popup.locator("#note")).toHaveText("Enter a title and a username.");
  await expect(popup.locator("#username")).toBeFocused();
  expect(h.requests("save")).toEqual([]);
});

test("the New password view sends the length and symbols and shows the result", async ({ h }) => {
  const page = await h.openGranted("/signup");
  h.setScenario({ vault: "unlocked", logins: LOGINS, create: { password: NEW_PASSWORD, delayMs: 800 } });
  const popup = await h.openPopupPage();
  await popup.locator("#new-open").click();
  await expect(popup.locator("#title")).toHaveValue(new URL(page.url()).host);
  await expect(popup.locator("#length")).toHaveValue("20");
  await expect(popup.locator("#symbols")).toBeChecked();
  await expect(popup.locator("#create")).toBeEnabled();
  await expect(popup.locator("#new-form")).toContainText("Apassy makes the password and keeps it before the page gets it.");
  await popup.locator("#username").fill("new@example.com");
  await popup.locator("#length").fill("32");
  await popup.locator("#symbols").uncheck();
  await popup.locator("#username").press("Enter");
  await expect(popup.locator("#note")).toHaveText("Confirm with Touch ID or your passphrase in Apassy.");
  await expect(popup.locator("#note")).toHaveText(FILLED);
  expect(h.requests("create")).toEqual([{
    v: 1, cmd: "create", url: page.url(), title: new URL(page.url()).host, username: "new@example.com", length: 32, symbols: false,
  }]);
  expect(await page.locator("#new-password").inputValue()).toBe(NEW_PASSWORD);
  expect(await page.locator("#confirm-password").inputValue()).toBe(NEW_PASSWORD);
  expect(await page.locator("#email").inputValue()).toBe("new@example.com");
  expect(await popup.content()).not.toContain(NEW_PASSWORD);
});

test("the New password view clamps the length and requires a username", async ({ h }) => {
  await h.openGranted("/signup");
  h.setScenario({ vault: "unlocked", logins: LOGINS, create: { password: NEW_PASSWORD } });
  const popup = await h.openPopupPage();
  await popup.locator("#new-open").click();
  await popup.locator("#length").fill("100");
  await popup.locator("#length").press("Enter");
  await expect(popup.locator("#note")).toHaveText("Enter a title and a username.");
  await expect(popup.locator("#length")).toHaveValue("64");
  expect(h.requests("create")).toEqual([]);
  await popup.locator("#username").fill("new@example.com");
  await popup.locator("#length").fill("5");
  await popup.locator("#username").press("Enter");
  await expect(popup.locator("#note")).toHaveText(FILLED);
  expect(h.requests("create").map((r) => r.length)).toEqual([12]);
});

test("the New password view on a page without a new password field disables the button", async ({ h }) => {
  await h.openGranted("/login");
  const popup = await h.openPopupPage();
  await popup.locator("#new-open").click();
  await expect(popup.locator("#note")).toHaveText("This page has no field for a new password.");
  await expect(popup.locator("#create")).toBeDisabled();
  await popup.locator("#back").click();
  await expect(popup.locator("button.login")).toHaveCount(2);
});

test("a cancelled New password keeps the form and shows the message of the app", async ({ h }) => {
  const page = await h.openGranted("/signup");
  h.setScenario({ vault: "unlocked", logins: LOGINS, create: { code: "cancelled" } });
  const popup = await h.openPopupPage();
  await popup.locator("#new-open").click();
  await popup.locator("#username").fill("new@example.com");
  await popup.locator("#create").click();
  await expect(popup.locator("#note")).toHaveText("The fill was cancelled. Nothing was filled.");
  await expect(popup.locator("#username")).toHaveValue("new@example.com");
  expect(await page.locator("#new-password").inputValue()).toBe("");
  expect((await h.badge()).text).toBe("");
});
