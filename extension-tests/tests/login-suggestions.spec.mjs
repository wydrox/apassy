import { test, expect, LOGINS, PASSWORD, USERNAME } from "../support/fixtures.mjs";
import { goto } from "../support/helium.mjs";
// A temporary extension copy grants localhost, as the existing passkey fixture
// does. The production manifest and all real browser profiles remain untouched.
test.use({ loginSiteAccess: true });
const selector = "[data-apassy-login-suggestions]";
async function setup(h, path = "/typed") {
  h.setScenario({ vault: "unlocked", logins: LOGINS.map((l) => ({ ...l, site: l.site === "127.0.0.1" ? "localhost" : l.site })) });
  const page = await h.openGranted(path, "localhost");
  expect((await h.handle({ type: "login_access", url: page.url(), on: true })).on).toBe(true);
  return page;
}
async function choose(page, frame = page) {
  await expect(frame.locator(selector)).toHaveAttribute("data-state", "list");
  await expect(frame.locator(selector)).toBeVisible();
  await frame.locator("#username").press("Alt+ArrowDown");
  await expect(frame.locator(selector)).toBeFocused();
  await page.keyboard.press("Enter");
}

test("menu aligns to the field, flips over Submit and follows scroll/resize", async ({ h }) => {
  const page = await setup(h);
  await page.setViewportSize({ width: 1000, height: 900 });
  await page.addStyleTag({ content: "body{margin:320px 200px;min-height:1500px}#username,#password{box-sizing:border-box;width:320px;height:40px;margin:8px 0}" });
  await page.focus("#password");
  await expect(page.locator(selector)).toHaveAttribute("data-state", "list");
  // Scroll/resize positioning is asynchronous; wait for the complete geometry.
  const checkGeometry = async () => expect(async () => {
    const field = await page.locator("#password").boundingBox();
    const menu = await page.locator(selector).boundingBox();
    expect(menu.x).toBeCloseTo(field.x, 0);
    expect(menu.width).toBeGreaterThanOrEqual(field.width);
    expect(menu.y + menu.height).toBeLessThanOrEqual(field.y);
  }).toPass({ timeout: 5000 });
  await checkGeometry();
  await page.evaluate(() => window.scrollTo(0, 40));
  await expect.poll(async () => (await page.locator(selector).boundingBox()).y).toBeLessThan(320);
  await checkGeometry();
  await page.setViewportSize({ width: 800, height: 850 });
  await checkGeometry();
});

test("focus retrieves metadata only, keyboard choice fills after explicit native request", async ({ h }) => {
  const page = await setup(h);
  await page.setViewportSize({ width: 320, height: 640 });
  await page.focus("#username");
  await expect.poll(() => h.requests("suggestions").length).toBeGreaterThan(0);
  expect(h.requests("fill")).toEqual([]);
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator(selector)).toHaveAttribute("data-state", "list");
  const menuBox = await page.locator(selector).boundingBox();
  expect(menuBox.x).toBeGreaterThanOrEqual(0);
  expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(320);
  await page.screenshot({ path: test.info().outputPath("login-suggestions.png") });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.screenshot({ path: test.info().outputPath("login-suggestions-dark.png") });
  await choose(page);
  await expect(page.locator("#password")).toHaveValue(PASSWORD);
  expect(h.requests("fill")).toHaveLength(1);
  expect(h.requests("fill")[0].trusted_gesture).toBe(true);
  await expect(page.locator("#username")).toHaveValue(USERNAME);
});

test("typing a username filters before choice and the second account fills", async ({ h }) => {
  const page = await setup(h);
  await page.fill("#username", "SECOND@");
  await expect.poll(() => h.requests("suggestions").some((r) => r.username === "SECOND@")).toBe(true);
  await choose(page);
  await expect(page.locator("#password")).toHaveValue(LOGINS[1].password);
  await expect(page.locator("#username")).toHaveValue(LOGINS[1].username);
});

test("same-origin iframe chooser fills only that frame document", async ({ h }) => {
  const page = await setup(h, "/same-frame");
  const frame = page.frameLocator("#frame");
  await frame.locator("#username").focus();
  await choose(page, frame);
  await expect(frame.locator("#password")).toHaveValue(PASSWORD);
  expect(h.requests("fill")).toHaveLength(1);
  expect(h.requests("fill")[0].trusted_gesture).toBe(true);
});

test("navigation during owner approval drops the password and retains a safe result", async ({ h }) => {
  const page = await setup(h);
  const before = await h.handle({ type: "state" });
  const barrier = h.holdReply("fill");
  try {
    await page.focus("#username");
    await choose(page);
    await expect.poll(() => h.requests("fill").length).toBe(1);
    await goto(page, h.url("/typed", "localhost"));
  } finally {
    h.releaseReply(barrier);
  }
  // Wait for the worker's actual nonsecret outcome, rather than a timed sleep.
  await expect.poll(async () => (await h.actionResult(before.tabId))?.code).toBe("page_changed");
  await expect(page.locator("#password")).toHaveValue("");
  const state = await h.handle({ type: "state" });
  expect(state.recent).toBeNull();
});

test("cross-origin embedded page uses explicit own-tab recovery, with no fill request", async ({ h }) => {
  const page = await setup(h, "/cross-frame");
  await page.frameLocator("#frame").locator("#username").focus();
  const state = await h.handle({ type: "state" });
  const result = await h.handle({ type: "fill", tabId: state.tabId, url: state.url, target: state.target, item: 7 });
  expect(result.ok).toBe(false);
  expect(result.message).toContain("own tab");
  expect(h.requests("fill")).toEqual([]);
});

test("Escape dismisses keyboard menu and restores the field without reopening", async ({ h }) => {
  const page = await setup(h);
  await page.focus("#username");
  await expect(page.locator(selector)).toHaveAttribute("data-state", "list");
  await page.locator("#username").press("Alt+ArrowDown");
  await page.keyboard.press("Escape");
  await expect(page.locator(selector)).toHaveCount(0);
  await expect(page.locator("#username")).toBeFocused();
  await page.locator("#username").press("Alt+ArrowDown");
  await expect(page.locator(selector)).toHaveAttribute("data-state", "list");
});

test("unlock alone never fills; the field still needs an explicit account choice", async ({ h }) => {
  const page = await setup(h);
  h.setScenario({ ...h.scenario(), vault: "locked" });
  await page.focus("#username");
  await expect(page.locator(selector)).toHaveAttribute("data-state", "recovery");
  h.setScenario({ ...h.scenario(), vault: "unlocked" });
  await page.waitForTimeout(200);
  expect(h.requests("fill")).toEqual([]);
  await expect(page.locator("#password")).toHaveValue("");
  // Recovery menu: Open Apassy, Show all accounts, Dismiss.
  await page.locator("#username").press("Alt+ArrowDown");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await choose(page);
  await expect(page.locator("#password")).toHaveValue(PASSWORD);
});

test("turning off suggestions while approval waits prevents the pending fill", async ({ h }) => {
  const page = await setup(h);
  const before = await h.handle({ type: "state" });
  const barrier = h.holdReply("fill");
  try {
    await page.focus("#username");
    await choose(page);
    await expect.poll(() => h.requests("fill").length).toBe(1);
    expect((await h.handle({ type: "login_access", url: page.url(), on: false })).on).toBe(false);
  } finally {
    h.releaseReply(barrier);
  }
  await expect.poll(async () => (await h.actionResult(before.tabId))?.code).toBe("page_changed");
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator(selector)).toHaveCount(0);
});
