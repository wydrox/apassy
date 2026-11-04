import { test, expect, passwordSha256, OFFER_PASSWORD, LOGINS } from "../support/fixtures.mjs";
import { shadowText, shadowButton } from "../cdp/closed-shadow.mjs";
test.use({ loginSiteAccess: true });
const banner = "data-apassy-save-offer";
// The first status of an offer, until it takes a press.
const OFFER_WAITS = "Saving needs your approval on your Mac.";
// A save starts two mock hosts (status, then save): slow on a busy macOS runner.
const HOST_WAIT = { timeout: 20_000 };
async function setup(h, path, existing = false) {
  h.setScenario({ vault: "unlocked", logins: existing ? [{ ...LOGINS[0], site: "localhost" }] : [] });
  const page = await h.openGranted(path, "localhost");
  await h.handle({ type: "login_access", on: true });
  const cdp = await h.context.newCDPSession(page);
  await expect.poll(() => page.evaluate(() => !!document.querySelector("form"))).toBe(true);
  return { page, cdp };
}
async function type(page, selector, value) {
  await page.locator(selector).pressSequentially(value);
}
// The banner takes a press only after it was fully visible for 250 ms (its guard against
// clickjacking), which a busy runner can delay past the pause of shadowButton. Press until
// the banner says that it took the press: its buttons are then off, so none acts twice.
async function press(cdp, label) {
  const until = Date.now() + 10_000;
  for (;;) {
    await shadowButton(cdp, banner, label);
    const text = await shadowText(cdp, banner);
    if (!text.includes(OFFER_WAITS)) return;
    if (Date.now() >= until) throw new Error(`the save offer did not take ${label}: ${text}`);
  }
}
for (const path of ["signin", "signup", "xhr", "click", "change", "step1"]) {
  test(`typed ${path} offers ${path === "change" ? "update" : "save"} after navigation or a fetch transition`, async ({ h }) => {
    const existing = path === "change";
    const { page, cdp } = await setup(h, "/offer/" + path, existing);
    await type(page, "#username", existing ? LOGINS[0].username : "new@example.test");
    if (path === "step1") {
      await page.locator("#submit").click(); await expect(page).toHaveURL(/\/offer\/step2/);
      await expect(page.locator("[data-apassy-save-offer]")).toHaveCount(0);
    }
    if (path === "change") await type(page, "#current", "synthetic-old");
    await type(page, "#password", OFFER_PASSWORD);
    if (["signup", "change"].includes(path)) await type(page, "#confirm", OFFER_PASSWORD);
    await page.locator("#submit").click();
    await expect.poll(() => shadowText(cdp, banner)).toContain(existing ? "Update the password in Apassy?" : "Save this login in Apassy?");
    expect(h.requests("save")).toEqual([]); expect(h.requests("update")).toEqual([]);
    expect(await page.locator("[data-apassy-save-offer]").evaluate((el) => el.shadowRoot)).toBeNull();
    const command = existing ? "update" : "save";
    await press(cdp, existing ? "Update" : "Save");
    // The host's answer, then the banner: no fixed time for two host starts.
    await expect.poll(() => h.answers(command).length, HOST_WAIT).toBe(1);
    expect(h.answers(command)[0].ok).toBe(true);
    await expect.poll(() => shadowText(cdp, banner)).toContain(existing ? "Login updated" : "Login saved");
    const request = h.requests(command)[0];
    expect(request.trusted_gesture).toBe(true); expect(request.password).toBe("[redacted]");
    expect(request.password_sha256).toBe(passwordSha256(OFFER_PASSWORD));
    expect(request.username).toBe(existing ? LOGINS[0].username : "new@example.test");
  });
}
test("Apassy fill without editing never offers", async ({ h }) => {
  const { page, cdp } = await setup(h, "/offer/signin", true);
  await page.focus("#username"); const state = await h.handle({ type: "state" });
  expect((await h.handle({ type: "fill", tabId: state.tabId, url: state.url, target: state.target, item: 7 })).ok).toBe(true);
  await page.locator("#submit").click(); await expect(page).toHaveURL(/\/offer\/done/);
  await expect(page.locator("[data-apassy-save-offer]")).toHaveCount(0);
  expect(h.requests("save")).toEqual([]); expect(h.requests("update")).toEqual([]);
  expect(await shadowText(cdp, banner)).toBe("");
});
test("an untrusted click after trusted typing cannot stage an offer", async ({ h }) => {
  const { page } = await setup(h, "/offer/signin");
  await type(page, "#username", "new@example.test"); await type(page, "#password", OFFER_PASSWORD);
  await page.evaluate(() => document.querySelector("#submit").click());
  await expect(page).toHaveURL(/\/offer\/done/);
  await expect(page.locator("[data-apassy-save-offer]")).toHaveCount(0);
  expect(h.requests("save")).toEqual([]);
});
test("hidden hosts and pointer-transparent top-layer overlays cannot clickjack Save", async ({ h }) => {
  const { page, cdp } = await setup(h, "/offer/xhr");
  await type(page, "#username", "new@example.test"); await type(page, "#password", OFFER_PASSWORD);
  await page.locator("#submit").click();
  await expect.poll(() => shadowText(cdp, banner)).toContain("Save this login");
  await page.evaluate(() => {
    document.querySelector("[data-apassy-save-offer]").style.opacity = "0";
  });
  await shadowButton(cdp, banner, "Save"); expect(h.requests("save")).toEqual([]);
  await page.evaluate(() => {
    document.querySelector("[data-apassy-save-offer]").style.opacity = "1";
    const cover = document.createElement("div"); cover.id = "attack-cover"; cover.popover = "manual";
    cover.style.cssText = "position:fixed;inset:0;margin:0;width:100vw;height:100vh;background:white;pointer-events:none";
    document.body.append(cover); cover.showPopover();
  });
  await shadowButton(cdp, banner, "Save"); expect(h.requests("save")).toEqual([]);
  await page.evaluate(() => document.getElementById("attack-cover").remove());
  await press(cdp, "Save");
  await expect.poll(() => h.requests("save").length, HOST_WAIT).toBe(1);
});
test("Never excludes the site after reload and can be undone in toolbar settings", async ({ h }) => {
  const { page, cdp } = await setup(h, "/offer/signin");
  await type(page, "#username", "new@example.test"); await type(page, "#password", OFFER_PASSWORD);
  await page.locator("#submit").click(); await expect.poll(() => shadowText(cdp, banner)).toContain("Save this login");
  await press(cdp, "Never for this site");
  await expect.poll(async () => (await h.handle({ type: "login_access_state" })).siteOff).toBe(true);
  await expect(page.locator("[data-apassy-save-offer]")).toHaveCount(0);
  await page.goto(h.url("/offer/signin", "localhost"));
  await type(page, "#username", "new@example.test"); await type(page, "#password", OFFER_PASSWORD);
  await page.locator("#submit").click(); await expect(page).toHaveURL(/\/offer\/done/);
  await expect(page.locator("[data-apassy-save-offer]")).toHaveCount(0);
  await expect.poll(async () => (await h.handle({ type: "login_access_state" })).siteOff).toBe(true);
  await h.handle({ type: "login_site", url: page.url(), on: true });
  await expect.poll(async () => (await h.handle({ type: "login_access_state" })).siteOff).toBe(false);
});
