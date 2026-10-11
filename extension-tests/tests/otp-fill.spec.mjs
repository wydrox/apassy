// "Fill code" in Helium: the one-time code goes from the host into the
// one-time-code field of the top frame, never to the popup.
//
// NOT the real app: the code comes from the scenario of
// fixtures/passkey-bridge/mock-passkey-host.mjs. The pages are on localhost,
// which the test copy of the extension may script (see browser.mjs); a real
// fill uses the activeTab grant of the toolbar click, as a password fill does.

import { test, expect } from "../fixtures/passkey-bridge/browser.mjs";

const CODE = "135790";
const LOGINS = [
  { item: 21, title: "With a code", username: "synthetic", has_totp: true, site: "localhost" },
  { item: 22, title: "Without", username: "other", site: "localhost" },
];

async function open(ph, pathname, scenario = {}) {
  ph.setScenario({ vault: "unlocked", logins: LOGINS, code: { value: CODE }, ...scenario });
  const page = await ph.context.newPage();
  await page.goto(ph.pageUrl(pathname));
  await page.bringToFront();
  const state = await ph.handle({ type: "state" });
  expect(state.state).toBe("list");
  return { page, state };
}

const fillCode = (ph, state, item = 21) => ph.handle({ type: "fill_code", tabId: state.tabId, url: state.url, item });
const values = (page, ids) => page.evaluate((list) => list.map((id) => document.getElementById(id).value), ids);

test("the state marks the login with a code, and holds no code", async ({ ph }) => {
  const { state } = await open(ph, "/otp");
  expect(state.logins).toEqual([
    { item: 21, title: "With a code", username: "synthetic", hasTotp: true },
    { item: 22, title: "Without", username: "other" },
  ]);
  expect(JSON.stringify(state)).not.toContain(CODE);
});

test("one field with autocomplete=one-time-code gets the code, nothing else", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp");
  const reply = await fillCode(ph, state);
  expect(reply).toEqual({ ok: true, code: "ok", message: "Code filled.", filled: { fields: 1 } });
  expect(await values(page, ["code", "other", "password"])).toEqual([CODE, "", ""]);
  expect(ph.requests("fill_code")).toEqual([{ v: 1, cmd: "fill_code", url: state.url, item: 21 }]);
});

test("a code split into six one-digit fields gets one digit each", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp-split");
  const reply = await fillCode(ph, state);
  expect(reply.filled).toEqual({ fields: 6 });
  expect(await values(page, ["d0", "d1", "d2", "d3", "d4", "d5", "after"])).toEqual([...CODE.split(""), ""]);
});

test("a hidden code field, or a field without the mark, is not filled", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp-hidden");
  const reply = await fillCode(ph, state);
  expect(reply).toEqual({ ok: false, code: "no_code_field", message: "Apassy found no field for a one-time code on this page." });
  expect(await values(page, ["code", "visible", "password"])).toEqual(["", "", ""]);
});

test("a code field in a frame is not filled (top frame only)", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp-iframe");
  const reply = await fillCode(ph, state);
  expect(reply.code).toBe("no_code_field");
  expect(await page.frameLocator("#frame").locator("#code").inputValue()).toBe("");
});

test("a code for another origin fills nothing", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp", { code: { value: CODE, origin: "https://evil.example" } });
  const reply = await fillCode(ph, state);
  expect(reply.code).toBe("host_failed");
  expect(await values(page, ["code"])).toEqual([""]);
});

test("a cancelled owner check fills nothing and keeps the message of the app", async ({ ph }) => {
  const { page, state } = await open(ph, "/otp", { code: { error: "cancelled" } });
  const reply = await fillCode(ph, state);
  expect(reply).toEqual({ ok: false, code: "cancelled", message: "cancelled" });
  expect(await values(page, ["code"])).toEqual([""]);
});

test("the popup offers Fill code only for the login with a code, and never shows the code", async ({ ph }) => {
  const { page } = await open(ph, "/otp");
  const popup = await ph.openPopupPage();
  await expect(popup.locator("button.login")).toHaveCount(2);
  const buttons = popup.locator("button.code");
  await expect(buttons).toHaveCount(1);
  await expect(buttons).toHaveAttribute("data-item", "21");
  await buttons.click();
  await expect(popup.locator("#note")).toHaveText("Code filled.");
  expect(await values(page, ["code"])).toEqual([CODE]);
  expect(await popup.content()).not.toContain(CODE);
});
