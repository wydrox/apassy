// The passkey bridge in Helium, against the independent relying party of
// fixtures/passkey-rp (it verifies every response with @simplewebauthn/server).
//
// NOT the real app: the native host is fixtures/passkey-bridge/mock-passkey-host.mjs
// with a SYNTHETIC authenticator, and the extension copy grants localhost in its
// manifest instead of the owner's click (see fixtures/passkey-bridge/browser.mjs).
// A pass shows that the extension builds requests and credentials that a real
// WebAuthn verifier accepts; it does not show that Apassy signs them.

import { test, expect } from "../fixtures/passkey-bridge/browser.mjs";

async function turnOn(ph) {
  const reply = await ph.handle({ type: "passkeys", on: true });
  expect(reply.on).toBe(true);
}

async function openRp(ph, query = "") {
  const page = await ph.context.newPage();
  await page.goto(`${ph.rp.origin}/${query}`);
  await expect(page.locator("#rp-origin")).toHaveText(ph.rp.origin);
  return page;
}

const status = (page) => page.locator("#status");

test("passkeys off: the page gets the browser's own WebAuthn, nothing reaches the host", async ({ ph }) => {
  const page = await openRp(ph);
  const browser = await ph.virtualAuthenticator(page);
  await page.click("#create-passkey");
  await expect(status(page)).toHaveAttribute("data-state", "registered");
  expect(await browser.credentials()).toHaveLength(1);
  expect(ph.requests("passkey_create")).toHaveLength(0);
  expect(await ph.registered()).toEqual([]);
});

test("turning on registers the two scripts: MAIN and ISOLATED, document_start, top frame only", async ({ ph }) => {
  await turnOn(ph);
  const scripts = (await ph.registered()).sort((a, b) => a.id.localeCompare(b.id));
  expect(scripts.map((s) => [s.id, s.world, s.runAt, s.allFrames, s.js])).toEqual([
    ["apassy-passkey-bridge", "ISOLATED", "document_start", false, ["passkey-bridge.js"]],
    ["apassy-passkey-page", "MAIN", "document_start", false, ["passkey-page.js"]],
  ]);
  const page = await ph.context.newPage();
  await page.goto(ph.pageUrl("/otp-iframe"));
  const frame = page.frameLocator("#frame");
  await expect(frame.locator("#code")).toBeVisible();
  const native = (p) => p.evaluate(() => CredentialsContainer.prototype.create.toString().includes("[native code]"));
  expect(await native(page)).toBe(false);
  expect(await native(page.frames()[1])).toBe(true);
});

for (const query of ["", "?transform=manual"]) {
  test(`passkeys on: create and sign in through the extension, verified by the RP ${query || "(native JSON)"}`, async ({ ph }) => {
    await turnOn(ph);
    const page = await openRp(ph, query);
    const browser = await ph.virtualAuthenticator(page);
    await page.click("#create-passkey");
    await expect(status(page)).toHaveAttribute("data-state", "registered");
    await expect(page.locator("#transform")).toHaveAttribute("data-transform", query ? "manual" : "native");

    const [create] = ph.requests("passkey_create");
    expect(create.origin).toBe(ph.rp.origin);
    expect(create.rp_id).toBe("localhost");
    expect(create.user_name).toBe("synthetic.user@example.test");
    expect(create.title).toBe("Apassy passkey test RP");
    const clientData = JSON.parse(Buffer.from(create.client_data_json, "base64").toString("utf8"));
    expect(Object.keys(clientData)).toEqual(["type", "challenge", "origin", "crossOrigin"]);
    expect(clientData).toMatchObject({ type: "webauthn.create", origin: ph.rp.origin, crossOrigin: false });

    await page.click("#sign-in");
    await expect(status(page)).toHaveAttribute("data-state", "signed-in");
    expect(ph.requests("passkey_get")).toHaveLength(1);
    expect(ph.rp.status()).toMatchObject({ credentialCount: 1, registrations: 1, signIns: 1 });
    // The browser's own authenticator was never asked.
    expect(await browser.credentials()).toHaveLength(0);
  });
}

for (const code of ["not_running", "bad_request", "bad_version"]) {
  test(`the app returns ${code} before owner approval: the browser does the request`, async ({ ph }) => {
    await turnOn(ph);
    ph.setScenario({ passkey: { error: code } });
    const page = await openRp(ph);
    const browser = await ph.virtualAuthenticator(page);
    await page.click("#create-passkey");
    await expect(status(page)).toHaveAttribute("data-state", "registered");
    expect(ph.requests("passkey_create")).toHaveLength(1);
    expect(await browser.credentials()).toHaveLength(1);
  });
}

test("the owner cancels: NotAllowedError for the page, never the browser", async ({ ph }) => {
  await turnOn(ph);
  ph.setScenario({ passkey: { error: "cancelled" } });
  const page = await openRp(ph);
  const browser = await ph.virtualAuthenticator(page);
  await page.click("#create-passkey");
  await expect(status(page)).toHaveAttribute("data-error-name", "NotAllowedError");
  expect(await browser.credentials()).toHaveLength(0);
  expect(ph.rp.status().credentialCount).toBe(0);
});

test("a navigation during the owner check closes the host before it answers", async ({ ph }) => {
  await turnOn(ph);
  ph.setScenario({ passkey: { delayMs: 5000 } });
  const page = await openRp(ph);
  await page.click("#create-passkey");
  await expect.poll(() => ph.requests("passkey_create").length).toBe(1);
  await page.goto(ph.pageUrl("/blank"));
  await expect.poll(() => ph.events((e) => e && e.event === "eof").length).toBe(1);
  const [eof] = ph.events((e) => e && e.event === "eof");
  expect(eof.pendingRid).toBe(ph.requests("passkey_create")[0].rid);
  expect(ph.events((e) => e && e.event === "answer")).toHaveLength(0);
  expect(ph.rp.status().credentialCount).toBe(0);
});

test("the popup shows the passkey switch and turns passkeys off", async ({ ph }) => {
  await turnOn(ph);
  const popup = await ph.openPopupPage();
  await expect(popup.locator("#passkeys-row")).toBeVisible();
  await expect(popup.locator("#passkeys")).toBeChecked();
  await popup.locator("#passkeys").click();
  await expect(popup.locator("#passkeys")).not.toBeChecked();
  await expect(popup.locator("#passkeys-note")).toHaveText("Off: sites use the passkeys of the browser.");
  expect(await ph.registered()).toEqual([]);
});
