// Playwright fixture for the passkey and one-time code tests: one Helium per
// test worker (never Google Chrome, never a downloaded browser).
//
// What is NOT real here, on purpose:
// - The native host is mock-passkey-host.mjs with the SYNTHETIC authenticator,
//   not apassy-browser-host and not the Apassy app or a vault.
// - The extension is a copy of ../../../extension whose manifest also grants
//   http://localhost/* as a host permission. A test cannot click the
//   permission prompt of the browser; the copy stands in for the owner's grant.
//   Everything else (the "passkeys" message of the popup, the registered
//   scripts, the worker) is the shipped code.
// - The relying party is the independent fixture ../passkey-rp (it checks
//   every response with @simplewebauthn/server), on http://localhost:PORT.

import { test as base, expect, chromium } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPasskeyRp } from "../passkey-rp/rp-server.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SOURCE_EXTENSION = path.resolve(HERE, "../../../extension");
export const EXTENSION_ID = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
export const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}/`;
const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
const MOCK_HOST = path.join(HERE, "mock-passkey-host.mjs");
const HEADLESS = process.env.HEADED !== "1";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function copyExtension(root) {
  const target = path.join(root, "extension");
  fs.cpSync(SOURCE_EXTENSION, target, { recursive: true });
  const file = path.join(target, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  manifest.host_permissions = ["http://localhost/*"];
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2));
  return target;
}

function installHost(root, profile) {
  const mockDir = path.join(root, "mock");
  fs.mkdirSync(mockDir, { recursive: true });
  const wrapper = path.join(root, "apassy-browser-host");
  fs.writeFileSync(wrapper, [
    "#!/bin/sh",
    `APASSY_MOCK_DIR='${mockDir}'`,
    "export APASSY_MOCK_DIR",
    `exec '${process.execPath}' '${MOCK_HOST}' "$@"`,
    "",
  ].join("\n"), { mode: 0o755 });
  const hostsDir = path.join(profile, "NativeMessagingHosts");
  fs.mkdirSync(hostsDir, { recursive: true });
  fs.writeFileSync(path.join(hostsDir, "com.wydrox.apassy.json"), JSON.stringify({
    name: "com.wydrox.apassy",
    description: "Apassy passkey test host (synthetic)",
    path: wrapper,
    type: "stdio",
    allowed_origins: [EXTENSION_ORIGIN],
  }));
  return mockDir;
}

const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>input { display: block; margin: 4px 0; } .split input { display: inline-block; width: 2em; }</style></head><body>${body}</body></html>`;

export const OTP_PAGES = {
  "/otp": page("Code", `
    <form onsubmit="return false">
      <input type="text" id="other" name="search">
      <input type="password" id="password" autocomplete="current-password">
      <input type="text" id="code" inputmode="numeric" autocomplete="one-time-code">
    </form>`),
  "/otp-split": page("Split code", `
    <form class="split" onsubmit="return false">
      <input id="d0" maxlength="1" inputmode="numeric" autocomplete="one-time-code"><input id="d1" maxlength="1"><input id="d2" maxlength="1"><input id="d3" maxlength="1"><input id="d4" maxlength="1"><input id="d5" maxlength="1">
      <input id="after" type="text">
    </form>`),
  "/otp-hidden": page("Hidden code", `
    <input type="text" id="code" autocomplete="one-time-code" style="display:none">
    <input type="text" id="visible" name="code">
    <input type="password" id="password">`),
  "/otp-iframe": page("Code in a frame", `
    <p>The code field is in a frame.</p>
    <iframe id="frame" srcdoc='<input type="text" id="code" autocomplete="one-time-code">'></iframe>`),
  "/blank": page("Blank", "<p>Nothing here.</p>"),
};

async function startPages() {
  const server = http.createServer((req, res) => {
    const body = OTP_PAGES[new URL(req.url, "http://localhost").pathname];
    res.writeHead(body ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
    res.end(body || "not found");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server;
}

class Harness {
  constructor(context, root, mockDir, rp, pages) {
    Object.assign(this, { context, root, mockDir, rp, pages });
  }

  pageUrl(pathname) {
    return `http://localhost:${this.pages.address().port}${pathname}`;
  }

  setScenario(scenario) {
    fs.writeFileSync(path.join(this.mockDir, "scenario.json"), JSON.stringify(scenario));
  }

  events(filter) {
    const file = path.join(this.mockDir, "events.jsonl");
    if (!fs.existsSync(file)) return [];
    const all = fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
    return filter ? all.filter(filter) : all;
  }

  requests(cmd) {
    return this.events((e) => e && e.cmd === cmd && !e.event);
  }

  async worker() {
    let [worker] = this.context.serviceWorkers().filter((w) => w.url().startsWith(EXTENSION_ORIGIN));
    if (!worker) worker = await this.context.waitForEvent("serviceworker");
    return worker;
  }

  async handle(message) {
    return (await this.worker()).evaluate((m) => self.apassyHandle(m), message);
  }

  async registered() {
    return (await this.worker()).evaluate(() => chrome.scripting.getRegisteredContentScripts());
  }

  // A virtual authenticator of the browser for one page, so that a request
  // that the extension leaves to the browser can finish in headless Helium.
  async virtualAuthenticator(page) {
    const cdp = await this.context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
      },
    });
    return { credentials: async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials };
  }

  async openPopupPage() {
    const popup = await this.context.newPage();
    await popup.goto(`${EXTENSION_ORIGIN}popup.html`);
    return popup;
  }

  async reset() {
    this.setScenario({ vault: "unlocked", logins: [] });
    fs.writeFileSync(path.join(this.mockDir, "events.jsonl"), "");
    fs.rmSync(path.join(this.mockDir, "keys.json"), { force: true });
    this.rp.reset();
    await this.handle({ type: "passkeys", on: false });
    const worker = await this.worker();
    await worker.evaluate(async () => {
      await chrome.action.setBadgeText({ text: "" });
      await chrome.action.setTitle({ title: "Apassy" });
    });
    for (const p of this.context.pages().slice(1)) await p.close();
  }
}

export const test = base.extend({
  passkeyHarness: [async ({}, use) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-passkey-test-"));
    const profile = path.join(root, "profile");
    fs.mkdirSync(profile);
    const extension = copyExtension(root);
    const mockDir = installHost(root, profile);
    const rp = await createPasskeyRp();
    await rp.start();
    const pages = await startPages();
    const context = await chromium.launchPersistentContext(profile, {
      executablePath: HELIUM,
      headless: HEADLESS,
      ignoreDefaultArgs: ["--disable-extensions"],
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    });
    const harness = new Harness(context, root, mockDir, rp, pages);
    await harness.worker();
    // Helium may reload the first tab about a second after the start.
    await sleep(1500);
    await use(harness);
    await context.close();
    await rp.stop();
    pages.close();
    fs.rmSync(root, { recursive: true, force: true });
  }, { scope: "worker" }],

  ph: async ({ passkeyHarness }, use) => {
    await passkeyHarness.reset();
    await use(passkeyHarness);
  },
});

export { expect, sleep };
