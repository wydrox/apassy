// Playwright fixtures: one Helium per test worker, with the extension loaded
// from ../extension, a temporary profile, a mock native host, and the test
// pages.

import { test as base, expect, chromium } from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "./pages.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const EXTENSION_DIR = path.resolve(HERE, "../../extension");
export const EXTENSION_ID = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
export const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}/`;
const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
const MOCK_HOST = path.resolve(HERE, "../mock-host/mock-host.mjs");
const HEADLESS = process.env.HEADED !== "1";

export const PASSWORD = "Tr0ub4dor&3-never-in-a-reply";
export const USERNAME = "rafal@example.com";
// The password that the mock app makes for "create" in the tests.
export const NEW_PASSWORD = "N3w-from-Apassy_never-in-a-reply";
// The password that a test types on a page for "save".
export const TYPED_PASSWORD = "typed-by-hand_S3cret!";

export const LOGINS = [
  { item: 7, title: "Local test", username: USERNAME, password: PASSWORD, site: "127.0.0.1" },
  { item: 8, title: "Second account", username: "second@example.com", password: "second-secret-value", site: "127.0.0.1" },
  { item: 9, title: "Other site", username: "other", password: "other-secret-value", site: "example.org" },
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// In its first second, Helium sometimes sends a new tab to about:blank, which
// aborts the navigation of the test (net::ERR_ABORTED). Try again then.
async function goto(page, url) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await page.goto(url);
    } catch (error) {
      if (attempt >= 3 || !String(error.message).includes("ERR_ABORTED")) throw error;
      await sleep(250);
    }
  }
}

// Writes the host manifest into the profile: Chromium reads user-level host
// manifests from <user-data-dir>/NativeMessagingHosts.
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
  const manifest = path.join(hostsDir, "com.wydrox.apassy.json");
  const body = JSON.stringify({
    name: "com.wydrox.apassy",
    description: "Apassy test host",
    path: wrapper,
    type: "stdio",
    allowed_origins: [EXTENSION_ORIGIN],
  }, null, 2);
  fs.writeFileSync(manifest, body);
  return { mockDir, manifest, manifestBody: body };
}

class Harness {
  constructor({ context, browserSession, server, mockDir, manifest, manifestBody }) {
    this.context = context;
    this.browserSession = browserSession;
    this.server = server;
    this.mockDir = mockDir;
    this.manifest = manifest;
    this.manifestBody = manifestBody;
    this.counter = 0;
  }

  url(pathname, host = "127.0.0.1") {
    this.counter += 1;
    return `http://${host}:${this.server.port}${pathname}?n=${this.counter}`;
  }

  setScenario(scenario) {
    fs.writeFileSync(path.join(this.mockDir, "scenario.json"), JSON.stringify(scenario));
  }

  clearRequests() {
    fs.writeFileSync(path.join(this.mockDir, "requests.jsonl"), "");
  }

  requests(cmd) {
    const file = path.join(this.mockDir, "requests.jsonl");
    if (!fs.existsSync(file)) return [];
    const all = fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
    return cmd ? all.filter((request) => request && request.cmd === cmd) : all;
  }

  removeHost() {
    fs.rmSync(this.manifest, { force: true });
  }

  restoreHost() {
    fs.writeFileSync(this.manifest, this.manifestBody);
  }

  async worker() {
    let [worker] = this.context.serviceWorkers().filter((w) => w.url().startsWith(EXTENSION_ORIGIN));
    if (!worker) worker = await this.context.waitForEvent("serviceworker");
    return worker;
  }

  // Calls the same handler that the popup uses.
  async handle(message) {
    const worker = await this.worker();
    return worker.evaluate((m) => self.apassyHandle(m), message);
  }

  async targets(type) {
    const { targetInfos } = await this.browserSession.send("Target.getTargets", { filter: [{ type }] });
    return targetInfos;
  }

  scenario() {
    return JSON.parse(fs.readFileSync(path.join(this.mockDir, "scenario.json"), "utf8"));
  }

  // Opens a page, then clicks the extension's toolbar button for its tab, as
  // the owner does. That grants activeTab for the tab. The real popup that it
  // opens is closed again, so that the test drives the extension itself.
  // While it is open, the mock answers not_running, so that the popup asks
  // only status and leaves no request behind.
  async openGranted(pathname, host = "127.0.0.1") {
    const url = this.url(pathname, host);
    const page = await this.context.newPage();
    await goto(page, url);
    await page.bringToFront();
    const tab = (await this.targets("tab")).find((t) => t.url === url);
    if (!tab) throw new Error(`no tab target for ${url}`);
    const scenario = this.scenario();
    this.setScenario({ notRunning: true });
    this.clearRequests();
    await this.browserSession.send("Extensions.triggerAction", { id: EXTENSION_ID, targetId: tab.targetId });
    for (let i = 0; i < 250 && this.requests("status").length === 0; i += 1) await sleep(20);
    await this.closeRealPopup();
    this.setScenario(scenario);
    this.clearRequests();
    return page;
  }

  async closeRealPopup() {
    const popupUrl = `${EXTENSION_ORIGIN}popup.html`;
    for (let i = 0; i < 50; i += 1) {
      const popup = (await this.targets("page")).find((t) => t.url === popupUrl && !this.popupPages.has(t.targetId));
      if (popup) {
        await this.browserSession.send("Target.closeTarget", { targetId: popup.targetId });
        for (let j = 0; j < 50; j += 1) {
          if (!(await this.targets("page")).some((t) => t.targetId === popup.targetId)) return;
          await sleep(20);
        }
        throw new Error("the real popup did not close");
      }
      await sleep(20);
    }
    throw new Error("the toolbar button opened no popup");
  }

  // Opens popup.html in a tab of its own, after the page tab.
  async openPopupPage() {
    const page = await this.context.newPage();
    const target = await (await this.context.newCDPSession(page)).send("Target.getTargetInfo");
    this.popupPages.add(target.targetInfo.targetId);
    await goto(page, `${EXTENSION_ORIGIN}popup.html`);
    return page;
  }

  async badge() {
    const worker = await this.worker();
    return worker.evaluate(async () => ({
      text: await chrome.action.getBadgeText({}),
      title: await chrome.action.getTitle({}),
    }));
  }

  async reset() {
    this.restoreHost();
    this.setScenario({ vault: "unlocked", logins: LOGINS });
    this.clearRequests();
    const worker = await this.worker();
    await worker.evaluate(async () => {
      await chrome.action.setBadgeText({ text: "" });
      await chrome.action.setTitle({ title: "Apassy" });
    });
    for (const page of this.context.pages().slice(1)) await page.close();
    this.popupPages = new Set();
  }
}

export const test = base.extend({
  harness: [async ({}, use) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-ext-test-"));
    const profile = path.join(root, "profile");
    fs.mkdirSync(profile);
    const host = installHost(root, profile);
    const server = await startServer();
    const started = Date.now();
    const context = await chromium.launchPersistentContext(profile, {
      executablePath: HELIUM,
      headless: HEADLESS,
      ignoreDefaultArgs: ["--disable-extensions"],
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        // Lets the tests click the toolbar button (Extensions.triggerAction).
        "--enable-unsafe-extension-debugging",
      ],
    });
    const browserSession = await context.browser().newBrowserCDPSession();
    const harness = new Harness({ context, browserSession, server, ...host });
    harness.popupPages = new Set();
    await harness.worker();
    // About one second after the start, Helium loads the page of the active
    // tab once more, which clears what a test typed into it. Let that happen
    // to a warm-up page.
    const warmUp = await context.newPage();
    await goto(warmUp, harness.url("/blank"));
    await sleep(Math.max(0, started + 2000 - Date.now()));
    await warmUp.close();
    await use(harness);
    await context.close();
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }, { scope: "worker" }],

  h: async ({ harness }, use) => {
    await harness.reset();
    await use(harness);
  },
});

export { expect };
