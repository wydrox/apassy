// Makes the images of the Chrome Web Store listing into
// design/store/chrome-web-store/:
//
//   cd extension-tests && node store/make-assets.mjs
//
// The popup in the screenshots is the real popup.html of ../extension, loaded
// in Helium and answered by the mock native host (mock-host/mock-host.mjs),
// as in the tests. The pages are served on their https addresses by a
// Playwright route (store/pages.mjs), so nothing goes to the network. The
// window around them (store/scene.html), the Touch ID prompt, the promo tile
// (store/promo.html), and the icon (packaging/AppIcon.svg) are drawn.
//
// Helium only: never Google Chrome and never a browser that Playwright
// downloads.

import { chromium } from "playwright";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { STORE_LOGINS, STORE_PAGES } from "./pages.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const OUT = path.join(ROOT, "design/store/chrome-web-store");
const EXTENSION_DIR = path.join(ROOT, "extension");
const APP_ICON_SVG = path.join(ROOT, "packaging/AppIcon.svg");
const MOCK_HOST = path.resolve(HERE, "../mock-host/mock-host.mjs");
const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
// The same as in support/fixtures.mjs: the key in the manifest fixes the id.
const EXTENSION_ID = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
const EXTENSION_ORIGIN = `chrome-extension://${EXTENSION_ID}/`;
const HEADLESS = process.env.HEADED !== "1";

// The page and the popup are taken at 1.5x and shown 1:1 in the 1280x800
// screenshot, so they show at 150 %: readable in the store. The page fills
// the window under its toolbar (store/scene.html: 1152x612 pixels).
const SCALE = 1.5;
const PAGE_VIEWPORT = { width: 768, height: 408 };
const POPUP_WIDTH = 340;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// In its first second, Helium sometimes sends a new tab to about:blank, which
// aborts the navigation (net::ERR_ABORTED). Try again then.
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

// The mock host in a temporary profile, as support/fixtures.mjs does.
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
    description: "Apassy store screenshots host",
    path: wrapper,
    type: "stdio",
    allowed_origins: [EXTENSION_ORIGIN],
  }, null, 2));
  return mockDir;
}

// Helium with the extension and the mock host. The pages come from the route.
class Extension {
  static async start(root) {
    const profile = path.join(root, "profile");
    fs.mkdirSync(profile);
    const self = new Extension();
    self.mockDir = installHost(root, profile);
    self.setScenario({ vault: "unlocked", logins: STORE_LOGINS });
    const started = Date.now();
    self.context = await chromium.launchPersistentContext(profile, {
      executablePath: HELIUM,
      headless: HEADLESS,
      viewport: PAGE_VIEWPORT,
      deviceScaleFactor: SCALE,
      colorScheme: "light",
      ignoreDefaultArgs: ["--disable-extensions"],
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        // Lets the script click the toolbar button (Extensions.triggerAction).
        "--enable-unsafe-extension-debugging",
      ],
    });
    await self.context.route(/^https:\/\//, (route) => {
      const url = new URL(route.request().url());
      const body = STORE_PAGES[`${url.origin}${url.pathname}`];
      if (!body) return route.fulfill({ status: 404, contentType: "text/plain", body: "" });
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body });
    });
    self.browserSession = await self.context.browser().newBrowserCDPSession();
    if (!self.context.serviceWorkers().some((w) => w.url().startsWith(EXTENSION_ORIGIN))) {
      await self.context.waitForEvent("serviceworker");
    }
    // About one second after the start, Helium loads the active tab once more,
    // which clears what was typed into it. Let that happen to a warm-up page.
    const warmUp = await self.context.newPage();
    await goto(warmUp, "https://github.com/login");
    await sleep(Math.max(0, started + 2000 - Date.now()));
    await warmUp.close();
    return self;
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
    return fs.readFileSync(file, "utf8").split("\n").filter(Boolean)
      .map((line) => JSON.parse(line)).filter((request) => request && request.cmd === cmd);
  }

  async targets(type) {
    const { targetInfos } = await this.browserSession.send("Target.getTargets", { filter: [{ type }] });
    return targetInfos;
  }

  // Opens a page and clicks the toolbar button for its tab, as the owner does:
  // that grants activeTab. The real popup is closed again; the script opens
  // popup.html in a tab of its own (openPopup), which it can screenshot.
  async openGranted(url, scenario) {
    for (const page of this.context.pages().slice(1)) await page.close();
    const page = await this.context.newPage();
    await goto(page, url);
    await page.bringToFront();
    const tab = (await this.targets("tab")).find((t) => t.url === url);
    if (!tab) throw new Error(`no tab target for ${url}`);
    this.setScenario({ notRunning: true });
    this.clearRequests();
    const before = new Set((await this.targets("page")).map((t) => t.targetId));
    await this.browserSession.send("Extensions.triggerAction", { id: EXTENSION_ID, targetId: tab.targetId });
    for (let i = 0; i < 250 && this.requests("status").length === 0; i += 1) await sleep(20);
    const popupUrl = `${EXTENSION_ORIGIN}popup.html`;
    let closed = false;
    for (let i = 0; i < 50 && !closed; i += 1) {
      const popup = (await this.targets("page")).find((t) => t.url === popupUrl && !before.has(t.targetId));
      if (popup) {
        await this.browserSession.send("Target.closeTarget", { targetId: popup.targetId });
        closed = true;
      } else {
        await sleep(20);
      }
    }
    if (!closed) throw new Error("the toolbar button opened no popup");
    await sleep(200);
    this.setScenario(scenario);
    this.clearRequests();
    return page;
  }

  // popup.html in a tab: the background then takes the page tab used before.
  async openPopup() {
    const popup = await this.context.newPage();
    await popup.setViewportSize({ width: POPUP_WIDTH, height: 700 });
    await goto(popup, `${EXTENSION_ORIGIN}popup.html`);
    return popup;
  }

  close() {
    return this.context.close();
  }
}

// The popup as the toolbar shows it: its body, at the width of popup.css.
async function shootPopup(popup) {
  await popup.evaluate(() => document.fonts.ready);
  const box = await popup.locator("body").boundingBox();
  if (Math.round(box.width) !== POPUP_WIDTH) throw new Error(`the popup is ${box.width} wide, not ${POPUP_WIDTH}`);
  return popup.screenshot({ clip: { x: 0, y: 0, width: POPUP_WIDTH, height: Math.ceil(box.height) } });
}

async function shootPage(page) {
  await page.evaluate(() => document.fonts.ready);
  return page.screenshot();
}

const dataUrl = (png) => `data:image/png;base64,${png.toString("base64")}`;
const fileDataUrl = (file, type) => `data:${type};base64,${fs.readFileSync(file).toString("base64")}`;

async function waitText(popup, selector, text) {
  await popup.locator(selector, { hasText: text }).first().waitFor({ state: "visible", timeout: 10_000 });
}

// Takes the real page and the real popup for each screenshot.
async function takeShots(ext) {
  const shots = {};

  // 1. The list of the logins for github.com.
  {
    const url = "https://github.com/login";
    const page = await ext.openGranted(url, { vault: "unlocked", logins: STORE_LOGINS });
    const pagePng = await shootPage(page);
    const popup = await ext.openPopup();
    await popup.locator("button.login").nth(1).waitFor();
    await waitText(popup, "#site", "github.com");
    shots.fill = { url, page: pagePng, popup: await shootPopup(popup) };
  }

  // 3. Save the login typed on a page.
  {
    const url = "https://notes.example.com/login";
    const page = await ext.openGranted(url, { vault: "unlocked", logins: STORE_LOGINS });
    await page.fill("#username", "rafal");
    await page.fill("#password", "synthetic-typed-value");
    await page.locator("#password").blur();
    const pagePng = await shootPage(page);
    const popup = await ext.openPopup();
    await popup.locator("#save-open").click();
    await popup.locator("#save-form").waitFor();
    await waitText(popup, "#save:not([disabled])", "Save");
    if (await popup.locator("#username").inputValue() !== "rafal") throw new Error("the Save view has no username");
    await popup.mouse.move(0, 0);
    shots.save = { url, page: pagePng, popup: await shootPopup(popup) };
  }

  // 4. A new password on a sign-up page.
  {
    const url = "https://shop.example.com/signup";
    const page = await ext.openGranted(url, { vault: "unlocked", logins: STORE_LOGINS });
    await page.fill("#email", "rafal@example.com");
    await page.locator("#email").blur();
    const pagePng = await shootPage(page);
    const popup = await ext.openPopup();
    await popup.locator("#new-open").click();
    await popup.locator("#new-form").waitFor();
    await waitText(popup, "#create:not([disabled])", "Create and fill");
    await popup.mouse.move(0, 0);
    shots.create = { url, page: pagePng, popup: await shootPopup(popup) };
  }

  // 2. The fill waits for Touch ID. Last: the fill of the mock never ends.
  {
    const url = "https://github.com/login";
    const page = await ext.openGranted(url, {
      vault: "unlocked", logins: STORE_LOGINS, fill: { delayMs: 10 * 60 * 1000 },
    });
    const pagePng = await shootPage(page);
    const popup = await ext.openPopup();
    await popup.locator("button.login").first().click();
    await waitText(popup, "#note", "Confirm with Touch ID");
    await popup.mouse.move(0, 0);
    shots.touch = { url, page: pagePng, popup: await shootPopup(popup) };
  }

  return shots;
}

// The store takes screenshots and promo tiles as 24-bit PNG without alpha
// (color type 2), and the icon with alpha (color type 6). The width, the
// height, and the color type are in the IHDR chunk, at bytes 16, 20, and 25.
function checkPng(png, width, height, alpha, name) {
  const w = png.readUInt32BE(16);
  const h = png.readUInt32BE(20);
  if (w !== width || h !== height) throw new Error(`${name} is ${w}x${h}, not ${width}x${height}`);
  const type = png[25];
  if (type !== (alpha ? 6 : 2)) throw new Error(`${name} has PNG color type ${type}, not ${alpha ? 6 : 2}`);
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-store-"));
  let ext;
  let shots;
  try {
    ext = await Extension.start(root);
    shots = await takeShots(ext);
  } finally {
    if (ext) await ext.close();
    fs.rmSync(root, { recursive: true, force: true });
  }

  // The compositing browser: plain Helium, no extension, at 1x.
  const browser = await chromium.launch({ executablePath: HELIUM, headless: HEADLESS });
  try {
    const context = await browser.newContext({ deviceScaleFactor: 1, colorScheme: "light" });
    const page = await context.newPage();
    const extIcon = fileDataUrl(path.join(EXTENSION_DIR, "icons/128.png"), "image/png");
    const appIcon = fileDataUrl(APP_ICON_SVG, "image/svg+xml");
    const write = (name, png, width, height, alpha = false) => {
      checkPng(png, width, height, alpha, name);
      fs.writeFileSync(path.join(OUT, name), png);
      console.log(`${name} ${width}x${height}`);
    };

    const scenes = [
      ["screenshot-1-fill.png", "Fill a login after Touch ID", shots.fill, null],
      ["screenshot-2-touch-id.png", "Touch ID for every fill", shots.touch,
        { app: "Apassy", why: "Apassy is trying to fill “GitHub” on github.com.", left: 677, top: 190 }],
      ["screenshot-3-save.png", "Save the login you typed", shots.save, null],
      ["screenshot-4-new-password.png", "A new password, straight into the vault", shots.create, null],
    ];
    await page.setViewportSize({ width: 1280, height: 800 });
    for (const [name, caption, shot, touch] of scenes) {
      await page.goto(pathToFileURL(path.join(HERE, "scene.html")).href);
      await page.evaluate((scene) => window.render(scene), {
        caption, url: shot.url, page: dataUrl(shot.page), popup: dataUrl(shot.popup), extIcon, appIcon, touch,
      });
      write(name, await page.screenshot({ type: "png" }), 1280, 800);
    }

    // The promo tile: opaque, no text.
    await page.setViewportSize({ width: 440, height: 280 });
    await page.goto(pathToFileURL(path.join(HERE, "promo.html")).href);
    write("promo-small-440x280.png", await page.screenshot({ type: "png" }), 440, 280);

    // The store icon: the app icon at 96x96 in a 128x128 image, with 16 px of
    // transparent padding. The body of AppIcon.svg is the 824 units at 100,
    // so a view box of that body plus 16/96 of it on each side.
    const pad = (824 * 16) / 96;
    const svg = fs.readFileSync(APP_ICON_SVG, "utf8").replace(
      /<svg [^>]*>/,
      `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="${100 - pad} ${100 - pad} ${824 + 2 * pad} ${824 + 2 * pad}">`,
    );
    // A 128 px viewport draws wrong in headless Helium: take a clip of a
    // larger one.
    await page.setViewportSize({ width: 400, height: 300 });
    await page.setContent(`<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block}</style></head><body>${svg}</body></html>`);
    const icon = await page.screenshot({ type: "png", omitBackground: true, clip: { x: 0, y: 0, width: 128, height: 128 } });
    write("icon-128.png", icon, 128, 128, true);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
