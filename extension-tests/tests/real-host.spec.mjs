// The real native messaging host (apassy-browser-host) between Helium and a
// fake app on the browser socket. This checks what the mock host cannot: that
// the browser starts the host with the extension origin as its first argument,
// and that the framing of the Rust host matches the browser.
//
// Build the host first: cargo build --bin apassy-browser-host. Set
// APASSY_BROWSER_HOST to its path when the target directory is not ../target.

import { test as base, expect, chromium } from "@playwright/test";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../support/pages.mjs";
import { EXTENSION_DIR, EXTENSION_ID, EXTENSION_ORIGIN } from "../support/fixtures.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
const HOST = process.env.APASSY_BROWSER_HOST ||
  path.resolve(HERE, "../../target/debug/apassy-browser-host");
const PASSWORD = "real-host-canary-0123456789";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A fake app: one JSON line in, one JSON line out, as on browser.sock. While
// `mode.quiet` is set, it answers not_running, so the real popup that the
// toolbar click opens stops after its status request.
function startApp(socket, requests, mode) {
  const server = net.createServer((connection) => {
    let buffer = "";
    connection.on("data", (chunk) => {
      buffer += chunk;
      const end = buffer.indexOf("\n");
      if (end < 0) return;
      const request = JSON.parse(buffer.slice(0, end));
      requests.push(request);
      const reply = (data, message = "ok") => ({ ok: true, code: "ok", message, data });
      let answer;
      if (mode.quiet) {
        answer = { ok: false, code: "not_running", message: "quiet", data: { type: "none" } };
      } else if (request.cmd === "status") {
        answer = reply({ type: "status", vault: "unlocked", version: "test" });
      } else if (request.cmd === "logins") {
        const url = new URL(request.url);
        answer = reply({
          type: "logins",
          origin: url.origin,
          host: url.host,
          logins: [{ item: 7, title: "Local test", username: "rafal" }],
        });
      } else if (request.cmd === "save") {
        answer = reply({ type: "saved", item: 12 }, "Saved.");
      } else if (request.cmd === "fill") {
        answer = reply({
          type: "fill",
          item: request.item,
          origin: new URL(request.url).origin,
          username: "rafal",
          password: PASSWORD,
        }, "Filled.");
      } else {
        answer = { ok: false, code: "bad_request", message: "unknown", data: { type: "none" } };
      }
      connection.end(JSON.stringify(answer) + "\n");
    });
  });
  return new Promise((resolve) => server.listen(socket, () => resolve(server)));
}

const test = base.extend({
  real: [async ({}, use) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "apr-"));
    const profile = path.join(root, "profile");
    const hosts = path.join(profile, "NativeMessagingHosts");
    fs.mkdirSync(hosts, { recursive: true });
    fs.writeFileSync(path.join(hosts, "com.wydrox.apassy.json"), JSON.stringify({
      name: "com.wydrox.apassy",
      description: "Apassy",
      path: HOST,
      type: "stdio",
      allowed_origins: [EXTENSION_ORIGIN],
    }));
    const socket = path.join(root, "b.sock");
    const requests = [];
    const mode = { quiet: true };
    const app = await startApp(socket, requests, mode);
    const pages = await startServer();
    const context = await chromium.launchPersistentContext(profile, {
      executablePath: HELIUM,
      headless: process.env.HEADED !== "1",
      ignoreDefaultArgs: ["--disable-extensions"],
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        "--enable-unsafe-extension-debugging",
      ],
      env: { ...process.env, APASSY_BROWSER_SOCKET: socket },
    });
    const session = await context.browser().newBrowserCDPSession();
    let [worker] = context.serviceWorkers().filter((w) => w.url().startsWith(EXTENSION_ORIGIN));
    if (!worker) worker = await context.waitForEvent("serviceworker");
    await use({ context, session, worker, pages, requests, mode });
    await context.close();
    pages.close();
    app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }, { scope: "test" }],
});

test.skip(!fs.existsSync(HOST), `build the host first: ${HOST}`);

test("the real host passes the requests of the extension to the app", async ({ real }) => {
  const { context, session, worker, pages, requests, mode } = real;
  const url = `http://127.0.0.1:${pages.port}/login`;
  const page = await context.newPage();
  for (let attempt = 1; ; attempt += 1) {
    try {
      await page.goto(url);
      break;
    } catch (error) {
      if (attempt >= 3 || !String(error.message).includes("ERR_ABORTED")) throw error;
      await sleep(250);
    }
  }
  await page.bringToFront();

  // The toolbar button grants activeTab, as the owner's click does. Close the
  // real popup that it opens.
  const { targetInfos } = await session.send("Target.getTargets", { filter: [{ type: "tab" }] });
  const tab = targetInfos.find((t) => t.url === url);
  await session.send("Extensions.triggerAction", { id: EXTENSION_ID, targetId: tab.targetId });
  // The real popup asks for the status through the real host. Then close it.
  for (let i = 0; i < 250 && requests.length === 0; i += 1) await sleep(20);
  expect(requests[0]).toEqual({ v: 1, cmd: "status" });
  for (let i = 0; i < 100; i += 1) {
    const popup = (await session.send("Target.getTargets", { filter: [{ type: "page" }] }))
      .targetInfos.find((t) => t.url === `${EXTENSION_ORIGIN}popup.html`);
    if (popup) {
      await session.send("Target.closeTarget", { targetId: popup.targetId });
      break;
    }
    await sleep(20);
  }
  mode.quiet = false;
  requests.length = 0;

  const state = await worker.evaluate((m) => self.apassyHandle(m), { type: "state" });
  expect(state.state).toBe("list");
  expect(state.logins).toEqual([{ item: 7, title: "Local test", username: "rafal" }]);

  const reply = await worker.evaluate((m) => self.apassyHandle(m),
    { type: "fill", tabId: state.tabId, url: state.url, item: 7 });
  expect(reply).toEqual({ ok: true, code: "ok", message: "Filled.", filled: { username: true, password: true } });
  expect(JSON.stringify(reply)).not.toContain(PASSWORD);
  expect(await page.evaluate(() => [
    document.getElementById("username").value,
    document.getElementById("password").value,
  ])).toEqual(["rafal", PASSWORD]);
  expect(requests).toEqual([
    { v: 1, cmd: "status" },
    { v: 1, cmd: "logins", url },
    { v: 1, cmd: "fill", url, item: 7 },
  ]);

  // "Save this login": the password from the page goes through the real host.
  const typed = "typed-through-the-real-host-7";
  await page.evaluate((value) => { document.getElementById("password").value = value; }, typed);
  requests.length = 0;
  const saved = await worker.evaluate((m) => self.apassyHandle(m),
    { type: "save", tabId: state.tabId, url: state.url, title: "Local test", username: "rafal" });
  expect(saved).toEqual({ ok: true, code: "ok", message: "Saved.", item: 12 });
  expect(JSON.stringify(saved)).not.toContain(typed);
  expect(requests).toEqual([
    { v: 1, cmd: "save", url, title: "Local test", username: "rafal", password: typed },
  ]);
});
