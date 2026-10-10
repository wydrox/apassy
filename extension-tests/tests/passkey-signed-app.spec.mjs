// Opt-in rejection check of the signed Apassy browser host and caller guard.
//
// Playwright drives Helium over --remote-debugging-pipe and loads the extension
// with --load-extension. The unpacked copy has the key of the store extension,
// so Helium gives the host the expected origin. That is the forgery that the
// guard refuses (docs/contracts/browser-v1.md, section 9.4): the signed host
// must answer `unsupported` to every passkey and code request, and the app must
// never see one. A legacy `status` still reaches the app, so the host runs.
//
// This test cannot accept anything: a browser that Playwright starts is never a
// normal browser for the guard. The positive check is manual, in Helium started
// from the Finder or the Dock, with the extension from the Chrome Web Store.
//
// Set APASSY_NATIVE_TEST_BUNDLE to an Apassy.app whose host and guard carry the
// Developer ID signature of the Apassy team. A fake app on a temporary socket
// answers `status`; no vault, no desktop app, and no real profile is used.

import { test, expect, chromium } from "@playwright/test";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUNDLE = process.env.APASSY_NATIVE_TEST_BUNDLE;
const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
const ID = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
const ORIGIN = `chrome-extension://${ID}/`;
const TEAM = "7S3F9767BM";

// The team of a valid signed program, from `codesign -dv` (it writes to standard error).
function team(program) {
  execFileSync("/usr/bin/codesign", ["--verify", "--strict", program]);
  const info = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=2", program], { encoding: "utf8" });
  return /^TeamIdentifier=(\S+)$/m.exec(info.stderr)?.[1];
}

// A fake app on browser.sock: it records each request and answers `status`.
function startApp(socket, requests) {
  const server = net.createServer((connection) => {
    let buffer = "";
    connection.on("data", (chunk) => {
      buffer += chunk;
      const end = buffer.indexOf("\n");
      if (end < 0) return;
      const request = JSON.parse(buffer.slice(0, end));
      requests.push(request.cmd);
      const answer = request.cmd === "status"
        ? { ok: true, code: "ok", message: "ok", data: { type: "status", vault: "locked", version: "test" } }
        : { ok: false, code: "refused", message: "the test app answers nothing else", data: { type: "none" } };
      connection.end(JSON.stringify(answer) + "\n");
    });
  });
  return new Promise((resolve) => server.listen(socket, () => resolve(server)));
}

// One request over a native port of its own, from the service worker.
function ask(worker, message) {
  return worker.evaluate((message) => new Promise((resolve) => {
    const port = chrome.runtime.connectNative("com.wydrox.apassy");
    const timer = setTimeout(() => {
      port.disconnect();
      resolve({ code: "test_timeout" });
    }, 30_000);
    port.onMessage.addListener((answer) => {
      clearTimeout(timer);
      port.disconnect();
      resolve(answer);
    });
    port.onDisconnect.addListener(() => {
      clearTimeout(timer);
      resolve({ code: "disconnected", message: chrome.runtime.lastError?.message });
    });
    port.postMessage(message);
  }), message);
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

test("the signed host refuses passkeys and codes from a browser started with test switches", async () => {
  test.skip(!BUNDLE, "Requires an Apassy.app signed by the Apassy team.");
  test.setTimeout(120_000);
  const bundle = fs.realpathSync(BUNDLE);
  const host = path.join(bundle, "Contents/MacOS/apassy-browser-host");
  const guard = path.join(bundle, "Contents/MacOS/apassy-browser-guard");
  // An unsigned or ad hoc guard refuses everything; that would prove nothing here.
  expect(team(host)).toBe(TEAM);
  expect(team(guard)).toBe(TEAM);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aps-"));
  const profile = path.join(root, "profile");
  const hosts = path.join(profile, "NativeMessagingHosts");
  fs.mkdirSync(hosts, { recursive: true });
  fs.writeFileSync(path.join(hosts, "com.wydrox.apassy.json"), JSON.stringify({
    name: "com.wydrox.apassy", description: "Apassy rejection check",
    path: host, type: "stdio", allowed_origins: [ORIGIN],
  }));
  const extension = path.resolve(HERE, "../../extension");
  const requests = [];
  const app = await startApp(path.join(root, "b.sock"), requests);
  let context;
  try {
    const env = { ...process.env, APASSY_BROWSER_SOCKET: path.join(root, "b.sock") };
    delete env.APASSY_BROWSER_GUARD;
    context = await chromium.launchPersistentContext(profile, {
      executablePath: HELIUM, headless: true, env,
      ignoreDefaultArgs: ["--disable-extensions"],
      args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    });
    let worker = context.serviceWorkers().find((w) => w.url().startsWith(ORIGIN));
    if (!worker) worker = await context.waitForEvent("serviceworker");

    // The host runs and reaches the app for a command without a caller check.
    expect(await ask(worker, { v: 1, cmd: "status" })).toMatchObject({ ok: true, code: "ok" });
    expect(requests).toEqual(["status"]);

    const client = JSON.stringify({
      type: "webauthn.get", challenge: b64url(new Uint8Array(32).fill(1)),
      origin: "https://example.com", crossOrigin: false,
    });
    const guarded = [
      {
        v: 1, cmd: "passkey_get", rid: "3b241101-e2bb-4255-8caf-4136c566a962",
        origin: "https://example.com", rp_id: "example.com",
        client_data_json: b64(Buffer.from(client)), allowed: [],
      },
      { v: 1, cmd: "fill_code", url: "https://example.com/2fa", item: 7 },
    ];
    for (const request of guarded) {
      const answer = await ask(worker, request);
      expect(answer, request.cmd).toMatchObject({ ok: false, code: "unsupported" });
      expect(answer.message, request.cmd).toContain("cannot verify");
    }
    // The guard refused in the host: the app saw no guarded request.
    expect(requests).toEqual(["status"]);
  } finally {
    await context?.close();
    app.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
