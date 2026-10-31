// Helium only. No browser library. All native requests go to a profile-local mock.
// node extension-tests/cdp/suggest-smoke.mjs [absolute-evidence-directory]
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import net from "node:net";
import { captureStates } from "./capture-states.mjs";
import { reviewChecks } from "./review-checks.mjs";
import { browser, worker, page, targets, delay } from "./cdp.mjs";
// Refuse an occupied port before creating a profile or starting Helium.
// Never attach this harness to an independently running browser.
await new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once("error", () => reject(new Error("CDP port 9371 is occupied; refusing to attach to another browser.")));
  probe.listen(9371, "127.0.0.1", () => probe.close(resolve));
});
const repo = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const out = path.resolve(
  process.argv[2] || path.join(os.tmpdir(), "apassy-suggest-smoke"),
);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-suggest-"));
const profile = path.join(root, "profile"),
  mock = path.join(root, "mock");
const id = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih",
  origin = `chrome-extension://${id}/`;
fs.mkdirSync(out, { recursive: true });
fs.mkdirSync(mock);
fs.mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
const shellQuote = (s) => `'${s.replaceAll("'", "'\\''")}'`;
const wrapper = path.join(root, "mock-host");
fs.writeFileSync(
  wrapper,
  `#!/bin/sh\nexport APASSY_MOCK_DIR=${shellQuote(mock)}\nexec ${shellQuote(process.execPath)} ${shellQuote(path.join(repo, "extension-tests/mock-host/mock-host.mjs"))} "$@"\n`,
  { mode: 0o755 },
);
fs.writeFileSync(
  path.join(profile, "NativeMessagingHosts/com.wydrox.apassy.json"),
  JSON.stringify({
    name: "com.wydrox.apassy",
    description: "Synthetic smoke host",
    path: wrapper,
    type: "stdio",
    allowed_origins: [origin],
  }),
);
const logins = [
  {
    item: 7,
    title: "Personal",
    username: "alex@example.test",
    password: "synthetic-unused",
    site: "localhost",
  },
  {
    item: 8,
    title: "Work",
    username: "alex.work@example.test",
    password: "synthetic-unused",
    site: "localhost",
  },
];
const scenario = (extra = {}) =>
  fs.writeFileSync(
    path.join(mock, "scenario.json"),
    JSON.stringify({ vault: "unlocked", logins, ...extra }),
  );
scenario();
const html = (body) =>
  `<!doctype html><html><head><meta name="color-scheme" content="light dark"><style>body{font:16px system-ui;max-width:420px;margin:150px auto;background:light-dark(#fff,#19191b);color:light-dark(#222,#eee)}input{display:block;width:300px;height:36px;margin:10px 0 20px}button{padding:10px}label{display:block}</style></head><body>${body}</body></html>`;
const fields =
  '<form><label for="f1">Email or username</label><input id="f1" autofocus><label>Password<input type="password" autocomplete="current-password"></label><button>Sign in</button></form>';
const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "text/html");
  const content = req.url.startsWith("/negative")
    ? '<form><input id="search" type="search"><input id="otp" autocomplete="one-time-code" aria-label="Username"><input id="hidden" type="hidden" name="username"><input id="readonly" readonly name="username"><input id="shown" name="password" type="text"></form><form aria-label="Newsletter"><label>Email<input id="newsletter" type="email"></label><button>Subscribe</button></form>'
    : req.url.startsWith("/action")
      ? fields.replace("<form>", '<form action="https://example.org/login">')
      : req.url.startsWith("/srcdoc")
        ? `<iframe id="frame" style="width:100%;height:600px" srcdoc="${fields.replaceAll('"', "&quot;")}"></iframe>`
        : req.url.startsWith("/blank")
          ? `<iframe id="frame" style="width:100%;height:600px"></iframe><script>frame.contentDocument.body.innerHTML=${JSON.stringify(fields)}</script>`
          : fields;
  res.end(html(content));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://localhost:${server.address().port}`;
const log = fs.openSync(path.join(root, "helium.log"), "w");
const helium = spawn(
  "/Applications/Helium.app/Contents/MacOS/Helium",
  [
    `--user-data-dir=${profile}`,
    "--remote-debugging-port=9371",
    `--load-extension=${path.join(repo, "extension")}`,
    "--enable-unsafe-extension-debugging",
    "--headless=new",
    "--use-mock-keychain",
    "--password-store=basic",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1280,900",
  ],
  { env: { ...process.env, HOME: root }, stdio: ["ignore", log, log] },
);
let b, w;
const checks = [];
const wait = async (fn, label) => {
  for (let i = 0; i < 100; i++) {
    try {
      const x = await fn();
      if (x) return x;
    } catch {}
    await delay(100);
  }
  throw new Error(`Timed out: ${label}`);
};
const check = (name, detail = true) => {
  checks.push({ name, pass: true, detail });
  console.log(`PASS ${name}`);
};
const handle = (m) => w.eval(`self.apassyHandle(${JSON.stringify(m)})`);
const closePage = async (p) => {
  p.close();
  await b.send("Target.closeTarget", { targetId: p.id });
};
async function text(p) {
  const doc = await p.send("DOM.getDocument", { depth: -1, pierce: true });
  const words = [];
  function walk(n, on = false) {
    on ||= (n.attributes || []).includes("data-apassy-login-suggestions");
    if (on && n.nodeType === 3 && !n.nodeValue.startsWith(":host"))
      words.push(n.nodeValue);
    for (const c of [
      ...(n.children || []),
      ...(n.shadowRoots || []),
      ...(n.contentDocument ? [n.contentDocument] : []),
    ])
      walk(c, on);
  }
  walk(doc.root);
  return words.join(" ");
}
async function paired(p, name, popup = false) {
  for (const theme of ["light", "dark"]) {
    await p.send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-color-scheme", value: theme }],
    });
    if (popup)
      await p.send("Emulation.setDeviceMetricsOverride", {
        width: 360,
        height: Math.min(900, await p.eval("document.body.scrollHeight")),
        deviceScaleFactor: 1,
        mobile: false,
      });
    await delay(80);
    const shot = await p.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(
      path.join(out, `${name}-${theme}.png`),
      Buffer.from(shot.data, "base64"),
    );
  }
}
try {
  await wait(
    async () => (await fetch("http://127.0.0.1:9371/json/version")).ok,
    "Helium",
  );
  b = await browser();
  w = await worker();
  // Grant only in the scratch profile, then exercise the real optional-permission API.
  const settings = await page("chrome://extensions/");
  for (const m of ["https://*/*", "http://localhost/*"])
    assert.equal(
      await settings.eval(
        `new Promise(r=>chrome.developerPrivate.addHostPermission('${id}',${JSON.stringify(m)},()=>r(chrome.runtime.lastError?.message||'ok')))`,
      ),
      "ok",
    );
  await closePage(settings);
  const permission = await page(origin + "popup.html");
  await wait(
    () => permission.eval("!document.getElementById('access-prompt').hidden"),
    "permission button",
  );
  await paired(permission, "popup-permission", true);
  const grantBox = await permission.eval(
    "(()=>{const r=document.getElementById('allow-sites').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()",
  );
  for (const type of ["mousePressed", "mouseReleased"])
    await permission.send("Input.dispatchMouseEvent", {
      type,
      ...grantBox,
      button: "left",
      clickCount: 1,
    });
  await wait(
    () =>
      w.eval(
        "chrome.permissions.contains({origins:['https://*/*','http://localhost/*']})",
      ),
    "trusted permission button",
  );
  check("one trusted popup click grants broad access");
  await closePage(permission);
  await wait(
    async () => (await handle({ type: "login_access_state" })).broad,
    "broad permission",
  );
  const p = await page(base + "/fresh");
  await p.send("Page.bringToFront");
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "fresh-site suggestions",
  );
  check("fresh site with broad access and default-on suggestions");
  assert.equal(await p.eval("document.activeElement.id"), "f1");
  check("already-focused label-only field after injection");
  await p.send("Page.reload");
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "reload autofocus",
  );
  check("reload autofocus");
  const scripts = await w.eval(
    "chrome.scripting.getRegisteredContentScripts({ids:['apassy-login-suggestions']})",
  );
  assert.equal(scripts.length, 1);
  assert.equal(scripts[0].matchOriginAsFallback, true);
  assert(scripts[0].matches.includes("https://*/*"));
  check("one broad registration with origin fallback");
  await w.eval(
    "chrome.scripting.unregisterContentScripts({ids:['apassy-login-suggestions']}).then(()=>chrome.scripting.registerContentScripts([{id:'apassy-login-suggestions',matches:['http://localhost/*'],js:['login-target.js','login-suggestions.js'],runAt:'document_idle',allFrames:true}])).then(()=>reconcileLoginScripts())",
  );
  const migrated = await w.eval(
    "chrome.scripting.getRegisteredContentScripts({ids:['apassy-login-suggestions']})",
  );
  assert.equal(migrated.length, 1);
  assert(migrated[0].matches.includes("https://*/*"));
  check("legacy per-host registration migrates without duplicates");
  await paired(p, "inline-matches");
  // Untrusted DOM activation must never send a fill request.
  const pop = await page(origin + "popup.html");
  await wait(
    () => pop.eval("document.querySelectorAll('button.login').length===2"),
    "popup",
  );
  await pop.eval("document.querySelector('button.login').click()");
  await delay(120);
  const requests = () =>
    fs.existsSync(path.join(mock, "requests.jsonl"))
      ? fs
          .readFileSync(path.join(mock, "requests.jsonl"), "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map(JSON.parse)
      : [];
  assert.equal(
    requests().filter((x) =>
      ["fill", "save", "create", "update"].includes(x.cmd),
    ).length,
    0,
  );
  check("untrusted popup activation refused");
  await reviewChecks({ pop, p, w, check });
  await paired(pop, "popup-matches", true);
  await pop.eval(
    "document.querySelector('input[type=search]').value='work';document.querySelector('input[type=search]').dispatchEvent(new Event('input'))",
  );
  assert.equal(
    await pop.eval(
      "[...document.querySelectorAll('#logins li')].filter(x=>!x.hidden).length",
    ),
    1,
  );
  check("popup metadata search");
  await paired(pop, "popup-filtered", true);
  await pop.eval("document.getElementById('settings-link').click()");
  await paired(pop, "popup-settings", true);
  await closePage(pop);
  await p.send("Page.bringToFront");
  await handle({ type: "login_site", url: base + "/fresh", on: false });
  await wait(
    () => p.eval("!document.querySelector('[data-apassy-login-suggestions]')"),
    "site disabled",
  );
  await p.send("Page.reload");
  await delay(300);
  assert.equal(
    await p.eval("!!document.querySelector('[data-apassy-login-suggestions]')"),
    false,
  );
  check("site exclusion persists across reload");
  await handle({ type: "login_site", url: base + "/fresh", on: true });
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "reenable focused",
  );
  check("re-enable already-focused field");
  await p.eval(
    "f1.value='does-not-match';f1.dispatchEvent(new Event('input',{bubbles:true}))",
  );
  await wait(
    async () => (await text(p)).includes("No login matches this username"),
    "filtered reason",
  );
  check("username empty reason distinct from Website guidance");
  await paired(p, "inline-filtered");
  scenario({ logins: [] });
  await p.eval(
    "f1.value='';f1.dispatchEvent(new Event('input',{bubbles:true}))",
  );
  await wait(
    async () => (await text(p)).includes("No logins for this site"),
    "empty",
  );
  await paired(p, "inline-empty");
  check("site empty reason and missing-Website guidance");
  scenario({ vault: "locked" });
  await p.eval("f1.dispatchEvent(new Event('input',{bubbles:true}))");
  await wait(
    async () => (await text(p)).includes("Your vault is locked"),
    "inline locked",
  );
  await paired(p, "inline-locked");
  scenario({ notRunning: true });
  await p.eval("f1.dispatchEvent(new Event('input',{bubbles:true}))");
  await wait(
    async () => (await text(p)).includes("Open Apassy"),
    "inline disconnected",
  );
  await paired(p, "inline-not-connected");
  scenario({ loginsCode: "timeout" });
  await p.eval("f1.dispatchEvent(new Event('input',{bubbles:true}))");
  await wait(
    async () =>
      (await text(p)).includes("Nothing was filled") ||
      (await text(p)).includes("in time"),
    "inline failure",
  );
  await paired(p, "inline-failure");
  scenario();
  await p.send("Page.navigate", { url: base + "/negative" });
  await delay(300);
  const tab = await w.eval(
    `chrome.tabs.query({url:${JSON.stringify(base + "/*")}})`,
  );
  const tabId = tab.find((t) => t.url.includes("/negative")).id;
  const negatives = await w.eval(
    `chrome.scripting.executeScript({target:{tabId:${tabId}},func:()=>Object.fromEntries([...document.querySelectorAll('input')].map(e=>[e.id,self.apassyLoginTarget.eligible(e)]))})`,
  );
  assert(Object.values(negatives[0].result).every((x) => x === false));
  check("search OTP hidden readonly newsletter and text-password excluded");
  await p.send("Page.navigate", { url: base + "/action" });
  await wait(
    async () => (await text(p)).includes("another origin"),
    "action refusal",
  );
  await paired(p, "inline-form-refused");
  check("cross-origin form action explains refusal");
  for (const frame of ["srcdoc", "blank"]) {
    await p.send("Page.navigate", { url: base + "/" + frame });
    await delay(200);
    await p.eval(
      "document.querySelector('iframe').contentDocument.querySelector('input').focus()",
    );
    await wait(
      async () => (await text(p)).includes("alex@example.test"),
      frame,
    );
    check("same-origin " + frame + " suggestions");
  }
  await captureStates({
    p,
    w,
    b,
    base,
    origin,
    logins,
    scenario,
    wait,
    paired,
    text,
    handle,
    check,
    closePage,
  });
  assert.equal(
    requests().filter((x) =>
      ["fill", "save", "create", "update"].includes(x.cmd),
    ).length,
    0,
  );
  check("metadata-only run, no fill/save/create/update");
  fs.writeFileSync(
    path.join(out, "smoke-results.json"),
    JSON.stringify(
      {
        checks,
        heliumPid: helium.pid,
        boundary:
          "Mock native host; synthetic metadata. Public pages loaded and focused only. Popup waiting/success/failure are render-state fixtures; inline approval/success/cancellation use a nonsecret transport fixture. No native owner check or secret fill.",
      },
      null,
      2,
    ),
  );
} catch (error) {
  fs.writeFileSync(
    path.join(out, "smoke-results.json"),
    JSON.stringify({ checks, error: error.stack }, null, 2),
  );
  throw error;
} finally {
  w?.close();
  if (b) {
    await b.send("Browser.close").catch(() => {});
    b.close();
  }
  if (helium.exitCode === null) {
    helium.kill("SIGTERM");
    await new Promise((r) => helium.once("exit", r));
  }
  await new Promise((r) => server.close(r));
  fs.closeSync(log);
  await fs.promises.rm(root, {
    recursive: true,
    force: true,
    maxRetries: 8,
    retryDelay: 100,
  });
  fs.writeFileSync(path.join(out, "cleanup.json"), JSON.stringify({
    heliumPid: helium.pid, exitCode: helium.exitCode, signalCode: helium.signalCode,
    scratchProfileRemoved: !fs.existsSync(root), cdpPort: 9371,
  }, null, 2));
}
