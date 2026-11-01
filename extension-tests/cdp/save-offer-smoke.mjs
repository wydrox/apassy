// Helium/CDP only. No Playwright imports or owner app/profile access.
// node extension-tests/cdp/save-offer-smoke.mjs /absolute/evidence/directory
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startServer } from "../support/pages.mjs";
import { shadowText, shadowButton } from "./closed-shadow.mjs";
process.env.APASSY_CDP_PORT = "9411";
const { browser, worker, page, targets, delay } = await import("./cdp.mjs");
await new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once("error", () => reject(new Error("Port 9411 occupied; refusing to attach.")));
  probe.listen(9411, "127.0.0.1", () => probe.close(resolve));
});
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const out = path.resolve(process.argv[2] || path.join(os.tmpdir(), "apassy-ext2-evidence"));
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-ext2-"));
const profile = path.join(scratch, "profile"), mock = path.join(scratch, "mock");
fs.mkdirSync(out, { recursive: true }); fs.mkdirSync(mock); fs.mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
const id = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih", extensionOrigin = `chrome-extension://${id}/`;
const quote = (s) => `'${s.replaceAll("'", "'\\''")}'`;
const wrapper = path.join(scratch, "mock-host");
fs.writeFileSync(wrapper, `#!/bin/sh\nexport APASSY_MOCK_DIR=${quote(mock)}\nexec ${quote(process.execPath)} ${quote(path.join(repo, "extension-tests/mock-host/mock-host.mjs"))} "$@"\n`, { mode: 0o755 });
fs.writeFileSync(path.join(profile, "NativeMessagingHosts/com.wydrox.apassy.json"), JSON.stringify({ name: "com.wydrox.apassy", description: "Synthetic extension offer host", path: wrapper, type: "stdio", allowed_origins: [extensionOrigin] }));
const username = "alice@example.test", secret = "Synthetic-Only-42!";
function scenario(existing = false) {
  fs.writeFileSync(path.join(mock, "scenario.json"), JSON.stringify({ vault: "unlocked", logins: existing ? [{ item: 7, title: "Synthetic account", username, password: secret, site: "localhost" }] : [] }));
}
scenario();
const server = await startServer(), base = `http://localhost:${server.port}`;
const log = fs.openSync(path.join(scratch, "helium.log"), "w");
const helium = spawn("/Applications/Helium.app/Contents/MacOS/Helium", [
  `--user-data-dir=${profile}`, "--remote-debugging-port=9411", `--load-extension=${path.join(repo, "extension")}`,
  "--enable-unsafe-extension-debugging", "--headless=new", "--use-mock-keychain", "--password-store=basic",
  "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--window-size=1280,900",
], { stdio: ["ignore", log, log] });
const checks = [], geometry = [];
let b, w, currentPage;
async function wait(fn, label, count = 100) {
  for (let i = 0; i < count; i++) { try { const result = await fn(); if (result) return result; } catch {} await delay(100); }
  throw new Error(`Timed out: ${label}`);
}
const check = (name, detail = true) => { checks.push({ name, pass: true, detail }); console.log("PASS " + name); };
const handle = (message) => w.eval(`self.apassyHandle(${JSON.stringify(message)})`);
const requests = () => fs.existsSync(path.join(mock, "requests.jsonl")) ? fs.readFileSync(path.join(mock, "requests.jsonl"), "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
async function close(p) { p.close(); await b.send("Target.closeTarget", { targetId: p.id }); }
async function input(p, selector, value) {
  await p.eval(`document.querySelector(${JSON.stringify(selector)}).focus()`);
  await p.send("Input.insertText", { text: value });
}
async function click(p, selector) {
  const pos = await p.eval(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
  for (const type of ["mousePressed", "mouseReleased"]) await p.send("Input.dispatchMouseEvent", { type, ...pos, button: "left", clickCount: 1 });
}
async function paired(p, name) {
  for (const theme of ["light", "dark"]) {
    await p.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: theme }] });
    await delay(100);
    const shot = await p.send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(out, `${name}-${theme}.png`), Buffer.from(shot.data, "base64"));
  }
}
async function fixture(kind, existing = false) {
  scenario(existing);
  const p = await page(base + "/offer/" + kind);
  currentPage = p;
  await p.send("Page.bringToFront");
  await wait(() => p.eval("!!document.querySelector('#submit')"), "fixture ready");
  await wait(async () => {
    const tab = (await w.eval("chrome.tabs.query({})")).find((t) => t.url === base + "/offer/" + kind);
    if (!tab) return false;
    const r = await w.eval(`chrome.scripting.executeScript({target:{tabId:${tab.id}},func:()=>!!self.apassyLoginSave})`);
    return r[0]?.result;
  }, "content script");
  return p;
}
async function submit(p, kind) {
  if (kind !== "step2") await input(p, "#username", username);
  if (kind === "step1") { await click(p, "#submit"); await wait(() => p.eval("location.pathname==='/offer/step2'"), "step 2"); await delay(300); }
  if (kind === "change") await input(p, "#current", "Synthetic-old");
  await input(p, "#password", secret);
  if (["signup", "change"].includes(kind)) await input(p, "#confirm", secret);
  await click(p, "#submit");
}
try {
  await wait(async () => (await fetch("http://127.0.0.1:9411/json/version")).ok, "Helium start", 300);
  b = await browser(); w = await worker();
  const settings = await page("chrome://extensions/");
  for (const grant of ["https://*/*", "http://localhost/*"]) assert.equal(await settings.eval(`new Promise(r=>chrome.developerPrivate.addHostPermission('${id}',${JSON.stringify(grant)},()=>r(chrome.runtime.lastError?.message||'ok')))`), "ok");
  await close(settings);
  const popup = await page(extensionOrigin + "popup.html");
  await wait(() => popup.eval("document.querySelector('#access-prompt')?.hidden===false"), "popup");
  await click(popup, "#allow-sites");
  await wait(() => w.eval("chrome.permissions.contains({origins:['https://*/*','http://localhost/*']})"), "optional permission");
  await close(popup);
  await handle({ type: "login_access", on: true });
  check("scratch profile optional permissions and profile-local mock only");
  for (const kind of ["signin", "signup", "step1", "xhr", "click", "change"]) {
    const p = await fixture(kind, kind === "change");
    const mutationsBefore = requests().filter((r) => ["save", "update"].includes(r.cmd)).length;
    await submit(p, kind);
    const expected = kind === "change" ? "Update the password in Apassy?" : "Save this login in Apassy?";
    await wait(async () => (await shadowText(p, "data-apassy-save-offer")).includes(expected), kind + " offer");
    assert.equal(requests().filter((r) => ["save", "update"].includes(r.cmd)).length, mutationsBefore);
    assert.equal(await p.eval("document.querySelector('[data-apassy-save-offer]').shadowRoot"), null);
    assert(!(await shadowText(p, "data-apassy-save-offer")).includes(secret));
    await paired(p, kind + "-offer");
    if (kind === "signin") {
      // Page DOM cannot invoke a closed-shadow action; element.click is untrusted.
      const tab = (await w.eval("chrome.tabs.query({})")).find((t) => t.url === base + "/offer/done");
      await w.eval(`chrome.scripting.executeScript({target:{tabId:${tab.id}},func:()=>document.querySelector('[data-apassy-save-offer]').click()})`);
      assert.equal(requests().filter((r) => r.cmd === "save").length, mutationsBefore);
    }
    await shadowButton(p, "data-apassy-save-offer", kind === "change" ? "Update" : "Save");
    await wait(async () => (await shadowText(p, "data-apassy-save-offer")).includes(kind === "change" ? "Login updated" : "Login saved"), "native mock outcome");
    assert.equal(requests().filter((r) => ["save", "update"].includes(r.cmd)).length, mutationsBefore + 1);
    await paired(p, kind + "-saved");
    check(kind + " trusted typing + submit + transition + explicit owner-path action");
    await close(p);
  }
  const filled = await fixture("signin", true);
  await filled.eval("document.querySelector('#username').focus()");
  const state = await handle({ type: "state" });
  assert.equal((await handle({ type: "fill", tabId: state.tabId, url: state.url, target: state.target, item: 7 })).ok, true);
  await click(filled, "#submit");
  await wait(() => filled.eval("location.pathname==='/offer/done'"), "filled navigation"); await delay(500);
  assert.equal(await filled.eval("!!document.querySelector('[data-apassy-save-offer]')"), false);
  await paired(filled, "filled-no-offer"); check("Apassy-filled unchanged password produces no offer"); await close(filled);
  const never = await fixture("signin"); await submit(never, "signin");
  await wait(async () => (await shadowText(never, "data-apassy-save-offer")).includes("Save this login"), "never offer");
  await shadowButton(never, "data-apassy-save-offer", "Never for this site");
  await wait(async () => (await handle({ type: "login_access_state" })).siteOff, "site off");
  await never.send("Page.navigate", { url: base + "/offer/signin" }); await wait(() => never.eval("!!document.querySelector('#submit')"), "never reload");
  await submit(never, "signin"); await wait(() => never.eval("location.pathname==='/offer/done'"), "never done"); await delay(500);
  assert.equal(await never.eval("!!document.querySelector('[data-apassy-save-offer]')"), false);
  await paired(never, "never-no-offer"); check("Never persists by hostname across navigation and reload");
  await handle({ type: "login_site", url: base, on: true }); await close(never);
  for (const [name, url, selector] of [
    ["github", "https://github.com/login", "#login_field"],
    ["google", "https://accounts.google.com/", '#identifierId, input[type="email"]'],
    ["vercel", "https://vercel.com/login", 'input[type="email"]'],
  ]) {
    const p = await page(url); await p.send("Page.bringToFront");
    await wait(() => p.eval(`!!document.querySelector(${JSON.stringify(selector)})`), name + " field", 180);
    await p.eval(`document.querySelector(${JSON.stringify(selector)}).focus()`);
    await wait(async () => {
      // Hydration can replace an initially focused field. Focus only; never type.
      await p.eval(`document.querySelector(${JSON.stringify(selector)})?.focus()`);
      return (await shadowText(p, "data-apassy-login-suggestions")).includes("No logins for this site");
    }, name + " menu");
    const rects = await p.eval(`(()=>{const f=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(),m=document.querySelector('[data-apassy-login-suggestions]').getBoundingClientRect();return {field:{left:f.left,top:f.top,bottom:f.bottom,width:f.width},menu:{left:m.left,top:m.top,bottom:m.bottom,width:m.width},viewport:{width:innerWidth,height:innerHeight}}})()`);
    assert(Math.abs(rects.menu.left - rects.field.left) < 1 || rects.menu.left === 8 || Math.abs(rects.menu.left + rects.menu.width - (rects.viewport.width - 8)) < 1);
    assert(rects.menu.top >= rects.field.bottom || rects.menu.bottom <= rects.field.top);
    assert(rects.menu.width >= Math.min(rects.field.width, rects.viewport.width - 16));
    // Reading/positioning the menu must not move the site's field.
    const layout = await p.eval(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {left:r.left,top:r.top,width:r.width}})()`);
    await delay(250);
    assert.deepEqual(await p.eval(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {left:r.left,top:r.top,width:r.width}})()`),layout);
    await p.send("Emulation.setDeviceMetricsOverride",{width:1000,height:800,deviceScaleFactor:1,mobile:false});
    await delay(250); await p.eval(`document.querySelector(${JSON.stringify(selector)})?.focus()`);
    await wait(()=>p.eval(`(()=>{const f=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(),m=document.querySelector('[data-apassy-login-suggestions]')?.getBoundingClientRect();return m&&m.width>0&&(m.top>=f.bottom||m.bottom<=f.top)&&(Math.abs(m.left-f.left)<1||m.left===8||Math.abs(m.right-(innerWidth-8))<1)})()`),name+" resize placement");
    await p.eval("window.scrollBy(0,30)"); await delay(250);
    const moved = await p.eval(`(()=>{const f=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(),m=document.querySelector('[data-apassy-login-suggestions]').getBoundingClientRect();return {fieldTop:f.top,fieldBottom:f.bottom,menuTop:m.top,menuBottom:m.bottom,scrollY}})()`);
    assert(moved.menuTop>=moved.fieldBottom||moved.menuBottom<=moved.fieldTop);
    geometry.push({ name, url: await p.eval("location.href"), ...rects, afterResizeScroll:moved });
    await paired(p, name + "-placement"); check(name + " live empty-field placement", rects); await close(p);
  }
  assert(!JSON.stringify(requests()).includes(secret));
  check("native request logs redact passwords");
  fs.writeFileSync(path.join(out, "results.json"), JSON.stringify({ checks, geometry, boundary: "Synthetic fixture credentials and profile-local mock native host. No real-site typing. No owner app, vault, keychain or Touch ID. Live sites loaded and focused only. No local Playwright run." }, null, 2));
} catch (error) {
  if(currentPage) await paired(currentPage,"failure").catch(()=>{});
  fs.writeFileSync(path.join(out, "results.json"), JSON.stringify({ checks, geometry, error: error.stack, pageState: currentPage ? await currentPage.eval("({url:location.href, status:document.querySelector('#status')?.textContent, formHidden:document.querySelector('form')?.hidden, active:document.activeElement?.id})").catch(()=>null) : null, text: currentPage ? await shadowText(currentPage, "data-apassy-save-offer").catch(()=>"") : "", requests: requests().map(({cmd,username,password})=>({cmd,username,password})), pending: w ? await w.eval("[...self.apassySaveTest.pendingSaves.values()].map(({id,until,mode,accepting,documentId,offerDocument})=>({id,until,mode,accepting,documentId,offerDocument}))").catch(()=>[]) : [] }, null, 2)); throw error;
} finally {
  w?.close();
  if (b) { await b.send("Browser.close").catch(() => {}); b.close(); }
  if (helium.exitCode === null) { helium.kill("SIGTERM"); await new Promise((r) => helium.once("exit", r)); }
  server.close(); fs.closeSync(log);
  fs.copyFileSync(path.join(scratch,"helium.log"),path.join(out,"helium.log"));
  await fs.promises.rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  fs.writeFileSync(path.join(out, "cleanup.json"), JSON.stringify({ cdpPort: 9411, heliumPid: helium.pid, exitCode: helium.exitCode, signalCode: helium.signalCode, scratchProfileRemoved: !fs.existsSync(scratch) }, null, 2));
}
