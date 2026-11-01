// Helium/CDP only. No Playwright imports or owner app/profile access.
// node extension-tests/cdp/save-offer-security.mjs /absolute/evidence/directory
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
const out = path.resolve(process.argv[2] || path.join(os.tmpdir(), "apassy-review39-evidence"));
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-review39-"));
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
  const positioned=await fixture("signin");
  await positioned.eval("document.body.style.minHeight='1800px'");
  const fieldRect=()=>positioned.eval("(()=>{const f=document.querySelector('#username').getBoundingClientRect();return {left:f.left,top:f.top,width:f.width}})()");
  const beforeOpen=await fieldRect(); await positioned.eval("document.querySelector('#username').focus()");
  await wait(()=>positioned.eval("!!document.querySelector('[data-apassy-login-suggestions]')"),"fixture placement");
  await delay(250); assert.deepEqual(await fieldRect(),beforeOpen);
  await positioned.eval("window.scrollTo(0,40)"); await delay(250);
  const scrollGeometry=await positioned.eval("(()=>{const f=document.querySelector('#username').getBoundingClientRect(),m=document.querySelector('[data-apassy-login-suggestions]').getBoundingClientRect();return {scrollY,field:{left:f.left,top:f.top,bottom:f.bottom},menu:{left:m.left,top:m.top,bottom:m.bottom}}})()");
  assert.equal(scrollGeometry.scrollY,40); assert.equal(scrollGeometry.menu.left,scrollGeometry.field.left); assert(scrollGeometry.menu.top>=scrollGeometry.field.bottom||scrollGeometry.menu.bottom<=scrollGeometry.field.top);
  check("actual fixture scroll repositions field-anchored menu without insertion layout shift",scrollGeometry); await close(positioned);
  const count = () => requests().filter(r => ["save", "update"].includes(r.cmd)).length;
  async function offer(existing = false) {
    const p = await fixture("xhr", existing); await submit(p, "xhr");
    await wait(async () => (await shadowText(p, "data-apassy-save-offer")).includes(existing ? "Update the password" : "Save this login"), "offer");
    return p;
  }
  const { shadowNodes } = await import("./closed-shadow.mjs");
  async function privateCall(p, nodeName, functionDeclaration) {
    const node = (await shadowNodes(p, "data-apassy-save-offer")).find(n => n.nodeName === nodeName);
    const { object } = await p.send("DOM.resolveNode", { nodeId: node.nodeId });
    const result = await p.send("Runtime.callFunctionOn", { objectId: object.objectId, functionDeclaration, returnByValue: true });
    await p.send("Runtime.releaseObject", { objectId: object.objectId });
    return result.result.value;
  }
  // Observe everything a page can observe, then remove the source input so only
  // the extension's retained copy remains. The attacker gets no secret back.
  let p = await fixture("xhr");
  await p.eval(`window.observed=[];window.channels=[];new MutationObserver(ms=>observed.push(...ms.map(m=>({type:m.type,text:m.target.textContent,html:m.target.outerHTML})))).observe(document.documentElement,{subtree:true,childList:true,attributes:true,characterData:true});addEventListener('message',e=>channels.push(e.data));addEventListener('apassy',e=>channels.push(e.detail));`);
  await submit(p, "xhr"); await wait(async () => (await shadowText(p, "data-apassy-save-offer")).includes("Save this login"), "observed offer");
  await p.eval("document.querySelector('form').remove()");
  assert.equal(await p.eval("document.querySelector('[data-apassy-save-offer]').shadowRoot"), null);
  assert(!(await p.eval("JSON.stringify({observed,channels,html:document.documentElement.outerHTML})")).includes(secret));
  const n = count();
  await p.eval("document.querySelector('[data-apassy-save-offer]').click();dispatchEvent(new MessageEvent('message',{data:{type:'login_save_action',action:'accept',trustedGesture:true}}));dispatchEvent(new CustomEvent('apassy',{detail:{type:'login_save_action',action:'accept',trustedGesture:true}}));document.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))");
  await privateCall(p, "BUTTON", "function(){this.click();this.dispatchEvent(new MouseEvent('click',{bubbles:true}))}");
  await delay(500); assert.equal(count(),n);
  check("closed root, DOM mutation and shared-channel probes expose no retained secret; synthetic actions refused");
  // Page CSS can hide/move the host, but cannot hide/move its private top-layer UI.
  await p.eval("document.querySelector('[data-apassy-save-offer]').style.opacity='0'");
  await shadowButton(p,"data-apassy-save-offer","Save"); await delay(250); assert.equal(count(),n);
  check("opacity-zero host cannot activate Save");
  await p.eval("document.querySelector('[data-apassy-save-offer]').style.cssText='font-size:0!important;color:transparent!important;direction:rtl;writing-mode:vertical-rl'");
  const inherited=await privateCall(p,"SECTION","function(){const s=getComputedStyle(this);return {fontSize:s.fontSize,color:s.color,writingMode:s.writingMode,direction:s.direction}}");
  assert.equal(inherited.fontSize,"13px"); assert.equal(inherited.writingMode,"horizontal-tb"); assert.equal(inherited.direction,"ltr"); assert(!['rgba(0, 0, 0, 0)','transparent'].includes(inherited.color));
  check("inherited host styles cannot camouflage the private action labels",inherited);
  await p.eval("document.querySelector('[data-apassy-save-offer]').style.cssText='opacity:0!important;transform:translate(-900px,700px)!important;display:none!important';document.documentElement.style.opacity='0'");
  const surface = await privateCall(p, "SECTION", "function(){const r=this.getBoundingClientRect();return {visible:this.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}),opacity:getComputedStyle(this).opacity,top:r.top,right:r.right,open:this.matches(':popover-open')}}");
  // display:none on an ancestor is allowed to suppress UI. It must fail closed.
  await shadowButton(p,"data-apassy-save-offer","Save").catch(()=>{}); await delay(250);
  assert.equal(count(),n); check("host/ancestor hiding cannot activate Save", surface); await close(p);
  // A visually opaque, pointer-transparent top-layer overlay must not trick the
  // visibility gate even though the real pointer events reach the private button.
  p = await offer();
  await p.eval("const cover=document.createElement('div');cover.popover='manual';cover.style.cssText='position:fixed;inset:0;margin:0;width:100vw;height:100vh;background:white;pointer-events:none';document.body.append(cover);cover.showPopover()");
  const before=count(); await shadowButton(p,"data-apassy-save-offer","Save"); await delay(250); assert.equal(count(),before);
  check("pointer-transparent opaque top-layer overlay blocks trusted Save"); await close(p);
  for (const existing of [false,true]) {
    p = await offer(existing); const before=count();
    await shadowButton(p,"data-apassy-save-offer",existing?"Update":"Save");
    await wait(()=>count()===before+1,"visible owner-path action");
    check((existing?"Update":"Save")+" visible trusted click reaches mock owner path once"); await close(p);
  }
  for (const attack of ["formaction", "formtarget", "formaction-race", "otp", "search", "synthetic-submit"]) {
    p = await fixture("xhr");
    await input(p,"#username",username); await input(p,"#password",secret);
    if(attack==="formaction") await p.eval("document.querySelector('#submit').setAttribute('formaction','https://other.example/login')");
    if(attack==="formtarget") await p.eval("document.querySelector('#submit').setAttribute('formtarget','another-frame')");
    if(attack==="formaction-race") await p.eval("document.querySelector('#submit').addEventListener('click',()=>document.querySelector('form').action='https://other.example/login')");
    if(attack==="otp") await p.eval("document.querySelector('#password').id='otp'");
    if(attack==="search") await p.eval("const q=document.createElement('input');q.type='search';document.querySelector('form').append(q)");
    if(attack==="synthetic-submit") await p.eval("document.querySelector('#submit').click()"); else await click(p,"#submit");
    await delay(700);
    assert.equal(await p.eval("!!document.querySelector('[data-apassy-save-offer]')"),false);
    check(attack+" cannot produce an offer"); await close(p);
  }
  // No capture from either same-origin or cross-origin iframe content.
  for(const cross of [false,true]) {
    p=await fixture("xhr"); await p.eval(`document.body.innerHTML='<iframe src="${cross?base.replace('localhost','127.0.0.1'):base}/offer/xhr" style="width:800px;height:700px"></iframe>'`);
    await delay(700);
    const tab=(await w.eval("chrome.tabs.query({})")).find(t=>t.url===base+"/offer/xhr");
    const frames=await w.eval(`chrome.scripting.executeScript({target:{tabId:${tab.id},allFrames:true},func:()=>({top:self===top,save:!!self.apassyLoginSave})})`);
    assert(frames.filter(f=>!f.result.top).every(f=>!f.result.save));
    check((cross?"cross":"same")+"-origin iframe cannot install capture listeners"); await close(p);
  }
  p=await offer(); const tab=(await w.eval("chrome.tabs.query({})")).find(t=>t.url===base+"/offer/xhr");
  await shadowButton(p,"data-apassy-save-offer","Not now");
  await wait(async()=>!(await w.eval(`self.apassySaveTest.pendingSaves.has(${tab.id})`)),"dismiss cleanup"); check("dismiss erases worker capture"); await close(p);
  p=await offer(); const closeTab=(await w.eval("chrome.tabs.query({})")).find(t=>t.url===base+"/offer/xhr"); await close(p);
  await wait(async()=>!(await w.eval(`self.apassySaveTest.pendingSaves.has(${closeTab.id})`)),"tab close cleanup"); check("tab close erases worker capture");
  p=await offer(); await p.send("Page.navigate",{url:base.replace('localhost','127.0.0.1')+"/offer/done"}); await delay(300);
  assert.equal(await w.eval("self.apassySaveTest.pendingSaves.size"),0); check("origin change erases worker capture"); await close(p);
  p=await offer();
  assert.equal(await w.eval(`Promise.all([chrome.storage.local.get(null),chrome.storage.sync.get(null),chrome.storage.session.get(null)]).then(x=>!JSON.stringify(x).includes(${JSON.stringify(secret)}))`),true);
  const storageTab=(await w.eval("chrome.tabs.query({})")).find(t=>t.url===base+"/offer/xhr");
  const sessionAccess=await w.eval(`chrome.scripting.executeScript({target:{tabId:${storageTab.id}},func:async()=>{try {if(!chrome.storage.session)return false;await chrome.storage.session.get(null);return true;}catch{return false;}}})`);
  assert.equal(sessionAccess[0].result,false); check("storage has no captured password; session storage is inaccessible to content scripts");
  await p.send("ServiceWorker.enable");
  const version=await wait(()=>p.events.flatMap(e=>e.method==='ServiceWorker.workerVersionUpdated'?e.params.versions:[]).find(v=>v.scriptURL===extensionOrigin+'background.js'&&v.runningStatus==='running'),"worker version");
  w.close(); w=null; await delay(100);
  await p.send("ServiceWorker.stopWorker",{versionId:version.versionId});
  await wait(async()=>!(await targets()).some(t=>t.type==='service_worker'&&t.url===extensionOrigin+'background.js'),"stopped worker target removed");
  await p.send("ServiceWorker.startWorker",{scopeURL:extensionOrigin});
  await wait(async()=>(await targets()).some(t=>t.type==='service_worker'&&t.url===extensionOrigin+'background.js'),"new worker target");
  w=await worker(); assert.equal(await w.eval("self.apassySaveTest.pendingSaves.size"),0);
  const beforeRestart=count(); await shadowButton(p,"data-apassy-save-offer","Save"); await delay(250); assert.equal(count(),beforeRestart);
  check("service-worker stop/restart loses capture; old banner cannot send it"); await close(p);
  p=await offer(); await w.eval("chrome.permissions.remove({origins:['https://*/*','http://localhost/*']})");
  await wait(async()=>await w.eval("self.apassySaveTest.pendingSaves.size===0"),"revoke cleanup"); await wait(()=>p.eval("!document.querySelector('[data-apassy-save-offer]')"),"revoked content script stopped"); check("permission revocation erases worker capture"); await close(p);
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
