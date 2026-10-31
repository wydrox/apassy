// Security regressions use a nonsecret popup transport, never the native app.
import assert from "node:assert/strict";
import { delay } from "./cdp.mjs";

export async function reviewChecks({ pop, p, w, check }) {
  const permission = await pop.eval(`(() => {
    const original = chrome.permissions.request.bind(chrome.permissions);
    self.reviewPermissionRequests = 0;
    chrome.permissions.request = () => { self.reviewPermissionRequests++; return Promise.resolve(false); };
    const box = document.getElementById('passkeys');
    box.checked = false;
    box.click();
    document.getElementById('allow-sites').click();
    chrome.permissions.request = original;
    return self.reviewPermissionRequests;
  })()`);
  assert.equal(permission, 0, "synthetic checkbox activation must not request permissions");
  check("synthetic popup choices cannot request permissions");
  const probe = await pop.eval(`(() => {
    const original = chrome.runtime.sendMessage.bind(chrome.runtime);
    self.reviewActions = [];
    chrome.runtime.sendMessage = (message) => {
      if (['fill', 'save', 'create', 'update'].includes(message.type)) {
        self.reviewActions.push(message.type);
        return Promise.resolve({ok:false,code:'cancelled',message:'Synthetic cancellation'});
      }
      return original(message);
    };
    self.reviewOriginalSend = original;
    renderSave({hasPassword:true}, {title:'Synthetic',username:'alex@example.test'});
    let trusted;
    document.querySelector('form').addEventListener('submit', e => trusted = e.isTrusted);
    document.querySelector('form').requestSubmit();
    return {trusted, actions:[...self.reviewActions]};
  })()`);
  assert.equal(probe.trusted, true, "requestSubmit creates a trusted submit event");
  assert.deepEqual(probe.actions, [], "scripted requestSubmit must not save");
  check("requestSubmit cannot authorize save despite trusted submit event");
  // A real Enter press still activates the submit button through the browser.
  await pop.send("Page.bringToFront");
  await pop.eval("document.getElementById('username').focus()");
  for (const type of ["keyDown", "keyUp"])
    await pop.send("Input.dispatchKeyEvent", {type,key:"Enter",code:"Enter",text:type==='keyDown'?'\r':'',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
  await delay(100);
  assert.deepEqual(await pop.eval("self.reviewActions"), ["save"]);
  check("trusted Enter authorizes save (nonsecret popup transport)");
  await pop.eval(`self.reviewActions=[]; renderNew({newPasswordFields:1}, {title:'Synthetic',username:'alex@example.test',length:20,symbols:true}); document.querySelector('form').requestSubmit()`);
  await delay(80);
  assert.deepEqual(await pop.eval("self.reviewActions"), []);
  check("requestSubmit cannot authorize create");
  await pop.eval("chrome.runtime.sendMessage=self.reviewOriginalSend; renderList()");
  const rows = await pop.eval(`(() => {
    return [...document.querySelectorAll('#logins li')].map(row => {
      const r = row.getBoundingClientRect();
      const fill = row.querySelector('.fill-label').getBoundingClientRect();
      const details = row.querySelector('.details').getBoundingClientRect();
      return {contained:fill.left>=r.left && fill.right<=r.right && details.right<=r.right,
        padding:r.right-details.right, outline:getComputedStyle(row).outlineWidth};
    });
  })()`);
  assert(rows.every(r => r.contained && r.padding >= 8));
  assert.equal(rows[0].outline, "2px");
  check("popup focus border contains both actions with right padding", rows);
  await pop.eval(`self.reviewState=current; renderState({...current,logins:[...current.logins,{item:99,title:'Work two',username:'second.work@example.test'}]}); const search=document.querySelector('input[type=search]'); search.value='work';search.dispatchEvent(new Event('input'));document.querySelector('button.login[data-item="99"]').focus()`);
  for (const type of ["keyDown", "keyUp"])
    await pop.send("Input.dispatchKeyEvent", {type,key:"ArrowDown",code:"ArrowDown",windowsVirtualKeyCode:40,nativeVirtualKeyCode:40});
  assert.equal(await pop.eval("document.activeElement.dataset.item"), "8");
  check("popup keyboard skips filtered accounts");
  await pop.eval("renderState(self.reviewState)");
  await p.send("Page.bringToFront");
  assert.equal(await p.eval("document.querySelector('[data-apassy-login-suggestions]').shadowRoot"), null);
  assert.equal(await p.eval("document.body.innerText.includes('alex@example.test')"), false);
  await p.eval("document.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true})); document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))");
  assert.equal(await p.eval("document.activeElement.id"), "f1");
  assert.equal(await p.eval("!!document.querySelector('[data-apassy-login-suggestions]')"), true);
  check("page cannot read closed menu or drive it with synthetic keys");
  const url = await p.eval("location.href");
  const tab = (await w.eval("chrome.tabs.query({})")).find(t => t.url === url);
  const geometry = await w.eval(`chrome.scripting.executeScript({target:{tabId:${tab.id}},func:()=>{
    const input=document.querySelector('input');
    const rect=()=>{const r=input.getBoundingClientRect(),h=document.querySelector('[data-apassy-login-button]'),b=h.getBoundingClientRect();return {hidden:getComputedStyle(h).display==='none',inside:b.left>=r.left&&b.right<=r.right&&b.top>=r.top&&b.bottom<=r.bottom}};
    dispatchEvent(new Event('resize')); const normal=rect();
    input.style.width='60px'; dispatchEvent(new Event('resize')); const narrow=rect();
    input.style.width='';
    const r=input.getBoundingClientRect(),control=document.createElement('button');
    control.textContent='Reveal';control.style.cssText='position:fixed;z-index:100;left:'+(r.right-40)+'px;top:'+r.top+'px;width:40px;height:'+r.height+'px';
    document.body.append(control);dispatchEvent(new Event('resize'));const occupied=rect();
    control.remove();dispatchEvent(new Event('resize'));
    const value=input.value;
    input.type='password';input.value='synthetic';input.dispatchEvent(new Event('input',{bubbles:true}));const populated=rect();
    input.type='text';input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));
    return {normal,narrow,occupied,populated};
  }})`);
  const result = geometry[0].result;
  assert(result.normal.inside && !result.normal.hidden);
  assert(result.narrow.hidden && result.occupied.hidden && result.populated.hidden);
  check("field icon stays inside or hides for narrow fields, site controls and typed passwords", result);
  const otp = await w.eval(`chrome.scripting.executeScript({target:{tabId:${tab.id}},func:()=>{
    const field=document.querySelector('input[type=password]'),saved=field.autocomplete;
    field.autocomplete='one-time-code';
    const eligible=self.apassyLoginTarget.eligible(field),capture=self.apassyLoginTarget.capture(document.querySelector('input'));
    field.autocomplete=saved;
    return {eligible,passwordFields:capture.passwordFields,newPasswordFields:capture.newPasswordFields};
  }})`);
  assert.deepEqual(otp[0].result, {eligible:false,passwordFields:0,newPasswordFields:0});
  check("password-masked OTP is excluded from username-form capture", otp[0].result);
  await pop.send("Page.bringToFront");
}
