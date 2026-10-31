// Visual-only fixtures and public-page geometry for the Helium smoke.
// Approval outcomes below never call a real native fill/save path.
import assert from "node:assert/strict";
import { page, delay } from "./cdp.mjs";
export async function captureStates({
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
}) {
  await p.send("Page.navigate", { url: base + "/visual-states" });
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "visual states",
  );
  const visualTab = (await w.eval("chrome.tabs.query({})")).find(
    (t) => t.url === base + "/visual-states",
  );
  // In this one scratch document, replace the inline message transport with delayed nonsecret UI outcomes.
  // This exercises the real trusted chooser and its state rendering without invoking a fill or owner check.
  const transport = async (code) =>
    w.eval(
      `chrome.scripting.executeScript({target:{tabId:${visualTab.id}},func:(code)=>{const original=chrome.runtime.sendMessage.bind(chrome.runtime);chrome.runtime.sendMessage=(m)=>m.type==='login_fill'?new Promise(r=>setTimeout(()=>r({ok:code==='ok',code,message:code==='ok'?'Login filled. Continue on this page.':'The fill was cancelled. Nothing was filled.'}),900)):original(m);},args:[${JSON.stringify(code)}]})`,
    );
  async function firstAccount(trusted = true) {
    const doc = await p.send("DOM.getDocument", { depth: -1, pierce: true });
    let found;
    function walk(n) {
      if (
        n.nodeName === "BUTTON" &&
        (n.attributes || []).includes("menuitem") &&
        !found
      )
        found = n;
      for (const c of [...(n.children || []), ...(n.shadowRoots || [])])
        walk(c);
    }
    walk(doc.root);
    assert(found);
    if (!trusted) {
      const { object } = await p.send("DOM.resolveNode", {
        nodeId: found.nodeId,
      });
      await p.send("Runtime.callFunctionOn", {
        objectId: object.objectId,
        functionDeclaration: "function(){this.click()}",
        returnByValue: true,
      });
      return;
    }
    const { model } = await p.send("DOM.getBoxModel", { nodeId: found.nodeId });
    const q = model.content;
    const x = (q[0] + q[2]) / 2,
      y = (q[1] + q[5]) / 2;
    await p.send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
    await p.send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
  }
  await firstAccount(false);
  await delay(80);
  assert(!(await text(p)).includes("Check Touch ID"));
  check("untrusted inline activation refused");
  await transport("ok");
  await firstAccount();
  await wait(
    async () => (await text(p)).includes("Check Touch ID"),
    "inline waiting",
  );
  await paired(p, "inline-waiting");
  await wait(
    async () => (await text(p)).includes("Login filled."),
    "inline success",
  );
  await paired(p, "inline-success");
  await p.eval("document.querySelector('form > button').focus()");
  await delay(1450);
  assert.equal(
    await p.eval("!!document.querySelector('[data-apassy-login-suggestions]')"),
    false,
  );
  assert.equal(await p.eval("document.activeElement.tagName"), "BUTTON");
  check("inline success collapses without moving page focus (transport fixture)");
  await p.send("Page.reload");
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "cancel choice",
  );
  await transport("cancelled");
  for (const [key, code] of [
    ["ArrowDown", 40],
    ["Enter", 13],
  ])
    for (const type of ["keyDown", "keyUp"])
      await p.send("Input.dispatchKeyEvent", {
        type,
        key,
        code: key,
        windowsVirtualKeyCode: code,
        nativeVirtualKeyCode: code,
      });
  await wait(
    async () => (await text(p)).includes("cancelled"),
    "cancel result",
  );
  await paired(p, "inline-cancelled");
  await p.send("Page.reload");
  await wait(
    async () => (await text(p)).includes("alex@example.test"),
    "keyboard",
  );
  await p.send("Input.dispatchKeyEvent", {
    type: "keyDown",
    key: "ArrowDown",
    code: "ArrowDown",
    windowsVirtualKeyCode: 40,
    nativeVirtualKeyCode: 40,
  });
  await p.send("Input.dispatchKeyEvent", {
    type: "keyUp",
    key: "ArrowDown",
    code: "ArrowDown",
    windowsVirtualKeyCode: 40,
    nativeVirtualKeyCode: 40,
  });
  await paired(p, "inline-keyboard");
  await p.send("Input.dispatchKeyEvent", {
    type: "keyDown",
    key: "Escape",
    code: "Escape",
    windowsVirtualKeyCode: 27,
    nativeVirtualKeyCode: 27,
  });
  await p.send("Input.dispatchKeyEvent", {
    type: "keyUp",
    key: "Escape",
    code: "Escape",
    windowsVirtualKeyCode: 27,
    nativeVirtualKeyCode: 27,
  });
  assert.equal(
    await p.eval("!!document.querySelector('[data-apassy-login-suggestions]')"),
    false,
  );
  assert.equal(await p.eval("document.activeElement.id"), "f1");
  check("arrow entry and Escape restore focus");
  const refused = await w.eval(
    `handleLoginField({type:'login_suggestions',token:'ignored',username:''},{id:chrome.runtime.id,tab:{id:${visualTab.id},url:${JSON.stringify(base + "/visual-states")}},frameId:1,documentLifecycle:'active',documentId:'synthetic-cross-origin',url:'https://other.example/',origin:'https://other.example'})`,
  );
  assert.equal(refused.code, "unsupported_frame");
  assert.match(refused.message, /own tab/);
  check("cross-origin frame refusal explains own-tab recovery");
  scenario({
    logins: Array.from({ length: 12 }, (_, i) => ({
      ...logins[0],
      item: i + 1,
      title: i
        ? "Account " + i
        : "A long account title that should remain readable without expanding the entire menu",
      username: i
        ? "user" + i + "@example.test"
        : "a.long.username.for.review@example.test",
    })),
  });
  await p.send("Page.reload");
  await wait(
    async () => (await text(p)).includes("Account 11"),
    "many accounts",
  );
  await paired(p, "inline-many");
  await p.send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 420,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await paired(p, "inline-small-viewport");
  await handle({ type: "login_access", on: false });
  assert.equal((await handle({ type: "login_access_state" })).on, false);
  await p.send("Page.reload");
  await delay(180);
  assert.equal(
    await p.eval("!!document.querySelector('[data-apassy-login-suggestions]')"),
    false,
  );
  check("global switch disables suggestions");
  await handle({ type: "login_access", on: true });
  scenario();
  await closePage(p);
  // Render-state fixtures cover visual outcomes without filling or saving a secret.
  const ui = await page(origin + "popup.html");
  await delay(200);
  const common = {
    host: "github.com",
    url: "https://github.com/login",
    tabId: 1,
    logins: [],
  };
  for (const state of [
    "empty",
    "vault_locked",
    "none_open",
    "host_missing",
    "not_running",
    "unsupported_page",
    "no_page",
    "host_failed",
  ]) {
    await ui.eval(
      `renderState(${JSON.stringify({ ...common, state, message: { none_open: "Open a vault in Apassy.", no_page: "Open a login page, then click Apassy.", vault_locked: "Unlock Apassy to fill logins.", host_missing: "Apassy is not connected to this browser.", not_running: "Open Apassy to fill logins.", host_failed: "Apassy did not answer. Try again.", unsupported_page: "Apassy fills logins on https pages only." }[state] || "" })})`,
    );
    await paired(ui, "popup-" + state, true);
  }
  await ui.eval(
    `renderState(${JSON.stringify({ ...common, state: "list", logins: logins.map(({ password, site, ...x }) => x) })})`,
  );
  for (const state of ["waiting", "success", "failure"]) {
    await ui.eval(
      state === "waiting"
        ? "show(element('h2','','Check Touch ID on your Mac'),accountContext({title:'Personal',username:'alex@example.test'}),note('Approve in Apassy, or use your vault passphrase if asked.'),element('p','hint','Nothing has been filled yet.'),element('button','secondary','Show Apassy'))"
        : state === "success"
          ? "show(element('h2','success','Login filled'),note('Continue on this page.'),backLink())"
          : "renderList('Apassy did not answer in time. Nothing was filled.',true)",
    );
    await paired(ui, "popup-" + state, true);
  }
  for (const kind of ["save", "new"]) {
    await ui.eval(
      `${kind === "save" ? "renderSave" : "renderNew"}({hasPassword:true,newPasswordFields:2},{title:'GitHub',username:'alex@example.test',length:20,symbols:true})`,
    );
    await paired(ui, "popup-" + kind, true);
  }
  await ui.eval(
    "renderDetails({title:'Personal',username:'alex@example.test',hasTotp:true,item:7})",
  );
  await paired(ui, "popup-details", true);
  await ui.eval(
    "renderUpdate({hasPassword:true},{title:'Personal',username:'alex@example.test',item:7})",
  );
  await paired(ui, "popup-update", true);
  await ui.eval(
    "renderSave({hasPassword:false},{title:'GitHub',username:'alex@example.test'})",
  );
  await paired(ui, "popup-save-no-password", true);
  await ui.eval(
    "renderNew({newPasswordFields:0},{title:'GitHub',username:'alex@example.test',length:20,symbols:true})",
  );
  await paired(ui, "popup-create-no-field", true);
  await ui.eval(
    "renderSave({hasPassword:true},{title:'GitHub',username:''},'Enter a username.',true)",
  );
  await paired(ui, "popup-validation", true);
  for (const [name, message] of [
    ["saved", "Saved."],
    [
      "created",
      "Filled. The new login is in Apassy. Submit the form on the page.",
    ],
    [
      "saved-not-filled",
      "The page changed. Nothing was filled. The new login is in Apassy.",
    ],
    [
      "duplicate",
      "A login with this username is already in Apassy for this page. Nothing was saved.",
    ],
    ["cancelled", "The fill was cancelled. Nothing was filled."],
  ]) {
    if (name === "duplicate")
      await ui.eval(
        `renderSave({hasPassword:true},{title:'GitHub',username:'alex@example.test'},${JSON.stringify(message)},true)`,
      );
    else if (name === "cancelled")
      await ui.eval(`renderList(${JSON.stringify(message)},false)`);
    else
      await ui.eval(
        `show(element('h2',${name === "saved-not-filled" ? "''" : "'success'"},${JSON.stringify(name === "saved" ? "Login saved" : name === "created" ? "Login created" : "Login saved, page not filled")}),accountContext({title:'Personal',username:'alex@example.test'}),note(${JSON.stringify(message)},${name === "saved-not-filled"}),backLink(true))`,
      );
    await paired(ui, "popup-" + name, true);
  }
  await closePage(ui);
  for (const [name, url, selector] of [
    ["github", "https://github.com/login", "#login_field"],
    ["google", "https://accounts.google.com/", "#identifierId"],
    ["vercel", "https://vercel.com/login", "input[type=email]"],
  ]) {
    scenario({
      logins: logins.map((x) => ({ ...x, site: new URL(url).hostname })),
    });
    const live = await page(url);
    await live.send("Page.bringToFront");
    try {
      await wait(
        () =>
          live.eval(`!!document.querySelector(${JSON.stringify(selector)})`),
        name + " field",
      );
    } catch (error) {
      await paired(live, "live-" + name + "-unavailable");
      const detail = await live.eval(
        "({title:document.title,url:location.origin+location.pathname,text:document.body.innerText.slice(0,500)})",
      );
      console.log(JSON.stringify({ name, detail }));
      throw error;
    }
    // SPA inputs can exist before the visible, writable login step is ready.
    await wait(
      () =>
        live.eval(
          `[...document.querySelectorAll(${JSON.stringify(selector)})].some(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().height&&!e.disabled&&!e.readOnly)`,
        ),
      name + " visible field",
    );
    await delay(700);
    await live.eval(
      `[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().height&&!e.disabled&&!e.readOnly).focus()`,
    );
    try {
      await wait(
        async () => (await text(live)).includes("alex@example.test"),
        name + " suggestions",
      );
    } catch (error) {
      await paired(live, "live-" + name + "-failed");
      console.log(
        JSON.stringify({
          name,
          menu: await text(live),
          page: await live.eval(
            "({title:document.title,active:document.activeElement?.outerHTML,ready:document.readyState})",
          ),
        }),
      );
      throw error;
    }
    await paired(live, "live-" + name);
    const geometry = await live.eval(
      "(()=>{const h=document.querySelector('[data-apassy-login-suggestions]'),r=h.getBoundingClientRect();return {visible:getComputedStyle(h).visibility!=='hidden',overlap:[...document.querySelectorAll('button,a[href],input[type=submit]')].filter(e=>{const b=e.getBoundingClientRect();return b.width&&b.height&&r.left<b.right&&r.right>b.left&&r.top<b.bottom&&r.bottom>b.top}).map(e=>e.textContent.trim().slice(0,50))}})()",
    );
    assert(geometry.visible, name + " menu visible");
    assert.deepEqual(geometry.overlap, []);
    check(name + " measured placement avoids actions", geometry);
    const icon = await live.eval(`(() => {
      const h=document.querySelector('[data-apassy-login-button]'),field=document.activeElement;
      const r=field.getBoundingClientRect(),b=h.getBoundingClientRect();
      const hidden=getComputedStyle(h).display==='none';
      return {hidden,inside:b.left>=r.left&&b.right<=r.right&&b.top>=r.top&&b.bottom<=r.bottom};
    })()`);
    assert(icon.hidden || icon.inside, name + " field icon stays inside input");
    check(name + " field icon is contained or hidden", icon);
    await closePage(live);
  }
}
