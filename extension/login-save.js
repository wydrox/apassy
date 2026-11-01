// ISOLATED world. No page bridge, password attributes, logs or persistent storage.
(() => {
  if (self !== top || !self.apassyLoginTarget) return;
  if (self.apassyLoginSave) { self.apassyLoginSave.resume(); return; }
  const api = self.apassyLoginTarget;
  const typed = api.typedTracker();
  let enabled = true, activation, attempt, monitor, banner, bannerTimer, bannerVisibility;
  const send = (m) => chrome.runtime.sendMessage(m).catch(() => ({ ok: false }));
  function removeBanner() { clearTimeout(bannerTimer); bannerVisibility?.disconnect(); bannerVisibility = null; banner?.remove(); banner = null; }
  function clearAttempt() { clearTimeout(monitor); attempt = null; }
  async function show(reply) {
    const offer = reply?.offer;
    if (!enabled || !offer || offer.until <= Date.now()) return;
    removeBanner();
    banner = document.createElement("div");
    banner.setAttribute("data-apassy-save-offer", "");
    const visibleBanner = banner;
    const root = banner.attachShadow({ mode: "closed" });
    const el = (tag, text) => { const n = document.createElement(tag); if (text) n.textContent = text; return n; };
    const style = el("style", `:host{all:initial;color-scheme:light dark;font:13px/1.5 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:light-dark(#1d1d1f,#f5f5f7)}*{box-sizing:border-box}section{all:initial;display:block;box-sizing:border-box;direction:ltr;writing-mode:horizontal-tb;font:13px/1.5 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:light-dark(#1d1d1f,#f5f5f7);color-scheme:light dark;position:fixed;inset:16px 16px auto auto;margin:0;max-height:calc(100vh - 32px);overflow:auto;width:min(380px,calc(100vw - 32px));padding:18px;border:1px solid light-dark(#d5d5da,#505055);border-radius:12px;background:light-dark(#fff,#242426);box-shadow:0 8px 32px #0003}.identity{display:flex;gap:12px;align-items:center}img{width:32px;height:32px}strong{font-size:15px}small{display:block;overflow-wrap:anywhere}small,p,.never{color:light-dark(#63636b,#b5b5bd)}p{margin:14px 0}.actions{display:flex;gap:8px;justify-content:flex-end}button{font:inherit;border:1px solid light-dark(#c6c6cd,#62626b);border-radius:7px;padding:7px 13px;cursor:pointer;background:transparent;color:inherit}button:focus-visible{outline:2px solid light-dark(#0066d6,#80b8ff);outline-offset:2px}.primary{background:light-dark(#0066d6,#80b8ff);color:light-dark(#fff,#10233a);border-color:transparent}.never{border:0;padding:4px 0;margin-top:10px;font-size:12px}button:disabled{opacity:.6}@media(forced-colors:active){section,button{border:1px solid CanvasText}}`);
    const section = el("section"); section.popover = "manual"; section.setAttribute("role", "region"); section.setAttribute("aria-label", "Apassy save login");
    const identity = el("div"); identity.className = "identity";
    const icon = el("img"); icon.src = chrome.runtime.getURL("icons/32.png"); icon.alt = "";
    const context = el("div");
    context.append(el("strong", offer.mode === "update" ? "Update the password in Apassy?" : "Save this login in Apassy?"), el("small", `${offer.site} · ${offer.username}`));
    identity.append(icon, context);
    const status = el("p", "Saving needs your approval on your Mac."); status.setAttribute("role", "status");
    const actions = el("div"); actions.className = "actions";
    let busy = false, visibleSince = null, press;
    // A closed shadow alone does not prevent transparent-host clickjacking.
    // The action surface lives in the browser top layer, outside page stacking,
    // and clipping. Explicit section styles prevent inherited text camouflage.
    // Visibility tracking also refuses opacity changes and occlusion
    // by a later page-owned top-layer element, including pointer-events:none.
    if (!section.showPopover || !("isVisible" in IntersectionObserverEntry.prototype)) return;
    const trackVisibility = (entries) => {
      for (const entry of entries) {
        if (entry.isVisible && entry.intersectionRatio === 1) visibleSince ??= performance.now();
        else { visibleSince = null; press = null; }
      }
    };
    const observer = new IntersectionObserver(trackVisibility, { trackVisibility: true, delay: 100, threshold: [1] });
    const visible = () => {
      trackVisibility(observer.takeRecords());
      return banner === visibleBanner && section.matches(":popover-open") && document.visibilityState === "visible" &&
        visibleSince !== null && performance.now() - visibleSince >= 250 &&
        section.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true });
    };
    const action = (label, name, cls) => {
      const b = el("button", label); b.type = "button"; b.className = cls || "";
      b.addEventListener("pointerdown", (event) => {
        press = event.isTrusted && event.button === 0 && visible() ? { button: b, at: performance.now() } : null;
      });
      b.addEventListener("keydown", (event) => {
        press = event.isTrusted && ["Enter", " "].includes(event.key) && root.activeElement === b && visible()
          ? { button: b, at: performance.now() } : null;
      });
      b.addEventListener("click", async (event) => {
        const activated = press?.button === b && performance.now() - press.at < 2000;
        press = null;
        if (!event.isTrusted || !activated || !visible() || busy || Date.now() >= offer.until) return;
        busy = true;
        if (name === "dismiss") removeBanner();
        else if (name === "never") { root.querySelectorAll("button").forEach((button) => { button.disabled = true; }); status.textContent = "Turning off login offers for this site…"; }
        else { root.querySelectorAll("button").forEach((button) => { button.disabled = true; }); status.textContent = "Check Touch ID on your Mac. Approve in Apassy, or use your vault passphrase if asked."; }
        const reply = await send({ type: "login_save_action", id: offer.id, action: name, trustedGesture: true });
        if (name === "never" && banner === visibleBanner) {
          if (reply.ok) removeBanner();
          else {
            status.textContent = reply.message || "Could not confirm that login offers are off. Check Apassy toolbar settings.";
            actions.replaceChildren(action("Close", "dismiss"));
            busy = false;
          }
        }
        if (name === "accept" && banner === visibleBanner) {
          status.textContent = reply.message || "Check this login in Apassy before trying again.";
          actions.replaceChildren(action("Close", "dismiss"));
          busy = false;
        }
      });
      return b;
    };
    actions.append(action("Not now", "dismiss"), action(offer.mode === "update" ? "Update" : "Save", "accept", "primary"));
    section.append(identity, status, actions, action("Never for this site", "never", "never"));
    root.append(style, section); document.documentElement.append(banner);
    section.showPopover(); // No focus transfer: the page cannot focus a private button.
    bannerVisibility = observer; observer.observe(section);
    bannerTimer = setTimeout(removeBanner, Math.max(0, offer.until - Date.now()));
  }
  function stage(scope, submitter) {
    if (!enabled || !scope || (scope.tagName === "FORM" && !scope.checkValidity())) return;
    // A page click listener can change the effective action before submit.
    // Revalidate even when this submission already has a captured click.
    if (!api.submissionAllowed(scope, submitter)) {
      if (attempt?.scope === scope) {
        const id = attempt.id; clearAttempt(); send({ type: "login_save_cancel", attempt: id });
      }
      return;
    }
    if (attempt?.scope === scope && Date.now() - attempt.at < 1000) return;
    const values = api.submission(scope, (el) => typed.has(el), submitter);
    if (!values) return;
    clearAttempt(); removeBanner();
    const id = crypto.randomUUID(), href = location.href;
    const passwordField = [...scope.querySelectorAll('input[type="password"]')].find((el) => el.value);
    const current = { id, scope, at: Date.now() };
    attempt = current;
    const message = { type: "login_save_capture", attempt: id, ...values };
    const captured = send(message);
    values.password = ""; message.password = "";
    typed.clearAll();
    // No typed value is kept in this content script after sendMessage cloned it.
    if (!passwordField) { clearAttempt(); return; }
    const poll = async () => {
      if (!enabled || attempt !== current) return;
      if (!api.submissionAllowed(scope, submitter)) {
        clearAttempt(); await send({ type: "login_save_cancel", attempt: id }); return;
      }
      const changed = location.href !== href || !scope.isConnected || !passwordField.isConnected ||
        !passwordField.getBoundingClientRect().width || !passwordField.getBoundingClientRect().height;
      if (changed) {
        clearAttempt();
        if ((await captured).ok) await show(await send({ type: "login_save_ready", attempt: id }));
      } else if (Date.now() - current.at >= 15000) {
        clearAttempt(); await send({ type: "login_save_cancel", attempt: id });
      } else monitor = setTimeout(poll, 150);
    };
    monitor = setTimeout(poll, 150);
  }
  document.addEventListener("input", (event) => {
    const field = event.composedPath()[0];
    if (enabled && field instanceof HTMLInputElement) typed.input(field, event.isTrusted);
  }, true);
  document.addEventListener("click", (event) => {
    if (!enabled || !event.isTrusted) return;
    const control = event.composedPath().find((el) => el instanceof HTMLElement && el.matches('button, input[type="submit"], input[type="image"], [role="button"]'));
    if (!control || control.disabled || control.matches('button[type="reset"], input[type="reset"]')) return;
    const scope = control.form || control.closest('form, fieldset, [role="group"]');
    if (!scope) return;
    const submit = control.matches('button:not([type]), button[type="submit"], input[type="submit"], input[type="image"]');
    if (!submit && !/^(sign\s*(in|up)|log\s*in|create\s*account|register|continue|next|change\s*password)$/i.test((control.textContent || control.value || "").trim())) return;
    activation = { scope, at: Date.now() };
    stage(scope, control);
  }, true);
  document.addEventListener("keydown", (event) => {
    if (enabled && event.isTrusted && event.key === "Enter" && api.eligible(event.composedPath()[0])) activation = { scope: api.group(event.composedPath()[0]), at: Date.now() };
  }, true);
  document.addEventListener("submit", (event) => {
    if (event.isTrusted && activation?.scope === event.target && Date.now() - activation.at < 1000) stage(event.target, event.submitter);
  }, true);
  self.apassyLoginSave = Object.freeze({
    filled(el) { typed.clear(el); },
    stop() { enabled = false; typed.clearAll(); activation = null; clearAttempt(); removeBanner(); },
    resume() { enabled = true; send({ type: "login_save_offer" }).then(show); },
  });
  // Revoked host access prevents executeScript, but messages still reach an
  // already injected isolated script. Stop before any further trusted typing.
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (message?.type === "login_features_stop" && sender.id === chrome.runtime.id && !sender.tab) self.apassyLoginSave.stop();
  });
  addEventListener("pagehide", () => { typed.clearAll(); activation = null; clearAttempt(); removeBanner(); });
  addEventListener("pageshow", () => { if (enabled) self.apassyLoginSave.resume(); });
  self.apassyLoginSave.resume();
})();
