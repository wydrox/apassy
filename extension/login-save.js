// ISOLATED world. No page bridge, password attributes, logs or persistent storage.
(() => {
  if (self !== top || !self.apassyLoginTarget) return;
  if (self.apassyLoginSave) { self.apassyLoginSave.resume(); return; }
  const api = self.apassyLoginTarget;
  const typed = api.typedTracker();
  let enabled = true, activation, attempt, monitor, banner, bannerTimer;
  const send = (m) => chrome.runtime.sendMessage(m).catch(() => ({ ok: false }));
  function removeBanner() { clearTimeout(bannerTimer); banner?.remove(); banner = null; }
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
    const style = el("style", `:host{all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;color-scheme:light dark;font:13px/1.5 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:light-dark(#1d1d1f,#f5f5f7)}*{box-sizing:border-box}section{width:min(380px,calc(100vw - 32px));padding:18px;border:1px solid light-dark(#d5d5da,#505055);border-radius:12px;background:light-dark(#fff,#242426);box-shadow:0 8px 32px #0003}.identity{display:flex;gap:12px;align-items:center}img{width:32px;height:32px}strong{font-size:15px}small{display:block;overflow-wrap:anywhere}small,p,.never{color:light-dark(#63636b,#b5b5bd)}p{margin:14px 0}.actions{display:flex;gap:8px;justify-content:flex-end}button{font:inherit;border:1px solid light-dark(#c6c6cd,#62626b);border-radius:7px;padding:7px 13px;cursor:pointer;background:transparent;color:inherit}button:focus-visible{outline:2px solid light-dark(#0066d6,#80b8ff);outline-offset:2px}.primary{background:light-dark(#0066d6,#80b8ff);color:light-dark(#fff,#10233a);border-color:transparent}.never{border:0;padding:4px 0;margin-top:10px;font-size:12px}button:disabled{opacity:.6}@media(forced-colors:active){section,button{border:1px solid CanvasText}}`);
    const section = el("section"); section.setAttribute("role", "region"); section.setAttribute("aria-label", "Apassy save login");
    const identity = el("div"); identity.className = "identity";
    const icon = el("img"); icon.src = chrome.runtime.getURL("icons/32.png"); icon.alt = "";
    const context = el("div");
    context.append(el("strong", offer.mode === "update" ? "Update the password in Apassy?" : "Save this login in Apassy?"), el("small", `${offer.site} · ${offer.username}`));
    identity.append(icon, context);
    const status = el("p", "Saving needs your approval on your Mac."); status.setAttribute("role", "status");
    const actions = el("div"); actions.className = "actions";
    let busy = false;
    const action = (label, name, cls) => {
      const b = el("button", label); b.type = "button"; b.className = cls || "";
      b.addEventListener("click", async (event) => {
        if (!event.isTrusted || busy || Date.now() >= offer.until) return;
        busy = true;
        if (name !== "accept") removeBanner();
        else { root.querySelectorAll("button").forEach((button) => { button.disabled = true; }); status.textContent = "Check Touch ID on your Mac. Approve in Apassy, or use your vault passphrase if asked."; }
        const reply = await send({ type: "login_save_action", id: offer.id, action: name, trustedGesture: true });
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
    bannerTimer = setTimeout(removeBanner, Math.max(0, offer.until - Date.now()));
  }
  function stage(scope) {
    if (!enabled || !scope || (scope.tagName === "FORM" && !scope.checkValidity())) return;
    if (attempt?.scope === scope && Date.now() - attempt.at < 1000) return;
    const values = api.submission(scope, (el) => typed.has(el));
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
    stage(scope);
  }, true);
  document.addEventListener("keydown", (event) => {
    if (enabled && event.isTrusted && event.key === "Enter" && api.eligible(event.composedPath()[0])) activation = { scope: api.group(event.composedPath()[0]), at: Date.now() };
  }, true);
  document.addEventListener("submit", (event) => {
    if (event.isTrusted && activation?.scope === event.target && Date.now() - activation.at < 1000) stage(event.target);
  }, true);
  self.apassyLoginSave = Object.freeze({
    filled(el) { typed.clear(el); },
    stop() { enabled = false; typed.clearAll(); activation = null; clearAttempt(); removeBanner(); },
    resume() { enabled = true; send({ type: "login_save_offer" }).then(show); },
  });
  addEventListener("pagehide", () => { typed.clearAll(); activation = null; clearAttempt(); removeBanner(); });
  addEventListener("pageshow", () => { if (enabled) self.apassyLoginSave.resume(); });
  self.apassyLoginSave.resume();
})();
