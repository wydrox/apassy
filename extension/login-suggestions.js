// Optional isolated-world field chooser. No page-world messages, secrets, or automatic fill.
(() => {
  self.apassyLoginSuggestionsEnabled = true;
  if (self.apassyLoginSuggestions || !self.apassyLoginTarget) return;
  self.apassyLoginSuggestions = true;
  let host, root, focused, target, generation = 0, busy = false, suppressFocus = false, inputTimer;
  const api = self.apassyLoginTarget;
  const send = (message) => chrome.runtime.sendMessage(message).catch(() => ({ ok: false, code: "host_failed", message: "Apassy did not answer. Use the Apassy toolbar to retry." }));
  function close() { clearTimeout(inputTimer); generation++; if (host) host.remove(); host = root = null; }
  function dismiss() {
    close(); suppressFocus = true; focused?.focus();
    queueMicrotask(() => { suppressFocus = false; });
  }
  self.apassyStopLoginSuggestions = () => { self.apassyLoginSuggestionsEnabled = false; close(); };
  const dismissMenu = dismiss;
  function node(tag, text) { const el = document.createElement(tag); if (text) el.textContent = text; return el; }
  function panel() {
    if (host) return;
    host = node("div");
    host.setAttribute("data-apassy-login-suggestions", "");
    // Keep page style and page DOM queries out of the account menu.
    root = host.attachShadow({ mode: "closed" });
    const style = node("style");
    style.textContent = `:host{all:initial;position:fixed;z-index:2147483647;color-scheme:light dark;font:13px/1.4 -apple-system,BlinkMacSystemFont,system-ui,sans-serif}section{box-sizing:border-box;width:min(340px,calc(100vw - 16px));max-height:55vh;overflow:auto;padding:8px;border:1px solid #84909b;border-radius:8px;background:light-dark(#fff,#141c23);color:light-dark(#0e1820,#e8edf2);box-shadow:0 3px 14px #0004}p{margin:4px 6px 8px}button{box-sizing:border-box;display:block;min-height:32px;width:100%;padding:6px 8px;text-align:left;border:0;border-radius:5px;background:transparent;color:inherit;font:inherit;cursor:pointer;white-space:normal;overflow-wrap:anywhere}button:hover{background:light-dark(#eef5ff,#1d2a36)}button:focus-visible{outline:2px solid light-dark(#0061d6,#80b8ff);outline-offset:-2px}button:disabled{opacity:.6;cursor:default}.brand{font-weight:600}.hint{color:light-dark(#4b5661,#b4bec8)}@media(forced-colors:active){section{border:1px solid CanvasText}button:focus-visible{outline:2px solid Highlight}}`;
    root.append(style);
    document.documentElement.append(host);
    position();
  }
  function position() {
    if (!host || !focused?.isConnected) return;
    const box = focused.getBoundingClientRect();
    host.style.left = `${Math.max(8, Math.min(box.left, innerWidth - 348))}px`;
    host.style.top = `${Math.max(8, Math.min(box.bottom + 4, innerHeight - 200))}px`;
  }
  function draw(message, logins = [], recovery = false) {
    if (!root) return;
    host.dataset.state = logins.length ? "list" : recovery ? "recovery" : "message";
    root.querySelector("section")?.remove();
    const section = node("section");
    section.setAttribute("role", "region");
    section.setAttribute("aria-label", "Apassy login suggestions");
    section.append(Object.assign(node("p", "Apassy"), { className: "brand" }));
    const status = node("p", message);
    status.setAttribute("role", "status");
    section.append(status);
    const menu = node("div");
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Choose an account to fill");
    for (const login of logins) {
      const button = node("button", `${login.title || "Login"} — ${login.username}`);
      button.type = "button";
      button.setAttribute("role", "menuitem");
      button.addEventListener("click", (event) => {
        if (event.isTrusted && !busy) choose(login);
      });
      menu.append(button);
    }
    if (logins.length) section.append(menu);
    if (recovery) {
      const open = node("button", "Open Apassy");
      open.type = "button";
      open.addEventListener("click", async (event) => {
        if (!event.isTrusted || busy) return;
        busy = true;
        const result = await send({ type: "login_show", token: target.token });
        busy = false;
        draw(result.ok ? "Return here after opening or unlocking your vault. Choose an account again to fill." : result.message);
      });
      section.append(open);
    }
    const all = node("button", "Show all accounts for this site");
    all.type = "button";
    all.addEventListener("click", (event) => { if (event.isTrusted && !busy) load(true); });
    const dismiss = node("button", "Dismiss suggestions");
    dismiss.type = "button";
    dismiss.addEventListener("click", () => { dismissMenu(); });
    section.append(all, dismiss);
    section.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { event.preventDefault(); dismissMenu(); return; }
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
      const buttons = [...section.querySelectorAll("button:not(:disabled)")];
      const at = buttons.indexOf(root.activeElement);
      const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 :
        (at + (event.key === "ArrowUp" ? -1 : 1) + buttons.length) % buttons.length;
      buttons[next]?.focus(); event.preventDefault();
    });
    root.append(section);
  }
  async function load(all = false) {
    if (!self.apassyLoginSuggestionsEnabled || busy || !focused?.isConnected) return;
    const capture = api.capture(focused);
    if (!capture.ok) { close(); return; }
    target = capture;
    panel();
    draw("Finding accounts for this site…");
    const mine = ++generation;
    const reply = await send({ type: "login_suggestions", token: target.token, username: all ? "" : capture.username });
    if (mine !== generation || !root) return;
    if (reply.ok) draw(reply.logins.length ? "Choose an account. Apassy asks for approval before filling." : "No matching login. In Apassy, edit the login’s Website field to include this site.", reply.logins);
    else draw(reply.message, [], ["not_running", "none_open", "vault_locked"].includes(reply.code));
  }
  async function choose(login) {
    busy = true;
    const mine = generation;
    draw("Confirm with Touch ID or your passphrase in Apassy.");
    const reply = await send({ type: "login_fill", token: target.token, item: login.item });
    busy = false;
    if (mine !== generation || !root) return;
    draw(reply.message, [], ["not_running", "none_open", "vault_locked"].includes(reply.code));
  }
  document.addEventListener("focusin", (event) => {
    const field = event.composedPath()[0];
    if (!self.apassyLoginSuggestionsEnabled || !api.eligible(field) || busy || suppressFocus) return;
    if (focused === field && root) return;
    focused = field;
    load();
  }, true);
  document.addEventListener("input", (event) => {
    if (event.composedPath()[0] === focused && focused.type !== "password" && !busy) {
      clearTimeout(inputTimer);
      inputTimer = setTimeout(() => load(), 120);
    }
  }, true);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && root) { event.preventDefault(); event.stopPropagation(); dismissMenu(); return; }
    if (event.key === "ArrowDown" && event.altKey && api.eligible(api.active())) {
      event.preventDefault();
      if (root) root.querySelector("button")?.focus(); else { focused = api.active(); load(); }
    }
  }, true);
  document.addEventListener("pointerdown", (event) => { if (host && !event.composedPath().includes(host) && event.composedPath()[0] !== focused) close(); }, true);
  addEventListener("scroll", position, true);
  addEventListener("resize", position);
  addEventListener("pagehide", close);
})();
