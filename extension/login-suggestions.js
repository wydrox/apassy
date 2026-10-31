// Isolated-world metadata chooser. A trusted choice is the only fill trigger.
(() => {
  self.apassyLoginSuggestionsEnabled = true;
  if (self.apassyLoginSuggestions) {
    self.apassyResumeLoginSuggestions?.();
    return;
  }
  if (!self.apassyLoginTarget) return;
  self.apassyLoginSuggestions = true;
  let host,
    root,
    launcher,
    focused,
    target,
    selected,
    generation = 0,
    busy = false,
    suppressFocus = false,
    inputTimer;
  const api = self.apassyLoginTarget;
  const send = (message) =>
    chrome.runtime
      .sendMessage(message)
      .catch(() => ({
        ok: false,
        code: "host_failed",
        message: "Apassy did not answer. Try again from the toolbar.",
      }));
  const node = (tag, text, cls) => {
    const el = document.createElement(tag);
    if (text) el.textContent = text;
    if (cls) el.className = cls;
    return el;
  };
  const button = (text, fn, cls) => {
    const el = node("button", text, cls);
    el.type = "button";
    el.addEventListener("click", fn);
    return el;
  };
  function close() {
    clearTimeout(inputTimer);
    generation++;
    host?.remove();
    host = root = null;
  }
  function dismiss() {
    close();
    suppressFocus = true;
    focused?.focus();
    queueMicrotask(() => {
      suppressFocus = false;
    });
  }
  self.apassyStopLoginSuggestions = () => {
    self.apassyLoginSuggestionsEnabled = false;
    close();
    launcher?.remove();
    launcher = null;
  };
  const css = `:host{all:initial;position:fixed;z-index:2147483647;color-scheme:light dark;font:13px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:light-dark(#1d1d1f,#f5f5f7)}:host([hidden]){display:none!important}*{box-sizing:border-box}section{width:min(328px,calc(100vw - 16px));max-height:min(440px,70vh);display:flex;flex-direction:column;border:1px solid #85858e;border-radius:12px;background:light-dark(#fff,#242426);box-shadow:0 4px 20px #0003;overflow:hidden}header,footer{display:flex;align-items:center;gap:8px;padding:10px 12px;flex-shrink:0}header{border-bottom:1px solid light-dark(#e1e1e5,#424246);font-weight:600}header small{margin-left:auto;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}img{width:20px;height:20px}small,.hint,footer{color:light-dark(#63636b,#b5b5bd);font-size:12px}.body{padding:8px 12px;overflow:auto;min-height:0}.compact .body{display:none}.accounts{overflow:auto;min-height:0;padding:4px 8px}.account{display:flex;align-items:center;gap:10px;width:100%;min-height:58px;text-align:left}.mark{width:30px;height:30px;border-radius:8px;background:light-dark(#f0f0f2,#363639);display:grid;place-items:center;flex-shrink:0}.identity{flex:1;min-width:0}.identity strong,.identity small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fill{color:light-dark(#0066d6,#80b8ff)}button{font:inherit;color:inherit;border:0;border-radius:7px;background:transparent;cursor:pointer;padding:7px 8px}button:hover{background:light-dark(#edf3ff,#303c50)}button:focus-visible{outline:2px solid light-dark(#0066d6,#80b8ff);outline-offset:-2px}button:disabled{opacity:.6;cursor:default}footer{border-top:1px solid light-dark(#e1e1e5,#424246);justify-content:space-between;background:light-dark(#f6f6f7,#19191b)}footer button{font-size:12px;padding:3px}.primary{background:light-dark(#0066d6,#80b8ff);color:light-dark(#fff,#10233a)}h3{font-size:17px;line-height:1.25;margin:6px 0}p{margin:6px 0 10px}.context{border-radius:8px;padding:10px;background:light-dark(#f6f6f7,#19191b);margin:10px 0;overflow-wrap:anywhere}.context small{display:block}.tools{display:flex;gap:8px;flex-wrap:wrap}.launcher{width:24px;height:24px;padding:2px;background:light-dark(#fff,#242426);border:1px solid #85858e;border-radius:6px;display:grid;place-items:center}@media(forced-colors:active){section,.launcher{border:1px solid CanvasText}button:focus-visible{outline:2px solid Highlight}}`;
  function shadowHost(attribute) {
    const el = node("div");
    el.setAttribute(attribute, "");
    const shadow = el.attachShadow({ mode: "closed" });
    shadow.append(node("style", css));
    document.documentElement.append(el);
    return [el, shadow];
  }
  function brand() {
    const img = node("img");
    img.src = chrome.runtime.getURL("icons/32.png");
    img.alt = "";
    return img;
  }
  function fieldButton() {
    if (!launcher) {
      let shadow;
      [launcher, shadow] = shadowHost("data-apassy-login-button");
      const b = button(
        "",
        (e) => {
          if (e.isTrusted && !busy) load(true);
        },
        "launcher",
      );
      b.setAttribute("aria-label", "Show Apassy accounts (Alt+Down)");
      b.append(brand());
      shadow.append(b);
    }
    const r = focused.getBoundingClientRect();
    const x = r.right - 30,
      y = r.top + (r.height - 24) / 2;
    const rect = { left: x, right: x + 24, top: y, bottom: y + 24 };
    launcher.style.left = `${x}px`;
    launcher.style.top = `${y}px`;
    const style = getComputedStyle(focused);
    const measure = document.createElement("canvas").getContext("2d");
    if (measure) measure.font = style.font;
    // Do not cover typed text, placeholders, or a site's reveal/clear controls.
    // Password values never need measuring; hide the affordance once populated.
    const text = focused.type === "password" ? "" : focused.value || focused.placeholder;
    const textRight = r.left + (parseFloat(style.paddingLeft) || 0) +
      (measure ? measure.measureText(text).width : text.length * 12);
    const scope = focused.getRootNode();
    const hit = scope.elementsFromPoint(x + 12, y + 12)
      .find((el) => el !== launcher && el !== host);
    launcher.hidden =
      r.width < 96 || r.height < 32 || rect.left < 0 || rect.right > innerWidth ||
      rect.top < 0 || rect.bottom > innerHeight || hit !== focused ||
      textRight + 8 > x || focused.scrollLeft > 0 ||
      (focused.type === "password" && Boolean(focused.value)) ||
      obstacles().some((b) => overlaps(rect, b));
  }
  function panel() {
    if (!host) [host, root] = shadowHost("data-apassy-login-suggestions");
  }
  const overlaps = (a, b) =>
    a.left < b.right + 4 &&
    a.right > b.left - 4 &&
    a.top < b.bottom + 4 &&
    a.bottom > b.top - 4;
  function obstacles() {
    const actions = [];
    function walk(scope) {
      actions.push(
        ...scope.querySelectorAll(
          "button, a[href], [role=button], input[type=submit], input[type=button]",
        ),
      );
      for (const el of scope.querySelectorAll("*"))
        if (el.shadowRoot) walk(el.shadowRoot);
    }
    walk(document);
    return actions
      .map((el) => el.getBoundingClientRect())
      .filter(
        (r) => r.width && r.height && r.bottom > 0 && r.top < innerHeight,
      );
  }
  function position() {
    if (!focused?.isConnected) {
      close();
      launcher?.remove();
      launcher = null;
      return;
    }
    if (launcher) fieldButton();
    const section = root?.querySelector("section");
    if (!section) return;
    const box = focused.getBoundingClientRect(),
      avoid = obstacles();
    section.style.maxHeight = `${Math.min(440, innerHeight - 16)}px`;
    const width = section.getBoundingClientRect().width,
      natural = section.getBoundingClientRect().height;
    const xs = [
      ...new Set([
        box.left,
        box.right + 8,
        box.left - width - 8,
        8,
        innerWidth - width - 8,
      ]),
    ].map((x) => Math.max(8, Math.min(x, innerWidth - width - 8)));
    // Measure the actual panel. Flip, move beside the form, or shorten the list before covering an action.
    for (const height of [
      ...new Set([natural, Math.min(natural, 180), Math.min(natural, 150)]),
    ]) {
      const ys = [
        box.bottom + 6,
        box.top - height - 6,
        8,
        innerHeight - height - 8,
      ];
      const candidates = xs.flatMap((x) =>
        ys.map((y) => ({
          x,
          y,
          score: Math.hypot(x - box.left, y - box.bottom),
        })),
      );
      candidates.sort((a, b) => a.score - b.score);
      for (const { x, y } of candidates) {
        const rect = { left: x, right: x + width, top: y, bottom: y + height };
        if (
          y < 8 ||
          rect.bottom > innerHeight - 8 ||
          overlaps(rect, box) ||
          avoid.some((r) => overlaps(rect, r))
        )
          continue;
        section.classList.toggle(
          "compact",
          height < 180 && Boolean(section.querySelector(".accounts")),
        );
        section.style.maxHeight = `${height}px`;
        host.style.left = `${x}px`;
        host.style.top = `${y}px`;
        host.style.visibility = "visible";
        return;
      }
    }
    // No safe space: leave the field affordance/toolbar available instead of covering page actions.
    host.style.visibility = "hidden";
  }
  function context(login) {
    const el = node("div", "", "context");
    el.append(
      node("strong", location.hostname || new URL(document.baseURI).hostname),
      node("small", `${login.title || "Login"} · ${login.username}`),
    );
    return el;
  }
  function draw(message, logins = [], state = "message", recovery = false) {
    if (!root) return;
    host.dataset.state = logins.length ? "list" : recovery ? "recovery" : state;
    root.querySelector("section")?.remove();
    const section = node("section");
    section.setAttribute("role", "region");
    section.setAttribute("aria-label", "Apassy login suggestions");
    const header = node("header");
    header.append(
      brand(),
      node("span", "Apassy"),
      node("small", location.hostname || new URL(document.baseURI).hostname),
    );
    section.append(header);
    if (logins.length) {
      const menu = node("div", "", "accounts");
      menu.setAttribute("role", "menu");
      menu.setAttribute("aria-label", "Choose an account to fill");
      for (const login of logins) {
        const row = button("", (event) => choose(event, login), "account");
        row.setAttribute("role", "menuitem");
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            choose(event, login);
          }
        });
        row.title = `${login.title || "Login"} · ${login.username}`;
        const identity = node("span", "", "identity");
        identity.append(
          node("strong", login.title || "Login"),
          node("small", login.username),
        );
        row.append(
          node("span", (login.title || "L").slice(0, 1).toUpperCase(), "mark"),
          identity,
          node("span", "Fill", "fill"),
        );
        menu.append(row);
      }
      section.append(menu);
    }
    const body = node("div", "", "body"),
      status = node(
        logins.length ? "p" : "h3",
        message,
        logins.length ? "hint" : "",
      );
    status.setAttribute("role", "status");
    body.append(status);
    if (selected && ["waiting", "failure", "success"].includes(state))
      body.append(context(selected));
    if (state === "waiting")
      body.append(
        node(
          "p",
          "Approve in Apassy, or use your vault passphrase if asked. Nothing has been filled yet.",
          "hint",
        ),
      );
    if (state === "empty")
      body.append(
        node(
          "p",
          "Already saved? A missing Website field prevents matching. Open the login in Apassy and add this site's address.",
          "hint",
        ),
      );
    if (recovery || state === "waiting" || state === "empty")
      body.append(
        button(
          state === "waiting" ? "Show Apassy" : "Open Apassy",
          async (e) => {
            if (!e.isTrusted) return;
            const reply = await send({
              type: "login_show",
              token: target.token,
            });
            if (!reply.ok && !busy) draw(reply.message, [], "failure");
          },
          "primary",
        ),
      );
    if (state === "failure")
      body.append(
        button("Try again", (e) => {
          if (e.isTrusted && !busy) load(true);
        }),
      );
    section.append(body);
    const footer = node("footer");
    if (!busy)
      footer.append(
        button("Show all accounts", (e) => {
          if (e.isTrusted) load(true);
        }),
      );
    else footer.append(node("span", "Waiting on your Mac"));
    footer.append(button("Dismiss · Esc", dismiss));
    section.append(footer);
    section.addEventListener("keydown", (e) => {
      if (!e.isTrusted) return;
      if (e.key === "Escape") {
        e.preventDefault();
        dismiss();
        return;
      }
      if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;
      const buttons = [...section.querySelectorAll("button:not(:disabled)")],
        at = buttons.indexOf(root.activeElement);
      const next =
        e.key === "Home"
          ? 0
          : e.key === "End"
            ? buttons.length - 1
            : (at + (e.key === "ArrowUp" ? -1 : 1) + buttons.length) %
              buttons.length;
      buttons[next]?.focus();
      e.preventDefault();
    });
    root.append(section);
    position();
  }
  async function load(all = false) {
    if (!self.apassyLoginSuggestionsEnabled || busy || !focused?.isConnected)
      return;
    const capture = api.capture(focused);
    panel();
    if (!capture.ok) {
      draw(
        capture.reason === "form_origin"
          ? "This form sends your login to another origin. Open the sign-in site in its own tab."
          : "Open this sign-in form in its own tab, then use Apassy.",
        [],
        "refused",
      );
      return;
    }
    target = capture;
    selected = null;
    fieldButton();
    draw("Finding accounts…");
    const mine = ++generation;
    const reply = await send({
      type: "login_suggestions",
      token: target.token,
      username: all ? "" : capture.username,
    });
    if (mine !== generation || !root) return;
    if (reply.ok)
      draw(
        reply.logins.length
          ? "Choose an account, then approve on your Mac."
          : reply.emptyReason === "username"
            ? "No login matches this username. Show all accounts to choose another."
            : "No logins for this site",
        reply.logins,
        reply.logins.length
          ? "list"
          : reply.emptyReason === "username"
            ? "filtered"
            : "empty",
      );
    else
      draw(
        reply.code === "vault_locked" ? "Your vault is locked" : reply.message,
        [],
        "failure",
        ["not_running", "none_open", "vault_locked"].includes(reply.code),
      );
  }
  // Keep all inline fill authority here for the owner-check-window branch.
  async function choose(event, login) {
    if (!event.isTrusted || busy || !target) return;
    busy = true;
    selected = login;
    const mine = generation;
    draw("Check Touch ID on your Mac", [], "waiting");
    const reply = await send({
      type: "login_fill",
      trustedGesture: true,
      token: target.token,
      item: login.item,
    });
    busy = false;
    if (mine !== generation || !root) return;
    draw(
      reply.ok ? "Login filled. Continue on this page." : reply.message,
      [],
      reply.ok ? "success" : "failure",
    );
    if (reply.ok)
      setTimeout(() => {
        if (mine === generation) close();
      }, 1400);
  }
  function resume() {
    const field = api.active();
    if (
      !self.apassyLoginSuggestionsEnabled ||
      !api.eligible(field) ||
      busy ||
      suppressFocus
    )
      return;
    if (focused === field && root) return;
    focused = field;
    load();
  }
  self.apassyResumeLoginSuggestions = resume;
  document.addEventListener(
    "focusin",
    (e) => {
      const field = e.composedPath()[0];
      if (api.eligible(field)) resume();
    },
    true,
  );
  document.addEventListener(
    "input",
    (e) => {
      if (e.composedPath()[0] !== focused || busy) return;
      fieldButton();
      if (focused.type !== "password") {
        clearTimeout(inputTimer);
        inputTimer = setTimeout(() => load(), 120);
      }
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted) return;
      if (e.key === "Escape" && root) {
        e.preventDefault();
        e.stopPropagation();
        dismiss();
        return;
      }
      if (
        e.key === "ArrowDown" &&
        (e.altKey || api.active() === focused) &&
        api.eligible(api.active())
      ) {
        e.preventDefault();
        if (root) root.querySelector("button")?.focus();
        else {
          focused = api.active();
          load();
        }
      }
    },
    true,
  );
  document.addEventListener(
    "pointerdown",
    (e) => {
      if (!e.isTrusted) return;
      if (
        host &&
        !e.composedPath().includes(host) &&
        !e.composedPath().includes(launcher) &&
        e.composedPath()[0] !== focused
      )
        close();
    },
    true,
  );
  addEventListener("scroll", position, true);
  addEventListener("resize", position);
  addEventListener("pagehide", () => {
    close();
    launcher?.remove();
  });
  // Injection, re-enable and reload must query a field that already owns focus.
  resume();
})();
