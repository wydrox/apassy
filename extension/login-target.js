// ISOLATED world only. Actual nodes stay here, never in page attributes or messages.
// A token names one document, URL, form, and exact set of input nodes for five minutes.
(() => {
  if (self.apassyLoginTarget) return;
  const targets = new Map();
  const TTL = 5 * 60 * 1000;
  const words = /user|e-?mail|login|account|identifier|sign-?in|\buid\b/i;
  const passwordWords = /pass|pwd|secret/i;
  const tokens = (el) => (el.autocomplete || "").toLowerCase().split(/\s+/);
  const usable = (el) => el instanceof HTMLInputElement && !el.disabled && !el.readOnly &&
    el.type !== "hidden" && el.getBoundingClientRect().width > 0 && el.getBoundingClientRect().height > 0 &&
    (typeof el.checkVisibility !== "function" || el.checkVisibility({ visibilityProperty: true }));
  const signals = (el) => [el.name, el.id, el.autocomplete, el.getAttribute("aria-label"), el.placeholder,
    ...Array.from(el.labels || [], (label) => label.textContent)].join(" ");
  const negative = /search|one-time|\botp\b|verification|newsletter|subscribe/i;
  const user = (el) => ["text", "email", "tel"].includes(el.type) &&
    !passwordWords.test(signals(el)) && !negative.test(signals(el));
  const eligible = (el) => {
    if (!usable(el)) return false;
    if (el.type === "password") return !tokens(el).includes("one-time-code");
    if (!user(el)) return false;
    const scope = el.form || el.closest("fieldset, [role=group]") || el.parentElement;
    if (scope && /newsletter|subscribe/i.test([scope.id, scope.getAttribute("aria-label"),
      ...Array.from(scope.querySelectorAll("button, input[type=submit]"), (b) => b.textContent || b.value)].join(" ")) &&
      !scope.querySelector('input[type=password]')) return false;
    return el.type === "email" || tokens(el).includes("username") || words.test(signals(el));
  };
  function inputs(root = document) {
    const out = [];
    for (const el of root.querySelectorAll("*")) {
      if (usable(el)) out.push(el);
      if (el.shadowRoot) out.push(...inputs(el.shadowRoot));
    }
    return out;
  }
  function active() {
    let el = document.activeElement;
    while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
    return el;
  }
  const signature = (el) => [el.type, el.name, el.id, el.autocomplete].join("\0");
  function group(el) {
    return el.form || el.closest("fieldset, [role=group]") || el.parentElement || el.getRootNode();
  }
  function members(scope) {
    return inputs().filter((el) => el.form ? el.form === scope : group(el) === scope);
  }
  function capture(preferred) {
    for (const [key, t] of targets) if (Date.now() - t.at > TTL) targets.delete(key);
    while (targets.size >= 32) targets.delete(targets.keys().next().value);
    let field = eligible(preferred) ? preferred : active();
    if (field && /^(IFRAME|FRAME)$/.test(field.tagName)) return { ok: false, reason: "frame" };
    if (!eligible(field)) {
      const candidates = inputs().filter(eligible);
      const groups = [...new Set(candidates.map(group))];
      // Never infer one of two forms from document order. Prefer login over newsletter.
      const passwordGroups = groups.filter((scope) => members(scope).some((el) => el.type === "password"));
      const choices = passwordGroups.length ? passwordGroups : groups;
      if (choices.length !== 1) return { ok: false, reason: choices.length ? "ambiguous" : "no_fields" };
      field = candidates.find((el) => group(el) === choices[0]);
    }
    const scope = group(field);
    const all = members(scope);
    const passwords = all.filter((el) => el.type === "password" && !tokens(el).includes("one-time-code"));
    const username = user(field) ? field : all.find((el) => user(el) && tokens(el).includes("username")) ||
      all.find((el) => user(el) && (el.type === "email" || words.test(signals(el)))) ||
      all.find(user) || null;
    const current = field.type === "password" ? field : passwords.find((el) => tokens(el).includes("current-password")) ||
      passwords.find((el) => !tokens(el).includes("new-password")) || passwords[0] || null;
    // Multiple password fields without a real form/group need an explicit focused password.
    if (!field.form && passwords.length > 1 && field.type !== "password") return { ok: false, reason: "ambiguous" };
    const token = crypto.randomUUID();
    const form = field.form;
    if (form && form.hasAttribute("action") && new URL(form.action, document.baseURI).origin !== self.origin) return { ok: false, reason: "form_origin" };
    targets.set(token, { at: Date.now(), href: location.href, scope, field, username, current,
      passwords, all, signatures: all.map(signature), action: form ? form.action : null });
    return { ok: true, token, username: username ? username.value : "", hasPassword: Boolean(current && current.value),
      passwordFields: passwords.length, newPasswordFields: passwords.filter((el) => !tokens(el).includes("current-password")).length };
  }
  function valid(token) {
    const t = targets.get(token);
    if (!t || Date.now() - t.at > TTL || location.href !== t.href || !t.field.isConnected) return null;
    if (t.action !== null && (!t.field.form || t.field.form !== t.scope || t.field.form.action !== t.action)) return null;
    const all = members(t.scope);
    if (all.length !== t.all.length || all.some((el, i) => el !== t.all[i] || signature(el) !== t.signatures[i])) return null;
    const focused = active();
    if (eligible(focused) && !t.all.includes(focused)) return null;
    return t;
  }
  function read(token, secret = false, purpose = "login") {
    const t = valid(token);
    if (!t) return { ok: false, reason: "target" };
    let source = t.current;
    if (purpose === "update") {
      const marked = t.passwords.filter((el) => tokens(el).includes("new-password"));
      if (marked.length) {
        const extra = t.passwords.filter((el) => !marked.includes(el) && !tokens(el).includes("current-password"));
        if (extra.some((el) => !/confirm|repeat|again|verify/i.test([el.name, el.id, el.getAttribute("aria-label")].join(" ")))) {
          return { ok: false, reason: "ambiguous_password" };
        }
        const confirmations = [...marked.slice(1), ...extra];
        if (confirmations.some((el) => el.value !== marked[0].value)) return { ok: false, reason: "password_confirmation" };
        source = marked[0];
      } else if (t.passwords.length !== 1) {
        return { ok: false, reason: "ambiguous_password" };
      } else source = t.passwords[0];
    }
    return { ok: true, username: t.username ? t.username.value : "", hasPassword: Boolean(source && source.value),
      passwordFields: t.passwords.length, newPasswordFields: t.passwords.filter((el) => !tokens(el).includes("current-password")).length,
      ...(secret ? { password: source ? source.value : "" } : {}) };
  }

  function fill(token, origin, username, password, mode) {
    const t = self.origin === origin && valid(token);
    if (!t) return { ok: false, reason: "target" };
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    const put = (el, value) => {
      // Input events may synchronously replace a React/SPA form. Stop before the next field.
      if (!valid(token)) return false;
      el.focus();
      if (!valid(token)) return false;
      setter.call(el, value);
      self.apassyLoginSave?.filled(el);
      el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
      el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
      return true;
    };
    const result = { ok: false, reason: "no_fields", username: false, password: false, passwords: 0 };
    const passwords = mode === "new" ? t.passwords.filter((el) => !tokens(el).includes("current-password")) : [t.current].filter(Boolean);
    if (mode === "new" && !passwords.length) return result;
    if (t.username && username) result.username = put(t.username, username);
    for (const el of passwords) if (password && put(el, password)) { result.password = true; result.passwords++; }
    if (passwords.length && password && !result.password && !valid(token)) return { ...result, reason: "target" };
    result.ok = result.username || result.password;
    result.reason = result.ok ? "" : "target";
    return result;
  }
  function submission(scope, typed) {
    if (!scope || /search|one-time|\botp\b|verification|newsletter|subscribe/i.test([scope.id, scope.getAttribute("role"), scope.getAttribute("aria-label")].join(" "))) return null;
    if (scope.tagName === "FORM" && new URL(scope.action, document.baseURI).origin !== self.origin) return null;
    const all = members(scope);
    if (all.some((el) => tokens(el).includes("one-time-code"))) return null;
    const username = all.find((el) => user(el) && eligible(el) && tokens(el).includes("username")) || all.find((el) => user(el) && eligible(el));
    const passwords = all.filter((el) => el.type === "password" && eligible(el));
    if (!passwords.length) return username?.value.trim() ? { username: username.value.trim(), password: "" } : null;
    const marked = passwords.filter((el) => tokens(el).includes("new-password"));
    const choices = marked.length ? marked : passwords;
    const source = choices[0];
    // Prefer a marked new password in change forms; refuse ambiguous old/new pairs.
    if (!source || !typed(source) || !source.value || (!marked.length && choices.length > 1 &&
        choices.slice(1).some((el) => !/confirm|repeat|again|verify/i.test(signals(el))))) return null;
    const confirmations = passwords.filter((el) => el !== source && !tokens(el).includes("current-password"));
    if (confirmations.some((el) => el.value !== source.value)) return null;
    return { username: username?.value.trim() || "", password: source.value };
  }
  function placement(field, panel, viewport, submits = []) {
    const gap = 6, margin = 8;
    if (field.bottom < margin || field.top > viewport.height - margin || viewport.width <= margin * 2) return null;
    const width = Math.min(panel.width, viewport.width - margin * 2);
    const left = Math.max(margin, Math.min(field.left, viewport.width - width - margin));
    const below = Math.max(0, viewport.height - margin - field.bottom - gap);
    const above = Math.max(0, field.top - gap - margin);
    const coversSubmit = submits.some((r) => r.left < left + width && r.right > left &&
      r.top < field.bottom + gap + panel.height && r.bottom > field.bottom + gap);
    const flip = (coversSubmit && above >= panel.height) || (below < panel.height && above > below);
    const height = Math.min(panel.height, flip ? above : below);
    if (height < 80) return null;
    return { left, top: flip ? field.top - gap - height : field.bottom + gap, height, width };
  }
  function typedTracker({ now = () => Date.now(), schedule = setTimeout, cancel = clearTimeout } = {}) {
    const records = new Map();
    function clear(field) {
      const record = records.get(field);
      if (record) { record.value = ""; cancel(record.timer); records.delete(field); }
    }
    return Object.freeze({
      input(field, trusted) {
        if (!trusted || field.type !== "password" || !eligible(field)) return;
        clear(field);
        if (records.size >= 32) clear(records.keys().next().value);
        const record = { value: field.value, until: now() + 180000 };
        record.timer = schedule(() => clear(field), 180000);
        records.set(field, record);
      },
      has(field) { const r = records.get(field); return Boolean(r && r.until > now() && r.value === field.value); },
      clear,
      clearAll() { for (const field of records.keys()) clear(field); },
    });
  }
  self.apassyLoginTarget = Object.freeze({ capture, read, fill, eligible, active, submission, group, placement, typedTracker });
})();
