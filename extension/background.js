// The service worker of the Apassy extension. It is the only part that talks
// to the native messaging host (wire: docs/contracts/browser-v1.md).
//
// A fill answer holds a password. It goes from the host straight into the
// fill function in the page. It is never logged, stored, or sent to the popup.
// "Save this login" reads the password that the owner typed on the page and
// sends it straight to the host, the same way. The extension never makes a
// password: for "New password", Apassy makes it and answers with a fill.
// A one-time code goes the same way: from the host straight into the page.
//
// Passkeys (the second half of this file): passkey-page.js and
// passkey-bridge.js run in the top frame of https pages after the owner turned
// them on in the popup. This worker is the authority: it takes the origin from
// the browser (the port of the bridge), builds clientDataJSON, asks the app
// over one native port per request, and answers only the same port.

importScripts("fill.js");

const HOST = "com.wydrox.apassy";
const WIRE_VERSION = 1;
// The host waits up to 240 s for the app (an owner check waits up to 180 s).
const ANSWER_TIMEOUT_MS = 250 * 1000;
const BADGE_CLEAR_MS = 10 * 1000;

const MESSAGES = {
  host_missing: "Apassy is not connected to this browser.",
  host_failed: "Apassy did not answer. Try again.",
  timeout: "Apassy did not answer in time. Nothing was filled.",
  not_running: "Open Apassy to fill logins.",
  none_open: "Unlock Apassy to fill logins.",
  vault_locked: "Unlock Apassy to fill logins.",
  unsupported_page: "Apassy fills logins on https pages only.",
  no_page: "Open a login page, then click Apassy.",
  page_changed: "The page changed. Nothing was filled.",
  no_fields: "Apassy found no login fields on this page.",
  fill_failed: "Apassy could not fill this page.",
  no_password: "Type your password on the page first.",
  bad_request: "Apassy did not understand the request.",
  no_code_field: "Apassy found no field for a one-time code on this page.",
};

const CODE_PAGE_CHANGED = "The page changed. No code was filled.";

// After "create", the new login is in Apassy even when the page did not get
// the password. The owner must know that.
const CREATED_BUT = {
  page_changed: "The page changed. Nothing was filled. The new login is in Apassy.",
  no_fields: "Apassy found no field for a new password. The new login is in Apassy.",
  fill_failed: "Apassy could not fill this page. The new login is in Apassy.",
  host_failed: "Apassy did not answer as expected. Check the new login in Apassy.",
};

// The answer of a create was lost: the app may have added the login before.
const MAYBE_CREATED = "Apassy did not answer in time. The new login may be in Apassy: look for it before you try again.";

const READ_FAILED = "Apassy could not read this page.";
const CREATED = "Filled. The new login is in Apassy. Submit the form on the page.";
const NEW_LENGTH = { min: 12, max: 64 };

// One native port per request. The open port keeps this service worker alive
// while the app waits for Touch ID.
function ask(request) {
  return new Promise((resolve) => {
    let done = false;
    let port;
    let timer;
    const finish = (answer) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { port.disconnect(); } catch (_) { /* already closed */ }
      resolve(answer);
    };
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (_) {
      resolve(localError("host_missing"));
      return;
    }
    port.onMessage.addListener((answer) => finish(answer));
    port.onDisconnect.addListener(() => {
      const error = chrome.runtime.lastError;
      const text = error && error.message ? error.message : "";
      finish(localError(/not found|forbidden/i.test(text) ? "host_missing" : "host_failed"));
    });
    timer = setTimeout(() => finish(localError("timeout")), ANSWER_TIMEOUT_MS);
    port.postMessage({ v: WIRE_VERSION, ...request });
  });
}

function localError(code) {
  return { ok: false, code, message: MESSAGES[code] || MESSAGES.host_failed, data: { type: "none" } };
}

function messageOf(answer) {
  return (answer && typeof answer.message === "string" && answer.message) ||
    MESSAGES[answer && answer.code] || MESSAGES.host_failed;
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch (_) {
    return "";
  }
}

function isWebPage(url) {
  return /^https?:\/\//i.test(url || "");
}

// The page that the owner looks at: the active tab of the last focused window.
// When the popup itself runs in a tab (not in the toolbar), that tab is
// skipped and the tab used last before it is taken.
async function targetTab() {
  const own = chrome.runtime.getURL("");
  const isOwn = (tab) => Boolean(tab.url && tab.url.startsWith(own));
  const [active] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (active && !isOwn(active)) return active;
  const others = (await chrome.tabs.query({ windowType: "normal" }))
    .filter((tab) => !isOwn(tab))
    .sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
  return others[0] || null;
}

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch (_) {
    return "";
  }
}

// Everything the popup needs to draw itself. No secret value is in it.
async function state() {
  const tab = await targetTab();
  const url = tab && tab.url ? tab.url : "";
  const base = { tabId: tab ? tab.id : null, url, host: hostOf(url), logins: [] };
  const reply = (fields) => ({ ...base, ...fields, message: fields.message || MESSAGES[fields.state] || "" });

  const status = await ask({ cmd: "status" });
  if (!status || !status.ok) {
    const code = (status && status.code) || "host_failed";
    return reply({ state: code, message: MESSAGES[code] || messageOf(status) });
  }
  const vault = status.data && status.data.vault;
  if (vault === "locked") return reply({ state: "vault_locked" });
  if (vault !== "unlocked") return reply({ state: "none_open" });

  if (!tab || !url) return reply({ state: "no_page" });
  if (!isWebPage(url)) return reply({ state: "unsupported_page" });

  const answer = await ask({ cmd: "logins", url });
  if (!answer || !answer.ok || !answer.data || answer.data.type !== "logins") {
    const code = (answer && answer.code) || "host_failed";
    return reply({ state: code, message: MESSAGES[code] || messageOf(answer) });
  }
  const logins = (answer.data.logins || []).map((login) => ({
    item: login.item,
    title: String(login.title || ""),
    username: String(login.username || ""),
    // Only a flag: the popup never gets a code or a seed.
    ...(login.has_totp === true ? { hasTotp: true } : {}),
  }));
  return reply({
    state: logins.length ? "list" : "empty",
    host: answer.data.host || base.host,
    origin: answer.data.origin || originOf(url),
    logins,
  });
}

async function pageOrigin(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab && tab.url ? originOf(tab.url) : "";
  } catch (_) {
    return "";
  }
}

// Asks the app for one login, then fills it into the top frame of the tab.
// The reply has a code and a message, never a value.
async function fill(tabId, url, item) {
  const startOrigin = await pageOrigin(tabId);
  if (!startOrigin || startOrigin !== originOf(url)) {
    return { ok: false, code: "page_changed", message: MESSAGES.page_changed };
  }
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch (_) {
    return { ok: false, code: "page_changed", message: MESSAGES.page_changed };
  }

  const answer = await ask({ cmd: "fill", url: tab.url, item });
  if (!answer || !answer.ok) {
    return { ok: false, code: (answer && answer.code) || "host_failed", message: messageOf(answer) };
  }
  const data = answer.data || {};
  let origin = typeof data.origin === "string" ? data.origin : "";
  let username = typeof data.username === "string" ? data.username : "";
  let password = typeof data.password === "string" ? data.password : "";
  answer.data = null;
  try {
    if (data.type !== "fill" || data.item !== item || !origin) {
      return { ok: false, code: "host_failed", message: MESSAGES.host_failed };
    }
    // The tab may have gone to another site while the owner check waited.
    if ((await pageOrigin(tabId)) !== origin) {
      return { ok: false, code: "page_changed", message: MESSAGES.page_changed };
    }
    let results;
    try {
      results = await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        func: fillLogin,
        args: [origin, username, password],
      });
    } catch (_) {
      return { ok: false, code: "fill_failed", message: MESSAGES.fill_failed };
    }
    const result = (results && results[0] && results[0].result) || {};
    if (result.reason === "origin") {
      return { ok: false, code: "page_changed", message: MESSAGES.page_changed };
    }
    if (!result.ok) {
      return { ok: false, code: "no_fields", message: MESSAGES.no_fields };
    }
    return {
      ok: true,
      code: "ok",
      message: "Filled.",
      filled: { username: result.username === true, password: result.password === true },
    };
  } finally {
    data.username = "";
    data.password = "";
    username = "";
    password = "";
    origin = "";
  }
}

function failure(code, message) {
  return { ok: false, code, message: message || MESSAGES[code] || MESSAGES.host_failed };
}

// The tab, when it is still on the origin of url.
async function tabOn(tabId, url) {
  const origin = originOf(url);
  if (!origin) return null;
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab && tab.url && originOf(tab.url) === origin ? tab : null;
  } catch (_) {
    return null;
  }
}

// Runs readLogin in the top frame of the tab. null when the browser refused.
async function readPage(tabId, origin, includePassword) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: readLogin,
      args: [origin, includePassword],
    });
    return (results && results[0] && results[0].result) || null;
  } catch (_) {
    return null;
  }
}

const count = (value) => (Number.isInteger(value) && value > 0 ? value : 0);

// What the popup needs for "Save this login" and "New password": the typed
// username and whether a password was typed. Never the password.
async function peek(tabId, url) {
  const changed = "The page changed. Open Apassy again.";
  const tab = await tabOn(tabId, url);
  if (!tab) return failure("page_changed", changed);
  const page = await readPage(tabId, originOf(tab.url), false);
  if (!page) return failure("fill_failed", READ_FAILED);
  if (!page.ok) return failure("page_changed", changed);
  return {
    ok: true,
    code: "ok",
    message: "",
    username: typeof page.username === "string" ? page.username : "",
    hasPassword: page.hasPassword === true,
    passwordFields: count(page.passwordFields),
    newPasswordFields: count(page.newPasswordFields),
  };
}

// Reads the login that the owner typed on the page and asks Apassy to save
// it. The password goes from the page to the host only. The reply has a code
// and a message, never a value.
async function save(tabId, url, title, username) {
  const changed = "The page changed. Nothing was saved.";
  const tab = await tabOn(tabId, url);
  if (!tab) return failure("page_changed", changed);
  const page = await readPage(tabId, originOf(tab.url), true);
  if (!page) return failure("fill_failed", READ_FAILED);
  let password = typeof page.password === "string" ? page.password : "";
  page.password = "";
  let request = null;
  try {
    if (!page.ok) return failure("page_changed", changed);
    if (!password) return failure("no_password");
    // The tab may have gone to another site while the page was read. The
    // password must not be saved for another site.
    const fresh = await tabOn(tabId, tab.url);
    if (!fresh) return failure("page_changed", changed);
    request = { cmd: "save", url: fresh.url, title, username, password };
    const answer = await ask(request);
    if (!answer || !answer.ok) {
      return failure((answer && answer.code) || "host_failed", messageOf(answer));
    }
    const data = answer.data || {};
    if (data.type !== "saved" || !Number.isInteger(data.item)) return failure("host_failed");
    return { ok: true, code: "ok", message: "Saved.", item: data.item };
  } finally {
    password = "";
    if (request) request.password = "";
  }
}

// Asks Apassy to make a new password and add the login, then fills it into
// each new password field of the page, as fill() does. The reply has a code
// and a message, never a value.
async function create(tabId, url, fields) {
  const tab = await tabOn(tabId, url);
  if (!tab) return failure("page_changed");
  const startOrigin = originOf(tab.url);

  const answer = await ask({ cmd: "create", url: tab.url, ...fields });
  if (!answer || !answer.ok) {
    const code = (answer && answer.code) || "host_failed";
    if (code === "host_failed" || code === "timeout") return failure(code, MAYBE_CREATED);
    return failure(code, messageOf(answer));
  }
  const data = answer.data || {};
  let origin = typeof data.origin === "string" ? data.origin : "";
  let username = typeof data.username === "string" ? data.username : "";
  let password = typeof data.password === "string" ? data.password : "";
  answer.data = null;
  try {
    if (data.type !== "fill" || !Number.isInteger(data.item) || !origin || !password) {
      return failure("host_failed", CREATED_BUT.host_failed);
    }
    const item = data.item;
    const failed = (code) => ({ ...failure(code, CREATED_BUT[code]), item });
    // The tab may have gone to another site while the owner check waited.
    if (origin !== startOrigin || (await pageOrigin(tabId)) !== origin) return failed("page_changed");
    let results;
    try {
      results = await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        func: fillLogin,
        args: [origin, username, password, "new"],
      });
    } catch (_) {
      return failed("fill_failed");
    }
    const result = (results && results[0] && results[0].result) || {};
    if (result.reason === "origin") return failed("page_changed");
    if (!result.ok || !result.password) return failed("no_fields");
    return {
      ok: true,
      code: "ok",
      message: CREATED,
      item,
      filled: { username: result.username === true, passwords: count(result.passwords) },
    };
  } finally {
    data.username = "";
    data.password = "";
    username = "";
    password = "";
    origin = "";
  }
}

// Asks Apassy for the one-time code of a login, then fills it into the
// one-time-code field of the top frame, as fill() does with a password. The
// reply has a code and a message, never the one-time code.
async function fillCode(tabId, url, item) {
  const tab = await tabOn(tabId, url);
  if (!tab) return failure("page_changed", CODE_PAGE_CHANGED);
  const startOrigin = originOf(tab.url);

  const answer = await ask({ cmd: "fill_code", url: tab.url, item });
  if (!answer || !answer.ok) {
    return failure((answer && answer.code) || "host_failed", messageOf(answer));
  }
  const data = answer.data || {};
  let code = typeof data.code === "string" ? data.code : "";
  answer.data = null;
  try {
    if (data.type !== "code" || data.item !== item || data.origin !== startOrigin || !/^[0-9]{6,8}$/.test(code)) {
      return failure("host_failed");
    }
    // The tab may have gone to another site while the owner check waited.
    if ((await pageOrigin(tabId)) !== startOrigin) return failure("page_changed", CODE_PAGE_CHANGED);
    let results;
    try {
      results = await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        func: fillOneTimeCode,
        args: [startOrigin, code],
      });
    } catch (_) {
      return failure("fill_failed");
    }
    const result = (results && results[0] && results[0].result) || {};
    if (result.reason === "origin") return failure("page_changed", CODE_PAGE_CHANGED);
    if (!result.ok) return failure("no_code_field");
    return { ok: true, code: "ok", message: "Code filled.", filled: { fields: count(result.fields) } };
  } finally {
    data.code = "";
    code = "";
  }
}

// Runs in the top frame (chrome.scripting.executeScript sends only the source
// of this function, so it uses nothing from outside its body). It fills a
// one-time code into visible text fields marked autocomplete="one-time-code":
// the first one that takes the whole code, or else a row of one-character
// fields that starts at the marked field (a code split into digits). Nothing
// else: no password field, no guess, no pasteboard. It returns a count, never
// the code.
function fillOneTimeCode(origin, code) {
  const result = { ok: false, reason: "no_fields", fields: 0 };
  if (location.origin !== origin) {
    result.reason = "origin";
    return result;
  }
  if (typeof code !== "string" || !/^[0-9]{6,8}$/.test(code)) {
    result.reason = "code";
    return result;
  }
  const TYPES = ["text", "tel", "number"];
  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;

  function allInputs(root, out) {
    for (const el of root.querySelectorAll("*")) {
      if (el instanceof HTMLInputElement) out.push(el);
      if (el.shadowRoot) allInputs(el.shadowRoot, out);
    }
    return out;
  }

  function usable(el) {
    if (el.disabled || el.readOnly || !TYPES.includes(el.type)) return false;
    if (typeof el.checkVisibility === "function" &&
        !el.checkVisibility({ visibilityProperty: true })) return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  }

  const marked = (el) => (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).includes("one-time-code");

  function put(el, value) {
    el.focus();
    valueSetter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }

  const inputs = allInputs(document, []).filter(usable);
  const otp = inputs.filter(marked);
  let targets = [];
  const whole = otp.find((el) => el.maxLength < 0 || el.maxLength >= code.length);
  if (whole) {
    targets = [whole];
  } else if (otp.length) {
    // The split fields: one character each, in the same form (or the same
    // group of fields), one after the other from the first marked field.
    const first = otp[0];
    const group = first.form || first.closest("fieldset, [role=group]") || first.parentElement;
    const row = [];
    for (const el of inputs.slice(inputs.indexOf(first))) {
      if (el.maxLength !== 1) break;
      if (first.form ? el.form !== first.form : !(group && group.contains(el))) break;
      row.push(el);
      if (row.length === code.length) break;
    }
    if (row.length === code.length) targets = row;
  }
  if (targets.length === 1) {
    put(targets[0], code);
  } else {
    targets.forEach((el, i) => put(el, code[i]));
  }
  code = "";
  if (targets.length) {
    result.ok = true;
    result.reason = "";
    result.fields = targets.length;
  }
  return result;
}

const bytes = (text) => new TextEncoder().encode(text).length;

// A title or a username for a new login: 1 to max bytes after trim.
function field(value, max) {
  if (typeof value !== "string") return null;
  const text = value.trim();
  return text && bytes(text) <= max ? text : null;
}

async function popupIsOpen() {
  try {
    const contexts = await chrome.runtime.getContexts({
      documentUrls: [chrome.runtime.getURL("popup.html")],
    });
    return contexts.length > 0;
  } catch (_) {
    return false;
  }
}

let badgeTimer = null;

// The popup closes when the owner check takes the focus. A failure then shows
// on the toolbar button for a short time.
async function showFailure(message) {
  clearTimeout(badgeTimer);
  await chrome.action.setBadgeBackgroundColor({ color: "#d93025" });
  await chrome.action.setBadgeText({ text: "!" });
  await chrome.action.setTitle({ title: `Apassy: ${message}` });
  badgeTimer = setTimeout(clearFailure, BADGE_CLEAR_MS);
}

async function clearFailure() {
  clearTimeout(badgeTimer);
  badgeTimer = null;
  await chrome.action.setBadgeText({ text: "" });
  await chrome.action.setTitle({ title: "Apassy" });
}

// Runs an action that waits for the owner check. When it fails while the
// popup is closed, the toolbar button shows it.
async function withBadge(action) {
  await clearFailure();
  const result = await action();
  if (!result.ok && !(await popupIsOpen())) await showFailure(result.message);
  return result;
}

// The one entry point for the popup.
async function handleMessage(message) {
  const bad = () => ({ ok: false, code: "bad_request", message: MESSAGES.bad_request });
  const onPage = message && Number.isInteger(message.tabId) && typeof message.url === "string";
  switch (message && message.type) {
    case "state":
      return state();
    case "fill": {
      if (!onPage || !Number.isInteger(message.item)) return bad();
      return withBadge(() => fill(message.tabId, message.url, message.item));
    }
    case "peek": {
      if (!onPage) return bad();
      return peek(message.tabId, message.url);
    }
    case "save": {
      const title = field(message && message.title, 128);
      const username = field(message && message.username, 1024);
      if (!onPage || !title || !username) return bad();
      return withBadge(() => save(message.tabId, message.url, title, username));
    }
    case "create": {
      const title = field(message && message.title, 128);
      const username = field(message && message.username, 1024);
      const { length, symbols } = message || {};
      if (!onPage || !title || !username || typeof symbols !== "boolean" ||
          !Number.isInteger(length) || length < NEW_LENGTH.min || length > NEW_LENGTH.max) {
        return bad();
      }
      return withBadge(() => create(message.tabId, message.url, { title, username, length, symbols }));
    }
    case "fill_code": {
      if (!onPage || !Number.isInteger(message.item)) return bad();
      return withBadge(() => fillCode(message.tabId, message.url, message.item));
    }
    case "passkeys_state":
      return passkeyState();
    case "passkeys": {
      if (typeof message.on !== "boolean") return bad();
      return message.on ? turnOnPasskeys() : turnOffPasskeys();
    }
    case "show": {
      const answer = await ask({ cmd: "show" });
      return { ok: Boolean(answer && answer.ok), code: (answer && answer.code) || "host_failed", message: messageOf(answer) };
    }
    default:
      return { ok: false, code: "bad_request", message: MESSAGES.bad_request };
  }
}

// --- Passkeys ----------------------------------------------------------------
//
// Flow: passkey-page.js (MAIN) -> passkey-bridge.js (ISOLATED) -> a runtime
// port "apassy-passkey" -> this worker -> one native port per request -> the
// host -> the app, which asks the owner (Touch ID or passphrase) and signs.
//
// What the page sends is untrusted. The origin comes from port.sender.origin
// (the browser fills it in), bound to the tab, frame 0, and the document of
// that same port. The answer goes back only through that port, after a check
// that it is still open and the tab still shows the origin.
//
// Before the app shows its owner check, a request that Apassy cannot serve goes
// back to the browser ("fallback"): an option that Apassy does not support, no
// app, a locked vault, no passkey for the site. After that, a failure is a
// DOMException for the page, never a second try. Nothing here logs a request,
// an answer, a signature, or a key; a request lives in memory only.

const PASSKEY_PORT = "apassy-passkey";
// https sites, and localhost for a local test site: optional_host_permissions
// of the manifest, granted only from the popup.
const PASSKEY_ORIGINS = chrome.runtime.getManifest().optional_host_permissions || [];
const PASSKEY_SCRIPTS = [
  { id: "apassy-passkey-page", js: ["passkey-page.js"], world: "MAIN" },
  { id: "apassy-passkey-bridge", js: ["passkey-bridge.js"], world: "ISOLATED" },
];
// The page script waits 1.5 s for the bridge; the bridge sends the request at once.
const PASSKEY_FIRST_MESSAGE_MS = 10 * 1000;
const PASSKEY_TIMEOUT = { min: 30 * 1000, max: 180 * 1000, standard: 120 * 1000 };
const PASSKEY_MAX_MESSAGE = 64 * 1024;
// Answers of the app that come before any owner check.
// Protocol errors occur before owner approval. Older apps return these for the
// new commands, so their native browser passkeys must remain usable.
const PASSKEY_FALLBACK_CODES = ["not_running", "none_open", "vault_locked", "no_match", "unsupported", "bad_request", "bad_version"];
const PASSKEY_NOT_DELIVERED = "The passkey is in Apassy, but the page did not get it. Look for it in Apassy before you try again.";
// How long a "turn on" waits for the permission prompt of the popup.
const PASSKEY_INTENT_MS = 2 * 60 * 1000;

const FALLBACK = Object.freeze({ kind: "fallback" });
const NOT_ALLOWED = Object.freeze({ kind: "error", name: "NotAllowedError" });
const INVALID_STATE = Object.freeze({ kind: "error", name: "InvalidStateError" });

// --- turning passkeys on and off ---

let passkeyIntent = 0;

async function grantedPasskeyOrigins() {
  const granted = [];
  for (const origin of PASSKEY_ORIGINS) {
    try {
      if (await chrome.permissions.contains({ origins: [origin] })) granted.push(origin);
    } catch (_) { /* not granted */ }
  }
  return granted;
}

async function registeredPasskeyScripts() {
  try {
    return await chrome.scripting.getRegisteredContentScripts({ ids: PASSKEY_SCRIPTS.map((script) => script.id) });
  } catch (_) {
    return [];
  }
}

async function unregisterPasskeyScripts() {
  const ids = (await registeredPasskeyScripts()).map((script) => script.id);
  if (ids.length) await chrome.scripting.unregisterContentScripts({ ids });
}

// Both scripts run at document_start in the top frame only, for the granted
// origins only.
async function registerPasskeyScripts(matches) {
  await unregisterPasskeyScripts();
  await chrome.scripting.registerContentScripts(PASSKEY_SCRIPTS.map((script) => ({
    ...script,
    matches,
    runAt: "document_start",
    allFrames: false,
    matchOriginAsFallback: false,
    persistAcrossSessions: true,
  })));
}

async function passkeyState() {
  const scripts = await registeredPasskeyScripts();
  const granted = await grantedPasskeyOrigins();
  return { ok: true, code: "ok", message: "", on: scripts.length === PASSKEY_SCRIPTS.length && granted.length > 0 };
}

// The popup asks the browser for the permission (a click of the owner), and
// sends this before and after. Before, it only notes the wish, so that the
// grant turns passkeys on even when the prompt closed the popup.
async function turnOnPasskeys() {
  const granted = await grantedPasskeyOrigins();
  if (!granted.length) {
    passkeyIntent = Date.now();
    return { ok: true, code: "ok", message: "", on: false };
  }
  passkeyIntent = 0;
  try {
    await registerPasskeyScripts(granted);
  } catch (_) {
    return { ok: false, code: "fill_failed", message: "Apassy could not turn on passkeys in this browser.", on: false };
  }
  return passkeyState();
}

async function turnOffPasskeys() {
  passkeyIntent = 0;
  try {
    await unregisterPasskeyScripts();
  } catch (_) { /* nothing registered */ }
  for (const session of passkeyByTab.values()) endPasskey(session, NOT_ALLOWED);
  return { ok: true, code: "ok", message: "", on: false };
}

chrome.permissions.onAdded.addListener(() => {
  if (passkeyIntent && Date.now() - passkeyIntent < PASSKEY_INTENT_MS) turnOnPasskeys().catch(() => {});
});

// The owner removed the site access in the browser: follow it.
chrome.permissions.onRemoved.addListener(async () => {
  if (!(await registeredPasskeyScripts()).length) return;
  const granted = await grantedPasskeyOrigins();
  if (granted.length) await registerPasskeyScripts(granted).catch(() => {});
  else await turnOffPasskeys();
});

// --- bytes ---

function standardBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

const base64url = (bytes) => standardBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function decodeBinary(binary) {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Canonical base64url (no padding) of min..max bytes, else null.
function fromBase64url(text, min, max) {
  if (typeof text !== "string" || text.length > 2 * PASSKEY_MAX_MESSAGE ||
      !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  let bytes;
  try {
    bytes = decodeBinary(atob(text.replace(/-/g, "+").replace(/_/g, "/")));
  } catch (_) {
    return null;
  }
  if (bytes.length < min || bytes.length > max || base64url(bytes) !== text) return null;
  return bytes;
}

// Canonical standard base64 with padding (the wire) of min..max bytes, else null.
function fromStandardBase64(text, min, max) {
  if (typeof text !== "string" || text.length > 4 * 1024 * 1024 || text.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  let bytes;
  try {
    bytes = decodeBinary(atob(text));
  } catch (_) {
    return null;
  }
  if (bytes.length < min || bytes.length > max || standardBase64(bytes) !== text) return null;
  return bytes;
}

const sameBytes = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

function containsBytes(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

// --- the sender ---

// An https origin, or an http origin of the host localhost (a local test
// site), with any port. Never
// an opaque origin, never from the page.
function passkeyOrigin(value) {
  if (typeof value !== "string" || value === "null") return null;
  let url;
  try {
    url = new URL(value);
  } catch (_) {
    return null;
  }
  if (url.origin !== value) return null;
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && url.hostname === "localhost") return url;
  return null;
}

// What the browser says about the bridge that opened the port. null when it
// is not the active top-level document of a tab of a secure origin.
function passkeyPeer(sender) {
  if (!sender || sender.id !== chrome.runtime.id) return null;
  const tab = sender.tab;
  if (!tab || !Number.isInteger(tab.id) || tab.id < 0) return null;
  if (sender.frameId !== 0 || typeof sender.documentId !== "string" || !sender.documentId) return null;
  if (sender.documentLifecycle !== "active") return null;
  const url = passkeyOrigin(sender.origin);
  if (!url) return null;
  const origin = url.origin;
  if (typeof sender.url !== "string" || originOf(sender.url) !== origin) return null;
  if (typeof tab.url === "string" && tab.url && originOf(tab.url) !== origin) return null;
  return { tabId: tab.id, documentId: sender.documentId, origin, hostname: url.hostname };
}

// The quick RP ID check: lower-case ASCII host name, not an IP address, not
// one label (but localhost for a local test site), and the host of the origin
// is the RP ID or under it. The app checks it again with the public suffix
// list. Fails here go to the browser, which does its own checks.
function passkeyRpId(hostname, claimed) {
  const rpId = claimed === undefined ? hostname : claimed;
  if (typeof rpId !== "string" || rpId.length < 1 || rpId.length > 253) return null;
  if (rpId === "localhost") return hostname === "localhost" ? rpId : null;
  const labels = rpId.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return null;
  if (hostname !== rpId && !hostname.endsWith(`.${rpId}`)) return null;
  return rpId;
}

// --- the request ---

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const onlyKeys = (object, allowed) => Object.keys(object).every((key) => allowed.includes(key));
const textOf = (value, max) => (typeof value === "string" && bytes(value) <= max ? value : null);

// Text from the page for the owner check of the app: no control, format
// (bidirectional, zero-width), or lone surrogate character, one line, bounded.
// The app shows it as untrusted text and filters it again.
function cleanText(value, maxChars) {
  const text = value.normalize("NFC")
    .replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}ᅟᅠㅤﾠ]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  return [...text].slice(0, maxChars).join("");
}

function credentialIds(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > 64) return null;
  const ids = [];
  for (const item of list) {
    if (!isRecord(item) || !onlyKeys(item, ["type", "id"]) || typeof item.type !== "string") return null;
    const id = fromBase64url(item.id, 1, 1023);
    if (!id) return null;
    // Another credential type is skipped, as WebAuthn says.
    if (item.type === "public-key") ids.push(id);
  }
  return ids;
}

function timeoutOf(value) {
  if (value === undefined) return PASSKEY_TIMEOUT.standard;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return null;
  return Math.min(PASSKEY_TIMEOUT.max, Math.max(PASSKEY_TIMEOUT.min, Math.round(value)));
}

// Hints that ask for a security key or another phone go to the browser.
function hintsOk(hints) {
  if (hints === undefined) return true;
  if (!Array.isArray(hints) || hints.length > 8 || !hints.every((hint) => textOf(hint, 64) !== null)) return false;
  return hints.length === 0 || hints[0] === "client-device";
}

function extensionsOk(extensions, allowed) {
  if (extensions === undefined) return true;
  return isRecord(extensions) && onlyKeys(extensions, allowed) &&
    Object.values(extensions).every((value) => typeof value === "boolean");
}

const USER_VERIFICATION = ["required", "preferred", "discouraged"];

// The request of the bridge: { op, options, mediation? }, options as JSON with
// base64url bytes (passkey-page.js). The parsed request, or null when Apassy
// does not serve it (the browser then does).
function parsePasskeyRequest(message, peer) {
  if (!isRecord(message) || !onlyKeys(message, ["op", "options", "mediation"])) return null;
  let size;
  try {
    size = JSON.stringify(message).length;
  } catch (_) {
    return null;
  }
  if (size > PASSKEY_MAX_MESSAGE) return null;
  const { op, options: o, mediation } = message;
  if (mediation !== undefined && mediation !== "optional" && mediation !== "required") return null;
  if (!isRecord(o)) return null;
  const challenge = fromBase64url(o.challenge, 16, 1024);
  const timeout = timeoutOf(o.timeout);
  if (!challenge || timeout === null || !hintsOk(o.hints)) return null;

  if (op === "get") {
    if (!onlyKeys(o, ["challenge", "timeout", "rpId", "allowCredentials", "userVerification", "hints", "extensions"])) return null;
    if (o.userVerification !== undefined && !USER_VERIFICATION.includes(o.userVerification)) return null;
    if (!extensionsOk(o.extensions, [])) return null;
    const rpId = passkeyRpId(peer.hostname, o.rpId);
    const allowed = credentialIds(o.allowCredentials);
    if (!rpId || !allowed) return null;
    return { op, rpId, challenge, timeout, allowed };
  }

  if (op === "create") {
    if (!onlyKeys(o, ["rp", "user", "challenge", "pubKeyCredParams", "timeout", "excludeCredentials",
      "authenticatorSelection", "attestation", "hints", "extensions"])) return null;
    const { rp, user } = o;
    if (!isRecord(rp) || !onlyKeys(rp, ["id", "name"]) || textOf(rp.name, 256) === null) return null;
    if (!isRecord(user) || !onlyKeys(user, ["id", "name", "displayName"]) ||
        textOf(user.name, 256) === null || textOf(user.displayName, 256) === null) return null;
    const userHandle = fromBase64url(user.id, 1, 64);
    const rpId = passkeyRpId(peer.hostname, rp.id);
    const excluded = credentialIds(o.excludeCredentials);
    if (!userHandle || !rpId || !excluded) return null;

    if (!Array.isArray(o.pubKeyCredParams) || o.pubKeyCredParams.length > 32) return null;
    const algorithms = [];
    for (const param of o.pubKeyCredParams) {
      if (!isRecord(param) || !onlyKeys(param, ["type", "alg"]) || typeof param.type !== "string" ||
          !Number.isInteger(param.alg) || Math.abs(param.alg) > 0x7fffffff) return null;
      if (param.type === "public-key" && !algorithms.includes(param.alg)) algorithms.push(param.alg);
    }
    // An empty list means ES256 and RS256 (WebAuthn). Apassy makes ES256 only.
    if (o.pubKeyCredParams.length === 0) algorithms.push(-7, -257);
    if (!algorithms.includes(-7)) return null;

    const selection = o.authenticatorSelection;
    if (selection !== undefined) {
      if (!isRecord(selection) || !onlyKeys(selection, ["authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"])) return null;
      if (selection.authenticatorAttachment !== undefined && selection.authenticatorAttachment !== "platform") return null;
      if (selection.userVerification !== undefined && !USER_VERIFICATION.includes(selection.userVerification)) return null;
      if (selection.residentKey !== undefined && typeof selection.residentKey !== "string") return null;
      if (selection.requireResidentKey !== undefined && typeof selection.requireResidentKey !== "boolean") return null;
    }
    // Apassy makes "none" attestation, which WebAuthn allows for every value but
    // enterprise.
    if (o.attestation !== undefined && (typeof o.attestation !== "string" || o.attestation === "enterprise")) return null;
    if (!extensionsOk(o.extensions, ["credProps"])) return null;

    const userName = cleanText(user.name, 128);
    if (!userName) return null;
    return {
      op,
      rpId,
      challenge,
      timeout,
      excluded,
      algorithms,
      userHandle,
      userName,
      userDisplayName: cleanText(user.displayName, 128),
      title: cleanText(rp.name, 64) || rpId,
      // Every Apassy passkey is discoverable.
      credProps: Boolean(o.extensions && o.extensions.credProps),
    };
  }
  return null;
}

// The exact bytes that the app hashes and signs. Fixed key order; no
// topOrigin, because only a top-level document gets here.
function clientDataFor(op, challenge, origin) {
  return JSON.stringify({
    type: op === "get" ? "webauthn.get" : "webauthn.create",
    challenge: base64url(challenge),
    origin,
    crossOrigin: false,
  });
}

function wireRequest(request, origin, clientData, rid) {
  const common = {
    v: WIRE_VERSION,
    origin,
    rp_id: request.rpId,
    client_data_json: standardBase64(new TextEncoder().encode(clientData)),
    rid,
  };
  if (request.op === "get") {
    return { ...common, cmd: "passkey_get", allowed: request.allowed.map(standardBase64) };
  }
  return {
    ...common,
    cmd: "passkey_create",
    user_handle: standardBase64(request.userHandle),
    user_name: request.userName,
    user_display_name: request.userDisplayName,
    algorithms: request.algorithms,
    excluded: request.excluded.map(standardBase64),
    title: request.title,
  };
}

// --- the answer ---

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

// Checks the answer of the app against what this worker asked. The reply for
// the page, or NOT_ALLOWED for anything unexpected (fail closed).
async function checkPasskeyAnswer(expect, answer) {
  if (!isRecord(answer) || typeof answer.ok !== "boolean") return NOT_ALLOWED;
  if (!answer.ok) {
    if (PASSKEY_FALLBACK_CODES.includes(answer.code)) return FALLBACK;
    if (expect.op === "create" && answer.code === "excluded") return INVALID_STATE;
    return NOT_ALLOWED;
  }
  const data = answer.data;
  if (!isRecord(data) || data.rid !== expect.rid) return NOT_ALLOWED;
  if (data.client_data_json !== expect.clientDataBase64) return NOT_ALLOWED;
  const credentialId = fromStandardBase64(data.credential_id, 1, 1023);
  const authData = fromStandardBase64(data.authenticator_data, 37, 16384);
  if (!credentialId || !authData) return NOT_ALLOWED;
  // The RP ID hash, user presence, and user verification (the owner check).
  if (!sameBytes(authData.subarray(0, 32), await sha256(expect.rpId))) return NOT_ALLOWED;
  if ((authData[32] & (FLAG_UP | FLAG_UV)) !== (FLAG_UP | FLAG_UV)) return NOT_ALLOWED;

  if (expect.op === "get") {
    if (data.type !== "passkey") return NOT_ALLOWED;
    if (expect.allowed.length && !expect.allowed.some((id) => sameBytes(id, credentialId))) return NOT_ALLOWED;
    const signature = fromStandardBase64(data.signature, 8, 1024);
    const userHandle = fromStandardBase64(data.user_handle, 0, 64);
    if (!signature || !userHandle) return NOT_ALLOWED;
    return {
      kind: "result",
      op: "get",
      credential: {
        id: base64url(credentialId),
        clientDataJSON: base64url(expect.clientData),
        authenticatorData: base64url(authData),
        signature: base64url(signature),
        userHandle: userHandle.length ? base64url(userHandle) : null,
        clientExtensionResults: {},
      },
    };
  }

  if (data.type !== "passkey_created") return NOT_ALLOWED;
  if (!Number.isSafeInteger(data.item) || data.item < 0) return NOT_ALLOWED;
  if (data.algorithm !== -7 || !expect.algorithms.includes(-7)) return NOT_ALLOWED;
  if (expect.excluded.some((id) => sameBytes(id, credentialId))) return NOT_ALLOWED;
  const attestation = fromStandardBase64(data.attestation_object, 1, 16384);
  const publicKey = fromStandardBase64(data.public_key_spki, 1, 1024);
  if (!attestation || !publicKey) return NOT_ALLOWED;
  // Attested credential data: AAGUID (16), length (2), then the credential ID.
  if (!(authData[32] & FLAG_AT) || authData.length < 55) return NOT_ALLOWED;
  const idLength = (authData[53] << 8) | authData[54];
  if (idLength !== credentialId.length || !sameBytes(authData.subarray(55, 55 + idLength), credentialId)) return NOT_ALLOWED;
  if (!containsBytes(attestation, authData)) return NOT_ALLOWED;
  return {
    kind: "result",
    op: "create",
    item: data.item,
    credential: {
      id: base64url(credentialId),
      clientDataJSON: base64url(expect.clientData),
      attestationObject: base64url(attestation),
      authenticatorData: base64url(authData),
      publicKey: base64url(publicKey),
      publicKeyAlgorithm: -7,
      transports: ["internal"],
      clientExtensionResults: expect.credProps ? { credProps: { rk: true } } : {},
    },
  };
}

// --- one request ---

// The open request of each tab. A new one ends the old one.
const passkeyByTab = new Map();

// Ends a request once: stops the timers, closes the native port (the host sees
// the end of its input and the app closes its owner check), and answers the
// page when its port is still open.
function endPasskey(session, reply) {
  if (session.done) return;
  session.done = true;
  for (const timer of session.timers) clearTimeout(timer);
  session.timers = [];
  closeNative(session);
  if (session.peer && passkeyByTab.get(session.peer.tabId) === session) passkeyByTab.delete(session.peer.tabId);
  if (session.open) {
    session.open = false;
    if (reply) {
      try { session.port.postMessage(reply); } catch (_) { /* the page is gone */ }
    }
    try { session.port.disconnect(); } catch (_) { /* already closed */ }
  }
  session.expect = null;
}

function closeNative(session) {
  const native = session.native;
  session.native = null;
  if (native) {
    try { native.disconnect(); } catch (_) { /* already closed */ }
  }
}

// The tab still shows the origin, and the document that opened the port is
// still there and on that origin (the browser refuses a documentId that is
// gone).
async function tabStillOn(peer) {
  try {
    const tab = await chrome.tabs.get(peer.tabId);
    if (!tab || !tab.url || originOf(tab.url) !== peer.origin) return false;
    const results = await chrome.scripting.executeScript({
      target: { tabId: peer.tabId, documentIds: [peer.documentId] },
      func: () => location.origin,
    });
    return Boolean(results && results[0] && results[0].result === peer.origin);
  } catch (_) {
    return false;
  }
}

function acceptPasskeyPort(port) {
  const session = {
    port, peer: passkeyPeer(port.sender), open: true, done: false, started: false,
    native: null, timers: [], expect: null,
  };
  port.onDisconnect.addListener(() => {
    // The page cancelled, navigated, or closed: end the request in the app too.
    session.open = false;
    endPasskey(session, null);
  });
  if (!session.peer) {
    endPasskey(session, FALLBACK);
    return;
  }
  session.timers.push(setTimeout(() => endPasskey(session, FALLBACK), PASSKEY_FIRST_MESSAGE_MS));
  port.onMessage.addListener((message) => {
    // One request per port.
    if (session.started) {
      endPasskey(session, NOT_ALLOWED);
      return;
    }
    session.started = true;
    startPasskey(session, message).catch(() => endPasskey(session, NOT_ALLOWED));
  });
}

async function startPasskey(session, message) {
  for (const timer of session.timers) clearTimeout(timer);
  session.timers = [];
  const { peer } = session;
  const request = parsePasskeyRequest(message, peer);
  if (!request) {
    endPasskey(session, FALLBACK);
    return;
  }
  const old = passkeyByTab.get(peer.tabId);
  if (old && old !== session) endPasskey(old, NOT_ALLOWED);
  passkeyByTab.set(peer.tabId, session);

  if (!(await tabStillOn(peer)) || session.done) {
    endPasskey(session, null);
    return;
  }

  const clientData = clientDataFor(request.op, request.challenge, peer.origin);
  const rid = crypto.randomUUID();
  const wire = wireRequest(request, peer.origin, clientData, rid);
  session.expect = {
    op: request.op,
    rid,
    rpId: request.rpId,
    clientData: new TextEncoder().encode(clientData),
    clientDataBase64: wire.client_data_json,
    allowed: request.allowed || [],
    excluded: request.excluded || [],
    algorithms: request.algorithms || [],
    credProps: request.credProps === true,
  };

  let native;
  try {
    native = chrome.runtime.connectNative(HOST);
  } catch (_) {
    endPasskey(session, FALLBACK);
    return;
  }
  session.native = native;
  native.onMessage.addListener((answer) => {
    if (session.done || session.native !== native) return;
    // One answer per request: the host is done.
    closeNative(session);
    for (const timer of session.timers) clearTimeout(timer);
    session.timers = [];
    deliverPasskey(session, answer).catch(() => endPasskey(session, NOT_ALLOWED));
  });
  native.onDisconnect.addListener(() => {
    if (session.done || session.native !== native) return;
    const error = chrome.runtime.lastError;
    const text = error && error.message ? error.message : "";
    session.native = null;
    // No host: nothing reached the app. Any other end may come after the
    // owner check.
    endPasskey(session, /not found|forbidden/i.test(text) ? FALLBACK : NOT_ALLOWED);
  });
  // The deadline of the page (30 to 180 s). Ending closes the native port.
  session.timers.push(setTimeout(() => endPasskey(session, NOT_ALLOWED), request.timeout));
  native.postMessage(wire);
}

async function deliverPasskey(session, answer) {
  const expect = session.expect;
  if (!expect) return;
  const reply = await checkPasskeyAnswer(expect, answer);
  if (reply.kind !== "result") {
    endPasskey(session, reply);
    return;
  }
  const delivered = !session.done && session.open && (await tabStillOn(session.peer)) &&
    !session.done && session.open;
  if (delivered) {
    const { item: _item, ...forPage } = reply;
    endPasskey(session, forPage);
    return;
  }
  endPasskey(session, null);
  // The app saved a new passkey that the page never got. The owner must know.
  if (expect.op === "create") await showFailure(PASSKEY_NOT_DELIVERED);
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== PASSKEY_PORT) {
    try { port.disconnect(); } catch (_) { /* already closed */ }
    return;
  }
  acceptPasskeyPort(port);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.url || !sender.url.startsWith(chrome.runtime.getURL(""))) {
    return false;
  }
  handleMessage(message).then(sendResponse, () => sendResponse(localError("host_failed")));
  return true;
});

// The tests drive the same handler that the popup uses.
self.apassyHandle = handleMessage;
// The unit checks reach the passkey parts the same way. Nothing secret is in them.
self.apassyPasskeyTest = { passkeyPeer, passkeyRpId, parsePasskeyRequest, clientDataFor, checkPasskeyAnswer, cleanText };
