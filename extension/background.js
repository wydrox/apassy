// The service worker of the Apassy extension. It is the only part that talks
// to the native messaging host (wire: docs/contracts/browser-v1.md).
//
// A fill answer holds a password. It goes from the host straight into the
// fill function in the page. It is never logged, stored, or sent to the popup.
// "Save this login" reads the password that the owner typed on the page and
// sends it straight to the host, the same way. The extension never makes a
// password: for "New password", Apassy makes it and answers with a fill.

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
};

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
    case "show": {
      const answer = await ask({ cmd: "show" });
      return { ok: Boolean(answer && answer.ok), code: (answer && answer.code) || "host_failed", message: messageOf(answer) };
    }
    default:
      return { ok: false, code: "bad_request", message: MESSAGES.bad_request };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.url || !sender.url.startsWith(chrome.runtime.getURL(""))) {
    return false;
  }
  handleMessage(message).then(sendResponse, () => sendResponse(localError("host_failed")));
  return true;
});

// The tests drive the same handler that the popup uses.
self.apassyHandle = handleMessage;
