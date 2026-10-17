// Login target and optional site-suggestion helpers. Imported only by the worker.
const LOGIN_SCRIPT = "apassy-login-suggestions";
const LOGIN_RESULT_TTL = 5 * 60 * 1000;
const loginIntents = new Map();
const loginOffers = new Map();
const loginBusy = new Set();
let loginFeatureGeneration = 0;

function loginMatch(url) {
  try {
    const u = new URL(url);
    return (u.protocol === "https:" || (u.protocol === "http:" && u.hostname === "localhost")) ? `${u.protocol}//${u.hostname}/*` : null;
  } catch (_) { return null; }
}

async function loginAccess(url) {
  const match = loginMatch(url);
  const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [LOGIN_SCRIPT] });
  return Boolean(match && scripts.some((s) => s.matches.includes(match)) &&
    await chrome.permissions.contains({ origins: [match] }));
}

let loginAccessWrites = Promise.resolve();
function loginAccessChange(url, on) {
  if (!on) { loginFeatureGeneration++; loginOffers.clear(); }
  const next = loginAccessWrites.then(() => writeLoginAccess(url, on));
  loginAccessWrites = next.catch(() => {});
  return next;
}

async function writeLoginAccess(url, on) {
  const match = loginMatch(url);
  if (!match) return failure("unsupported_page");
  const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [LOGIN_SCRIPT] });
  const matches = new Set((scripts[0] && scripts[0].matches) || []);
  if (on) {
    if (!(await chrome.permissions.contains({ origins: [match] }))) {
      loginIntents.set(match, Date.now());
      return { ok: true, on: false };
    }
    matches.add(match);
  } else {
    loginIntents.delete(match);
    matches.delete(match);
    loginOffers.clear();
    for (const tab of await chrome.tabs.query({})) {
      if (loginMatch(tab.url) !== match) continue;
      try {
        await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true },
          func: () => { self.apassyLoginSuggestionsEnabled = false; self.apassyStopLoginSuggestions?.(); } });
      } catch (_) { /* no remaining access */ }
    }
  }
  if (scripts.length) await chrome.scripting.unregisterContentScripts({ ids: [LOGIN_SCRIPT] });
  if (matches.size) await chrome.scripting.registerContentScripts([{
    id: LOGIN_SCRIPT, matches: [...matches], js: ["login-target.js", "login-suggestions.js"],
    runAt: "document_idle", allFrames: true, matchOriginAsFallback: false, persistAcrossSessions: true,
  }]);
  if (on) {
    loginIntents.delete(match);
    const tab = await targetTab();
    if (tab && originOf(tab.url) === originOf(url)) {
      try { await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, files: ["login-target.js", "login-suggestions.js"] }); } catch (_) { /* next navigation */ }
    }
  }
  return { ok: true, on };
}

async function captureLoginTarget(tabId, url) {
  if (!(await tabOn(tabId, url))) return null;
  try {
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["login-target.js"] });
    const [result] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: () => self.apassyLoginTarget.capture() });
    if (!result || !result.documentId || !result.result) return null;
    if (!result.result.ok) return { failure: result.result.reason === "no_fields" ? "no_fields" : "page_changed" };
    return { tabId, url, origin: originOf(url), frameId: 0, documentId: result.documentId, token: result.result.token };
  } catch (_) { return null; }
}

function validLoginTarget(target, tabId, url) {
  return target && target.tabId === tabId && target.url === url && target.origin === originOf(url) &&
    Number.isInteger(target.frameId) && typeof target.documentId === "string" && target.documentId.length > 0 &&
    typeof target.token === "string" && /^[0-9a-f-]{36}$/.test(target.token);
}

async function targetCall(target, method, args = []) {
  if (!target || !(await tabOn(target.tabId, target.url))) return null;
  if (method === "fill") {
    const active = await targetTab();
    if (!active || active.id !== target.tabId) return null;
    if (target.inline && (target.generation !== loginFeatureGeneration || !(await loginAccess(target.url)))) return null;
    if (target.inline && target.generation !== loginFeatureGeneration) return null;
  }
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: target.tabId, documentIds: [target.documentId] },
      func: (origin, token, op, values, inline) => location.origin === origin && self.apassyLoginTarget && (!inline || self.apassyLoginSuggestionsEnabled === true)
        ? self.apassyLoginTarget[op](token, ...values) : { ok: false, reason: "target" },
      args: [target.origin, target.token, method, args, target.inline === true],
    });
    return result && result.documentId === target.documentId ? result.result : null;
  } catch (_) { return null; }
}

async function resolveLoginTarget(tabId, url, target) {
  const resolved = target === undefined ? await captureLoginTarget(tabId, url) : target;
  if (resolved?.failure) return resolved;
  return validLoginTarget(resolved, tabId, url) && (await targetCall(resolved, "read"))?.ok ? resolved : null;
}

async function rememberLoginResult(target, result) {
  // Session storage is extension-only; never include credentials, account labels, or native data.
  if (!target || target.failure || !chrome.storage?.session) return;
  const key = `login-result-${target.tabId}`;
  const code = Object.hasOwn(MESSAGES, result.code) || ["ok", "cancelled", "busy", "exists", "owner_check_failed", "refused"].includes(result.code)
    ? result.code : "host_failed";
  await chrome.storage.session.set({ [key]: { at: Date.now(), origin: target.origin, documentId: target.documentId,
    token: target.token, url: target.origin, frameId: target.frameId, tabId: target.tabId,
    ok: result.ok === true, code, message: result.ok ? result.message : MESSAGES[result.code] || "Apassy did not confirm the action. Check the login in Apassy before trying again." } });
}

async function recentLoginResult(tab) {
  if (!tab || !chrome.storage?.session) return null;
  const key = `login-result-${tab.id}`;
  const stored = (await chrome.storage.session.get(key))[key];
  if (!stored) return null;
  if (Date.now() - stored.at > LOGIN_RESULT_TTL || stored.origin !== originOf(tab.url) ||
      !(await targetCall(stored, "read"))?.ok) {
    await chrome.storage.session.remove(key);
    return null;
  }
  return { ok: stored.ok, code: stored.code, message: stored.message };
}

async function boundLoginAction(target, action) {
  if (target?.failure) return failure(target.failure, target.failure === "no_fields" ? MESSAGES.no_fields : "Focus the intended login field, then open Apassy. Frames can be opened in their own tab.");
  if (!target) return failure("page_changed", "Focus the login field, then choose the account again. The page or form may have changed.");
  const key = `${target.tabId}:${target.documentId}`;
  if (loginBusy.has(key)) return failure("busy", "Finish the current Apassy check before trying again.");
  loginBusy.add(key);
  try {
    const result = await action();
    await rememberLoginResult(target, result);
    return result;
  } finally { loginBusy.delete(key); }
}

async function updateLogin(tabId, url, item, username, target) {
  return boundLoginAction(target, async () => {
    const page = await targetCall(target, "read", [true, "update"]);
    if (!page?.ok) return failure(["ambiguous_password", "password_confirmation"].includes(page?.reason) ? page.reason : "page_changed");
    let password = typeof page.password === "string" ? page.password : "";
    page.password = "";
    let request;
    try {
      if (!password) return failure("no_password");
      // Exact selected metadata identity, never the editable page username.
      const metadata = await ask({ cmd: "suggestions", url });
      if (!metadata?.ok) return failure(metadata?.code || "host_failed", messageOf(metadata));
      if (metadata.data?.type !== "logins" || metadata.data.origin !== target.origin ||
          !metadata.data.logins?.some((login) => login.item === item && login.username === username)) return failure("no_match");
      if (!(await targetCall(target, "read"))?.ok) return failure("page_changed");
      request = { cmd: "update", url, item, username, password };
      const answer = await ask(request);
      if (!answer?.ok) return failure(answer?.code || "host_failed", ["timeout", "host_failed"].includes(answer?.code)
        ? "Apassy did not confirm the update. Check this login in Apassy before trying again." : messageOf(answer));
      if (answer.data?.type !== "updated" || answer.data.item !== item || answer.data.origin !== target.origin || answer.data.username !== username) return failure("host_failed", "Check the login in Apassy before trying again.");
      return { ok: true, code: "ok", message: "Login updated in Apassy. Nothing was submitted on the website.", item };
    } finally { password = ""; if (request) request.password = ""; }
  });
}

async function handleLoginField(message, sender) {
  // Separate from the extension-page route. All authority comes from browser sender metadata.
  if (sender?.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id) || sender.tab.id < 0 ||
      !Number.isInteger(sender.frameId) || sender.frameId < 0 || sender.documentLifecycle !== "active" ||
      typeof sender.documentId !== "string" || !sender.documentId || !loginMatch(sender.url) ||
      originOf(sender.url) !== sender.origin || originOf(sender.tab.url) !== sender.origin) return failure("unsupported_frame", "Open this sign-in page in its own tab, then use Apassy.");
  if (!(await loginAccess(sender.url))) return failure("site_access", "Enable login suggestions for this site from the Apassy toolbar.");
  const active = await targetTab();
  if (!active || active.id !== sender.tab.id || originOf(active.url) !== sender.origin) return failure("page_changed");
  if (!message || !["login_suggestions", "login_fill", "login_show"].includes(message.type) ||
      Object.keys(message).some((key) => !["type", "token", "username", "item"].includes(key))) return failure("bad_request");
  const target = { tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId,
    origin: sender.origin, url: sender.url, token: message.token, inline: true, generation: loginFeatureGeneration };
  if (!validLoginTarget(target, sender.tab.id, sender.url) || !(await targetCall(target, "read"))?.ok) return failure("page_changed");
  const key = `${target.tabId}:${target.documentId}:${target.token}`;
  if (message.type === "login_show") {
    const answer = await ask({ cmd: "show" });
    return { ok: answer?.ok === true, code: answer?.code || "host_failed", message: messageOf(answer) };
  }
  if (message.type === "login_suggestions") {
    if (typeof message.username !== "string" || bytes(message.username) > 1024) return failure("bad_request");
    const answer = await ask({ cmd: "suggestions", url: sender.url, username: message.username });
    if (!answer?.ok) { loginOffers.clear(); return failure(answer?.code || "host_failed", messageOf(answer)); }
    if (answer.data?.type !== "logins" || answer.data.origin !== sender.origin || !(await targetCall(target, "read"))?.ok) return failure("page_changed");
    const logins = (answer.data.logins || []).filter((l) => Number.isInteger(l.item) && typeof l.title === "string" && typeof l.username === "string")
      .map(({ item, title, username }) => ({ item, title, username }));
    for (const [offerKey, offer] of loginOffers) if (Date.now() - offer.at > LOGIN_RESULT_TTL) loginOffers.delete(offerKey);
    while (loginOffers.size >= 128) loginOffers.delete(loginOffers.keys().next().value);
    loginOffers.set(key, { at: Date.now(), items: logins.map((l) => l.item) });
    return { ok: true, logins };
  }
  const offer = loginOffers.get(key);
  if (!Number.isInteger(message.item) || !offer || Date.now() - offer.at > LOGIN_RESULT_TTL || !offer.items.includes(message.item)) return failure("bad_request");
  loginOffers.delete(key);
  return withBadge(() => fill(target.tabId, target.url, message.item, target));
}

chrome.permissions.onAdded.addListener(async () => {
  for (const [match, at] of loginIntents) if (Date.now() - at < 120000) await loginAccessChange(match.slice(0, -2), true).catch(() => {});
});
chrome.permissions.onRemoved.addListener(async () => {
  loginFeatureGeneration++;
  loginOffers.clear();
  const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [LOGIN_SCRIPT] });
  for (const match of scripts[0]?.matches || []) if (!(await chrome.permissions.contains({ origins: [match] }))) await loginAccessChange(match.slice(0, -2), false).catch(() => {});
});
