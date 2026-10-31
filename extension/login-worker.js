// Login target and optional site-suggestion helpers. Imported only by the worker.
const LOGIN_SCRIPT = "apassy-login-suggestions";
const LOGIN_RESULT_TTL = 5 * 60 * 1000;
const LOGIN_ORIGINS = ["https://*/*", "http://localhost/*"];
const loginOffers = new Map();
const loginBusy = new Set();
let loginFeatureGeneration = 0;
let loginAccessWrites = Promise.resolve();

function loginMatch(url) {
  try {
    const u = new URL(url);
    return (u.protocol === "https:" || (u.protocol === "http:" && u.hostname === "localhost")) ? `${u.protocol}//${u.hostname}/*` : null;
  } catch (_) { return null; }
}

async function loginPreferences() {
  const stored = await chrome.storage.local.get(["loginSuggestionsEnabled", "loginSuggestionsExcluded"]);
  return { enabled: stored.loginSuggestionsEnabled !== false,
    excluded: Array.isArray(stored.loginSuggestionsExcluded) ? stored.loginSuggestionsExcluded : [] };
}

async function loginAccess(url) {
  const match = loginMatch(url);
  const prefs = await loginPreferences();
  return Boolean(match && prefs.enabled && !prefs.excluded.includes(new URL(url).hostname) &&
    await chrome.permissions.contains({ origins: [match] }));
}

// One serialized registration replaces the legacy per-host script, including on update.
function reconcileLoginScripts() {
  const next = loginAccessWrites.then(writeLoginScripts);
  loginAccessWrites = next.catch(() => {});
  return next;
}
async function writeLoginScripts() {
  const prefs = await loginPreferences();
  const granted = (await chrome.permissions.getAll()).origins || [];
  const matches = prefs.enabled ? granted.filter((m) => /^https:\/\//.test(m) || m === "http://localhost/*") : [];
  const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [LOGIN_SCRIPT] });
  const excludeMatches = prefs.excluded.flatMap((host) => [ `https://${host}/*`, ...(host === "localhost" ? ["http://localhost/*"] : []) ]);
  const spec = { id: LOGIN_SCRIPT, matches, excludeMatches, js: ["login-target.js", "login-suggestions.js"],
    runAt: "document_idle", allFrames: true, matchOriginAsFallback: true, persistAcrossSessions: true };
  const old = scripts[0];
  if (old && JSON.stringify([old.matches, old.excludeMatches || [], old.matchOriginAsFallback]) ===
      JSON.stringify([matches, excludeMatches, true])) return;
  if (old) await chrome.scripting.unregisterContentScripts({ ids: [LOGIN_SCRIPT] });
  if (matches.length) await chrome.scripting.registerContentScripts([spec]);
  for (const tab of await chrome.tabs.query({})) {
    if (!loginMatch(tab.url)) continue;
    try {
      if (await loginAccess(tab.url)) {
        await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, files: spec.js });
      } else {
        await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true },
          func: () => self.apassyStopLoginSuggestions?.() });
      }
    } catch (_) { /* Browser may refuse a frame or a tab that just navigated. */ }
  }
}
async function loginAccessChange(_url, on) {
  loginFeatureGeneration++; loginOffers.clear();
  await chrome.storage.local.set({ loginSuggestionsEnabled: on });
  await reconcileLoginScripts();
  return { ok: true, on };
}
async function loginSiteChange(url, on) {
  if (!loginMatch(url)) return failure("unsupported_page");
  loginFeatureGeneration++; loginOffers.clear();
  const prefs = await loginPreferences();
  const excluded = new Set(prefs.excluded);
  const host = new URL(url).hostname;
  if (on) excluded.delete(host); else excluded.add(host);
  await chrome.storage.local.set({ loginSuggestionsExcluded: [...excluded] });
  await reconcileLoginScripts();
  return { ok: true, on };
}

async function captureLoginTarget(tabId, url) {
  if (!(await tabOn(tabId, url))) return null;
  try {
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["login-target.js"] });
    const [result] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: () => self.apassyLoginTarget.capture() });
    if (!result || !result.documentId || !result.result) return null;
    if (!result.result.ok) return { failure: ["no_fields", "form_origin", "frame"].includes(result.result.reason) ? result.result.reason : "page_changed" };
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
      func: (origin, token, op, values, inline) => self.origin === origin && self.apassyLoginTarget && (!inline || self.apassyLoginSuggestionsEnabled === true)
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
  if (target?.failure) return failure(target.failure, MESSAGES[target.failure] || "Focus the intended login field, then open Apassy. Frames can be opened in their own tab.");
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
      typeof sender.documentId !== "string" || !sender.documentId ||
      !(loginMatch(sender.url) || ["about:blank", "about:srcdoc"].includes(sender.url)) ||
      (loginMatch(sender.url) && originOf(sender.url) !== sender.origin) || originOf(sender.tab.url) !== sender.origin) return failure("unsupported_frame", "Open this sign-in page in its own tab, then use Apassy.");
  if (!(await loginAccess(sender.tab.url))) return failure("site_access", "Enable login suggestions for this site from the Apassy toolbar.");
  const active = await targetTab();
  if (!active || active.id !== sender.tab.id || originOf(active.url) !== sender.origin) return failure("page_changed");
  if (!message || !["login_suggestions", "login_fill", "login_show"].includes(message.type) ||
      Object.keys(message).some((key) => !["type", "token", "username", "item"].includes(key))) return failure("bad_request");
  const target = { tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId,
    origin: sender.origin, url: sender.tab.url, token: message.token, inline: true, generation: loginFeatureGeneration };
  if (!validLoginTarget(target, sender.tab.id, sender.tab.url) || !(await targetCall(target, "read"))?.ok) return failure("page_changed");
  const key = `${target.tabId}:${target.documentId}:${target.token}`;
  if (message.type === "login_show") {
    const answer = await ask({ cmd: "show" });
    return { ok: answer?.ok === true, code: answer?.code || "host_failed", message: messageOf(answer) };
  }
  if (message.type === "login_suggestions") {
    if (typeof message.username !== "string" || bytes(message.username) > 1024) return failure("bad_request");
    const answer = await ask({ cmd: "suggestions", url: sender.tab.url, username: message.username });
    if (!answer?.ok) { loginOffers.clear(); return failure(answer?.code || "host_failed", messageOf(answer)); }
    if (answer.data?.type !== "logins" || answer.data.origin !== sender.origin || !(await targetCall(target, "read"))?.ok) return failure("page_changed");
    const logins = (answer.data.logins || []).filter((l) => Number.isInteger(l.item) && typeof l.title === "string" && typeof l.username === "string")
      .map(({ item, title, username }) => ({ item, title, username }));
    for (const [offerKey, offer] of loginOffers) if (Date.now() - offer.at > LOGIN_RESULT_TTL) loginOffers.delete(offerKey);
    while (loginOffers.size >= 128) loginOffers.delete(loginOffers.keys().next().value);
    loginOffers.set(key, { at: Date.now(), items: logins.map((l) => l.item) });
    let emptyReason = logins.length ? null : "no_logins";
    if (!logins.length && message.username.trim()) {
      const all = await ask({ cmd: "suggestions", url: sender.tab.url, username: "" });
      if (!all?.ok) return failure(all?.code || "host_failed", messageOf(all));
      if (all.data?.type !== "logins" || all.data.origin !== sender.origin || !(await targetCall(target, "read"))?.ok) return failure("page_changed");
      if (all.data.logins?.length) emptyReason = "username";
    }
    return { ok: true, logins, emptyReason };
  }
  const offer = loginOffers.get(key);
  if (!Number.isInteger(message.item) || !offer || Date.now() - offer.at > LOGIN_RESULT_TTL || !offer.items.includes(message.item)) return failure("bad_request");
  loginOffers.delete(key);
  return withBadge(() => fill(target.tabId, target.url, message.item, target));
}

chrome.permissions.onAdded.addListener(() => { reconcileLoginScripts().catch(() => {}); });
chrome.permissions.onRemoved.addListener(() => {
  loginFeatureGeneration++; loginOffers.clear();
  reconcileLoginScripts().catch(() => {});
});
// Runs when the worker starts, including the first start after an extension update.
reconcileLoginScripts().catch(() => {});
