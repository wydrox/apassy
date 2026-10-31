// Typed credentials exist only in this worker's memory, scoped to tab + exact
// origin. Worker suspension loses the offer safely; no storage API sees a secret.
const SAVE_TTL = 3 * 60 * 1000;
const SAVE_SUBMIT_TTL = 15 * 1000;
const pendingSaves = new Map();
const saveUsernames = new Map();

function forgetSave(tabId) {
  const entry = pendingSaves.get(tabId);
  if (entry) { entry.password = ""; clearTimeout(entry.timer); }
  pendingSaves.delete(tabId);
}
function forgetSaveUsername(tabId) {
  const entry = saveUsernames.get(tabId);
  if (entry) clearTimeout(entry.timer);
  saveUsernames.delete(tabId);
}
self.apassyClearSaveOffers = () => {
  for (const id of pendingSaves.keys()) forgetSave(id);
  for (const id of saveUsernames.keys()) forgetSaveUsername(id);
};

async function savePeer(sender, liveDocument = false) {
  if (sender?.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id) || sender.tab.id < 0 ||
      sender.frameId !== 0 || sender.documentLifecycle !== "active" || !sender.documentId ||
      !loginMatch(sender.url) || originOf(sender.url) !== sender.origin || originOf(sender.tab.url) !== sender.origin) return false;
  const tab = await chrome.tabs.get(sender.tab.id).catch(() => null);
  if (!tab || originOf(tab.url) !== sender.origin || !(await loginAccess(tab.url))) return false;
  if (!liveDocument) return true;
  try {
    const [result] = await chrome.scripting.executeScript({ target: { tabId: sender.tab.id, documentIds: [sender.documentId] },
      func: (origin) => self.origin === origin && self.apassyLoginSuggestionsEnabled === true,
      args: [sender.origin] });
    return result?.documentId === sender.documentId && result.result === true;
  } catch (_) { return false; }
}

// Match the app's case-insensitive duplicate identity, then use the exact stored
// username for its update gate. A capped result or multiple matches is ambiguous.
function saveDecision(answer, origin, username) {
  if (!answer?.ok || answer.data?.type !== "logins" || answer.data.origin !== origin || !Array.isArray(answer.data.logins)) return null;
  const logins = answer.data.logins;
  const wanted = username.trim().toLowerCase();
  const exact = logins.filter((l) => typeof l.username === "string" && l.username.trim().toLowerCase() === wanted && Number.isInteger(l.item));
  if (logins.length >= 50 || exact.length > 1) return null;
  if (exact.length === 1) return { mode: "update", item: exact[0].item, username: exact[0].username };
  return { mode: "save" };
}

async function handleLoginSave(message, sender) {
  // Erase the incoming message's secret even when sender validation fails.
  let incoming = typeof message?.password === "string" ? message.password : "";
  if (message && Object.hasOwn(message, "password")) message.password = "";
  try {
    if (!(await savePeer(sender))) return failure("page_changed");
    const tabId = sender.tab.id, origin = sender.origin;
    const allowed = {
      login_save_capture: ["type", "attempt", "username", "password"],
      login_save_ready: ["type", "attempt"], login_save_offer: ["type"],
      login_save_cancel: ["type", "attempt"],
      login_save_action: ["type", "id", "action", "trustedGesture"],
    }[message.type];
    if (!allowed || Object.keys(message).some((key) => !allowed.includes(key))) return failure("bad_request");
    if (message.type === "login_save_capture") {
      if (typeof message.attempt !== "string" || !/^[0-9a-f-]{36}$/.test(message.attempt) ||
          typeof message.username !== "string" || bytes(message.username) > 1024 || bytes(incoming) > 4096) return failure("bad_request");
      let username = message.username.trim();
      if (!incoming) {
        if (!username) return failure("bad_request");
        forgetSaveUsername(tabId);
        saveUsernames.set(tabId, { origin, username, until: Date.now() + SAVE_TTL,
          timer: setTimeout(() => forgetSaveUsername(tabId), SAVE_TTL) });
        return { ok: true };
      }
      const remembered = saveUsernames.get(tabId);
      if (!username && remembered?.origin === origin && remembered.until > Date.now()) username = remembered.username;
      forgetSaveUsername(tabId);
      forgetSave(tabId);
      if (!username) return failure("bad_request");
      // Bound total retained credentials even with many independently open tabs.
      if (pendingSaves.size >= 32) forgetSave(pendingSaves.keys().next().value);
      const entry = { id: crypto.randomUUID(), attempt: message.attempt, origin, username,
        password: incoming, documentId: sender.documentId, until: Date.now() + SAVE_TTL, ready: false };
      entry.timer = setTimeout(() => forgetSave(tabId), SAVE_SUBMIT_TTL);
      pendingSaves.set(tabId, entry);
      return { ok: true };
    }
    const entry = pendingSaves.get(tabId);
    if (!entry || entry.origin !== origin || Date.now() >= entry.until) { forgetSave(tabId); return { ok: true, offer: null }; }
    if (message.type === "login_save_cancel") {
      if (entry.attempt === message.attempt && entry.documentId === sender.documentId) forgetSave(tabId);
      return { ok: true };
    }
    if (message.type === "login_save_ready") {
      if (entry.documentId !== sender.documentId || entry.attempt !== message.attempt) return failure("bad_request");
      entry.ready = true;
    }
    if (["login_save_ready", "login_save_offer"].includes(message.type)) {
      if (!entry.ready && entry.documentId === sender.documentId) return { ok: true, offer: null };
      entry.ready = true;
      clearTimeout(entry.timer);
      entry.timer = setTimeout(() => forgetSave(tabId), Math.max(0, entry.until - Date.now()));
      const generation = loginFeatureGeneration;
      const answer = await ask({ cmd: "suggestions", url: origin, username: entry.username });
      if (!(await savePeer(sender, true)) || pendingSaves.get(tabId) !== entry || entry.until <= Date.now() || generation !== loginFeatureGeneration) return failure("page_changed");
      const decision = saveDecision(answer, origin, entry.username);
      if (!decision) { forgetSave(tabId); return { ok: true, offer: null }; }
      Object.assign(entry, decision, { offerDocument: sender.documentId });
      return { ok: true, offer: { id: entry.id, username: entry.username, site: new URL(origin).host,
        mode: entry.mode, until: entry.until } };
    }
    if (message.type !== "login_save_action" || message.trustedGesture !== true || message.id !== entry.id ||
        entry.offerDocument !== sender.documentId || !entry.mode || !["accept", "dismiss", "never"].includes(message.action)) return failure("bad_request");
    if (message.action !== "accept") {
      forgetSave(tabId);
      if (message.action === "never") await loginSiteChange(origin, false);
      return { ok: true };
    }
    if (entry.accepting) return failure("busy");
    entry.accepting = true;
    // Negotiate with metadata only. Expiry/navigation can erase the pending
    // password even if an older/missing app stalls during the status probe.
    const compatible = await compatibleGestureRequest({ trusted_gesture: true });
    if (!(await savePeer(sender, true)) || pendingSaves.get(tabId) !== entry || entry.until <= Date.now()) {
      forgetSave(tabId); return failure("page_changed");
    }
    // Consume once, immediately before the native port clones the packet.
    let password = entry.password;
    forgetSave(tabId);
    let request;
    try {
      request = { cmd: entry.mode === "update" ? "update" : "save", url: origin,
        username: entry.username, password, ...compatible,
        ...(entry.mode === "update" ? { item: entry.item } : { title: new URL(origin).hostname }) };
      const waiting = askNative(request); // existing SaveLogin/UpdateLogin owner gate, including ADR 0030
      password = ""; request.password = "";
      const answer = await waiting;
      const data = answer?.data;
      const valid = entry.mode === "update" ? data?.type === "updated" && data.item === entry.item && data.origin === origin && data.username === entry.username
        : data?.type === "saved" && Number.isInteger(data.item);
      return answer?.ok && valid ? { ok: true, message: entry.mode === "update" ? "Login updated in Apassy." : "Login saved in Apassy." }
        : failure(answer?.ok ? "host_failed" : answer?.code || "host_failed", "Apassy did not confirm the action. Check this login in Apassy before trying again.");
    } finally { password = ""; if (request) request.password = ""; }
  } finally { incoming = ""; }
}

chrome.tabs.onRemoved?.addListener((tabId) => { forgetSave(tabId); forgetSaveUsername(tabId); });
chrome.tabs.onUpdated?.addListener((tabId, change) => {
  if (!change.url) return;
  const origin = originOf(change.url);
  if (pendingSaves.get(tabId)?.origin !== origin) forgetSave(tabId);
  if (saveUsernames.get(tabId)?.origin !== origin) forgetSaveUsername(tabId);
});
self.apassySaveTest = { handleLoginSave, saveDecision, pendingSaves, saveUsernames };
