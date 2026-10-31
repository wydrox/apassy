// A mock of apassy-browser-host for the tests. It speaks the native messaging
// framing of docs/contracts/browser-v1.md (a 32-bit little-endian length, then
// UTF-8 JSON), logs each request, and answers from a scenario file.
//
// The browser starts it through a shell wrapper (support/browser.mjs) that sets
// APASSY_MOCK_DIR and calls node by its absolute path.
//
// Scenario (APASSY_MOCK_DIR/scenario.json), read again for each request:
//   notRunning   true: answer not_running to everything
//   vault        "unlocked" | "locked" | "none"
//   logins       [{ item, title, username, password, site }]; site is a host
//   loginsCode   an error code to answer to logins
//   fill         { code: "ok" | "cancelled" | ..., delayMs, origin, holdReply }
//   save         { code: "ok" | "exists" | "cancelled" | ..., delayMs, item, message }
//   create       { code: "ok" | "cancelled" | ..., delayMs, item, origin, password }
//
// Like the app, it answers bad_request to a missing or an unknown field.

import fs from "node:fs";
import path from "node:path";

const EXTENSION_ORIGIN = "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/";
const dir = process.env.APASSY_MOCK_DIR;

if (process.argv[2] !== EXTENSION_ORIGIN || !dir) {
  process.exit(2);
}

const MESSAGES = {
  bad_request: "Apassy did not understand the request.",
  bad_version: "Update Apassy or the extension.",
  not_running: "Open Apassy to fill logins.",
  none_open: "Open a vault in Apassy.",
  vault_locked: "Unlock Apassy to fill logins.",
  unsupported_page: "Apassy fills logins on https pages only.",
  no_match: "This login is not for this page.",
  busy: "Apassy is busy with another check. Try again.",
  cancelled: "The fill was cancelled. Nothing was filled.",
  owner_check_failed: "The check failed. Nothing was filled.",
  refused: "The vault refused the fill.",
  timeout: "Apassy did not answer in time.",
  stopped: "Apassy is quitting.",
  exists: "A login with this username is already in Apassy for this page. Nothing was saved.",
};

const CREATED_PASSWORD = "Mock-generated_Passw0rd!42";

// The fields of each command, as in docs/contracts/browser-v1.md, section 2.
const FIELDS = {
  status: {},
  show: {},
  logins: { url: true },
  suggestions: { url: true, username: false },
  update: { url: true, item: true, username: true, password: true, trusted_gesture: false },
  fill: { url: true, item: true, trusted_gesture: false },
  save: { url: true, title: true, username: true, password: true, trusted_gesture: false },
  create: { url: true, title: true, username: true, length: true, symbols: true, trusted_gesture: false },
};

function wellFormed(request) {
  const fields = FIELDS[request.cmd];
  if (!fields) return false;
  if ("trusted_gesture" in request && typeof request.trusted_gesture !== "boolean") return false;
  for (const key of Object.keys(request)) {
    if (key !== "v" && key !== "cmd" && !(key in fields)) return false;
  }
  for (const [key, required] of Object.entries(fields)) {
    if (required && !(key in request)) return false;
  }
  const text = (value, max) => typeof value === "string" && value.trim().length > 0 &&
    Buffer.byteLength(value.trim()) <= max;
  if ("title" in fields && !text(request.title, 128)) return false;
  if ("username" in fields && request.cmd !== "suggestions" && !text(request.username, 1024)) return false;
  if (request.cmd === "suggestions" && "username" in request && (typeof request.username !== "string" || Buffer.byteLength(request.username) > 1024)) return false;
  if (["save", "update"].includes(request.cmd) && !(typeof request.password === "string" &&
    request.password.length > 0 && Buffer.byteLength(request.password) <= 4096)) return false;
  if (request.cmd === "create" && !(Number.isInteger(request.length) &&
    request.length >= 12 && request.length <= 64 && typeof request.symbols === "boolean")) return false;
  return true;
}

function scenario() {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, "scenario.json"), "utf8"));
  } catch {
    return { vault: "unlocked", logins: [] };
  }
}

function log(request) {
  fs.appendFileSync(path.join(dir, "requests.jsonl"), JSON.stringify(request) + "\n");
}

function write(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([head, body]));
}

function error(code) {
  return { ok: false, code, message: MESSAGES[code] || code, data: { type: "none" } };
}

function pageOf(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && local)) return null;
  return { origin: parsed.origin, host: parsed.host, hostname: parsed.hostname };
}

function matches(login, page) {
  return page.hostname === login.site || page.hostname.endsWith("." + login.site);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A test releases approval only after navigation/replacement has actually
// completed. The barrier is synthetic fixture state, never a wire field.
async function waitForReplyRelease(config) {
  if (!config.holdReply) return true;
  if (typeof config.holdReply !== "string" || !/^[a-z0-9-]{1,80}$/.test(config.holdReply)) return false;
  const release = path.join(dir, `release-${config.holdReply}`);
  const deadline = Date.now() + 30000;
  while (!fs.existsSync(release)) {
    if (Date.now() >= deadline) return false; // fail closed; never release a secret on timeout
    await sleep(10);
  }
  return true;
}

async function answer(request) {
  const s = scenario();
  if (!request || request.v !== 1) return error("bad_version");
  if (s.notRunning) return error("not_running");
  if (!wellFormed(request)) return error("bad_request");
  const vault = s.vault || "unlocked";

  switch (request.cmd) {
    case "status":
      return { ok: true, code: "ok", message: "Apassy runs.", data: { type: "status", vault, version: "0.3.2" } };
    case "show":
      return { ok: true, code: "ok", message: "Apassy is in front.", data: { type: "none" } };
    case "suggestions":
    case "logins": {
      if (vault === "locked") return error("vault_locked");
      if (vault === "none") return error("none_open");
      if (s.loginsCode) return error(s.loginsCode);
      const page = pageOf(request.url);
      if (!page) return error("unsupported_page");
      const logins = (s.logins || [])
        .filter((login) => matches(login, page))
        .filter((login) => request.cmd !== "suggestions" || login.username.toLowerCase().startsWith((request.username || "").trim().toLowerCase()))
        .slice(0, 50)
        .map(({ item, title, username }) => ({ item, title, username }));
      return { ok: true, code: "ok", message: "", data: { type: "logins", origin: page.origin, host: page.host, logins } };
    }
    case "fill": {
      if (vault === "locked") return error("vault_locked");
      const page = pageOf(request.url);
      if (!page) return error("unsupported_page");
      const login = (s.logins || []).find((l) => l.item === request.item && matches(l, page));
      if (!login) return error("no_match");
      const fill = s.fill || {};
      if (!(await waitForReplyRelease(fill))) return error("timeout");
      if (fill.delayMs) await sleep(fill.delayMs);
      if (fill.code && fill.code !== "ok") return error(fill.code);
      return {
        ok: true,
        code: "ok",
        message: "Filled.",
        data: {
          type: "fill",
          item: login.item,
          origin: fill.origin || page.origin,
          username: login.username,
          password: login.password,
        },
      };
    }
    case "update": {
      if (vault === "locked") return error("vault_locked");
      if (vault === "none") return error("none_open");
      const page = pageOf(request.url);
      if (!page) return error("unsupported_page");
      const index = (s.logins || []).findIndex((l) => l.item === request.item && l.username === request.username && matches(l, page));
      if (index < 0) return error("no_match");
      if (s.update?.delayMs) await sleep(s.update.delayMs);
      if (s.update?.code && s.update.code !== "ok") return error(s.update.code);
      s.logins[index] = { ...s.logins[index], password: request.password };
      fs.writeFileSync(path.join(dir, "scenario.json"), JSON.stringify(s));
      return { ok: true, code: "ok", message: "Updated.", data: { type: "updated", item: request.item, origin: page.origin, username: request.username } };
    }
    case "save": {
      if (vault === "locked") return error("vault_locked");
      const page = pageOf(request.url);
      if (!page) return error("unsupported_page");
      const save = s.save || {};
      if (save.delayMs) await sleep(save.delayMs);
      if (save.code && save.code !== "ok") {
        return { ...error(save.code), message: save.message || MESSAGES[save.code] || save.code };
      }
      return { ok: true, code: "ok", message: "Saved.", data: { type: "saved", item: save.item || 12 } };
    }
    case "create": {
      if (vault === "locked") return error("vault_locked");
      const page = pageOf(request.url);
      if (!page) return error("unsupported_page");
      const create = s.create || {};
      if (!(await waitForReplyRelease(create))) return error("timeout");
      if (create.delayMs) await sleep(create.delayMs);
      // The host dies after the app made the login: no answer reaches the browser.
      if (create.crash) process.exit(0);
      if (create.code && create.code !== "ok") return error(create.code);
      return {
        ok: true,
        code: "ok",
        message: "Filled.",
        data: {
          type: "fill",
          item: create.item || 13,
          origin: create.origin || page.origin,
          username: request.username.trim(),
          password: create.password || CREATED_PASSWORD,
        },
      };
    }
    default:
      return error("bad_request");
  }
}

let buffered = Buffer.alloc(0);
let queue = Promise.resolve();

process.stdin.on("data", (chunk) => {
  buffered = Buffer.concat([buffered, chunk]);
  while (buffered.length >= 4) {
    const length = buffered.readUInt32LE(0);
    if (length > 64 * 1024) process.exit(1);
    if (buffered.length < 4 + length) break;
    const body = buffered.subarray(4, 4 + length).toString("utf8");
    buffered = buffered.subarray(4 + length);
    let request;
    try {
      request = JSON.parse(body);
    } catch {
      request = null;
    }
    log(request);
    queue = queue.then(async () => write(await answer(request)));
  }
});

process.stdin.on("end", () => {
  queue.then(() => process.exit(0));
});
