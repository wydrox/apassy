// A mock of apassy-browser-host for the Helium passkey and one-time code
// tests. It is NOT Apassy: passkeys come from the SYNTHETIC authenticator of
// this folder, codes from the scenario file. It speaks the native messaging
// framing (32-bit little-endian length, then UTF-8 JSON).
//
// APASSY_MOCK_DIR holds:
//   scenario.json   read again for each request:
//                   { vault, logins: [{ item, title, username, has_totp, site }],
//                     code: { value, origin, delayMs, error },
//                     passkey: { error, delayMs } }
//   events.jsonl    one line per request ({ cmd, ...wire }) and per end of input
//                   ({ event: "eof", pendingRid }), so a test can see that a
//                   cancel reached the host before it answered
//   keys.json       the synthetic keys

import fs from "node:fs";
import path from "node:path";
import { createSyntheticAuthenticator, fail, ok } from "./synthetic-authenticator.mjs";

const EXTENSION_ORIGIN = "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/";
const dir = process.env.APASSY_MOCK_DIR;
if (process.argv[2] !== EXTENSION_ORIGIN || !dir) process.exit(2);

const scenario = () => {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, "scenario.json"), "utf8"));
  } catch {
    return {};
  }
};
const log = (entry) => fs.appendFileSync(path.join(dir, "events.jsonl"), JSON.stringify(entry) + "\n");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function write(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([head, body]));
}

let pendingRid = null;

async function answer(request) {
  const s = scenario();
  if (!request || request.v !== 1) return fail("bad_version");
  switch (request.cmd) {
    case "status":
      return ok({ type: "status", vault: s.vault || "unlocked", version: "0.0.0-test" });
    case "logins": {
      const host = new URL(request.url).hostname;
      const logins = (s.logins || []).filter((l) => l.site === host)
        .map(({ item, title, username, has_totp }) => ({ item, title, username, has_totp }));
      return ok({ type: "logins", origin: new URL(request.url).origin, host: new URL(request.url).host, logins });
    }
    case "fill_code": {
      const code = s.code || {};
      if (code.delayMs) await sleep(code.delayMs);
      if (code.error) return fail(code.error);
      return ok({ type: "code", item: request.item, origin: code.origin || new URL(request.url).origin, code: code.value || "135790", remaining: 20 });
    }
    case "passkey_create":
    case "passkey_get": {
      pendingRid = request.rid;
      const passkey = s.passkey || {};
      if (passkey.delayMs) await sleep(passkey.delayMs);
      if (passkey.error) return fail(passkey.error);
      const authenticator = createSyntheticAuthenticator({ file: path.join(dir, "keys.json") });
      if (request.cmd === "passkey_create") return ok(authenticator.create(request));
      const signed = authenticator.get(request);
      return signed ? ok(signed) : fail("no_match");
    }
    default:
      return fail("bad_request");
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
    let request;
    try {
      request = JSON.parse(buffered.subarray(4, 4 + length).toString("utf8"));
    } catch {
      request = null;
    }
    buffered = buffered.subarray(4 + length);
    log(request);
    queue = queue.then(async () => {
      const reply = await answer(request);
      log({ event: "answer", cmd: request && request.cmd, ok: reply.ok, code: reply.code });
      write(reply);
      pendingRid = null;
    });
  }
});

// The extension closed the port. The real host must stop waiting for the app
// then; this mock only records whether a request was still open.
process.stdin.on("end", () => {
  log({ event: "eof", pendingRid });
  process.exit(0);
});
