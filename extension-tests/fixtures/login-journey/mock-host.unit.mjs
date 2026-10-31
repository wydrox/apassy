// Native framing and held-reply barriers against only the synthetic fixture host.
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
const host = fileURLToPath(new URL("../../mock-host/mock-host.mjs", import.meta.url));
const extension = "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/";
async function waitFor(check) {
  const deadline = Date.now() + 5000;
  while (!check()) {
    assert.ok(Date.now() < deadline, "synthetic host did not reach its barrier");
    await delay(5);
  }
}
for (const command of ["fill", "create"]) for (const gesture of [false, true]) {
  test(`synthetic ${command} (gesture=${gesture}) replies only after the fixture releases its barrier`, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "apassy-reply-barrier-"));
    const token = `${command}-held`;
    fs.writeFileSync(path.join(dir, "scenario.json"), JSON.stringify({
      vault: "unlocked", [command]: { holdReply: token },
      logins: [{ item: 7, title: "Synthetic", username: "synthetic", password: "fixture-password", site: "example.test" }],
    }));
    const child = spawn(process.execPath, [host, extension], { env: { ...process.env, APASSY_MOCK_DIR: dir }, stdio: ["pipe", "pipe", "pipe"] });
    let output = Buffer.alloc(0);
    child.stdout.on("data", (chunk) => { output = Buffer.concat([output, chunk]); });
    try {
      const request = command === "fill"
        ? { v: 1, cmd: command, url: "https://example.test/login", item: 7 }
        : { v: 1, cmd: command, url: "https://example.test/signup", title: "Synthetic", username: "synthetic", length: 20, symbols: true };
      if (gesture) request.trusted_gesture = true;
      const body = Buffer.from(JSON.stringify(request));
      const header = Buffer.alloc(4); header.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([header, body]));
      await waitFor(() => fs.existsSync(path.join(dir, "requests.jsonl")));
      assert.equal(output.length, 0, "native reply escaped the held barrier");
      fs.writeFileSync(path.join(dir, `release-${token}`), "released");
      await waitFor(() => output.length >= 4 && output.length >= 4 + output.readUInt32LE(0));
      const answer = JSON.parse(output.subarray(4, 4 + output.readUInt32LE(0)));
      assert.equal(answer.ok, true);
      assert.equal(answer.data.type, "fill");
      assert.equal(answer.data.username, "synthetic");
    } finally {
      child.kill();
      await new Promise((resolve) => child.exitCode !== null ? resolve() : child.once("exit", resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
