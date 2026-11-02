// Keep the extension's static security boundary check available without a browser.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { EXTENSION_DIR } from "../passkey-bridge/mock-chrome.mjs";

test("all extension sources pass the forbidden API and remote request scan", () => {
  const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
  for (const file of walk(EXTENSION_DIR).filter(file => /\.(js|html)$/.test(file))) {
    const source = fs.readFileSync(file, "utf8").replace(/https?:\/\/(?:\*|localhost|\$\{host\})\/\*/g, "");
    assert.doesNotMatch(source, /console\.|eval\(|new Function|clipboard|fetch\(|XMLHttpRequest|https?:\/\/(?!127\.0\.0\.1)/, file);
  }
});
