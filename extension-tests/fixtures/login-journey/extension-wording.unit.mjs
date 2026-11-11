// The extension serves the Apassy app on macOS and on Linux (ADR 0045, unit L7). Its
// own texts, which every user reads, name nothing that exists only on a Mac: the
// manifest description (also the store summary), the popup page, and every string of
// the popup and service-worker scripts. Texts that come from the app are the app's.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { EXTENSION_DIR } from "../passkey-bridge/mock-chrome.mjs";

const MAC_ONLY = [/Touch ID/, /Apassy\.app/, /\bmacOS\b/, /\bMacs?\b/, /Keychain/, /Finder/, /iCloud/, /[⌘⌥⌃]/];

function read(name) {
  return fs.readFileSync(path.join(EXTENSION_DIR, name), "utf8");
}

// The string literals of a script, without its comments.
function strings(source) {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  return [...code.matchAll(/"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`/g)]
    .map(match => match[1] ?? match[2] ?? match[3]);
}

function macWords(text) {
  return MAC_ONLY.filter(pattern => pattern.test(text)).map(String);
}

test("the manifest description names no Mac-only thing and fits the store summary", () => {
  const manifest = JSON.parse(read("manifest.json"));
  assert.deepEqual(macWords(manifest.description), [], manifest.description);
  assert.ok(manifest.description.length <= 132, `${manifest.description.length} characters`);
});

test("the popup page names no Mac-only thing", () => {
  const text = read("popup.html").replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]*>/g, " ");
  assert.deepEqual(macWords(text), [], text);
});

for (const script of ["popup.js", "background.js", "login-save.js", "login-suggestions.js", "fill.js", "login-target.js"]) {
  test(`${script}: no string names a Mac-only thing`, () => {
    const found = strings(read(script))
      // Font stacks name the system fonts of every platform.
      .filter(text => !/BlinkMacSystemFont/.test(text))
      .filter(text => macWords(text).length > 0);
    assert.deepEqual(found, []);
  });
}
