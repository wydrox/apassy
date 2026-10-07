import fs from "node:fs";
import path from "node:path";
import { test, expect, EXTENSION_DIR, EXTENSION_ID } from "../support/fixtures.mjs";

test("the loaded extension has the fixed ID", async ({ h }) => {
  const worker = await h.worker();
  expect(worker.url()).toBe(`chrome-extension://${EXTENSION_ID}/background.js`);
  expect(await worker.evaluate(() => chrome.runtime.id)).toBe(EXTENSION_ID);
});

test("the manifest asks only for nativeMessaging, activeTab, and scripting", async ({ h }) => {
  const manifest = await (await h.worker()).evaluate(() => chrome.runtime.getManifest());
  expect(manifest.manifest_version).toBe(3);
  expect(manifest.permissions).toEqual(["nativeMessaging", "activeTab", "scripting"]);
  expect(manifest.host_permissions).toBeUndefined();
  expect(manifest.content_scripts).toBeUndefined();
  expect(manifest.optional_permissions).toBeUndefined();
  expect(manifest.content_security_policy.extension_pages).toBe("script-src 'self'; object-src 'none'");
});

test("the extension folder holds only extension files", () => {
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? [full + "/", ...walk(full)] : [full];
  });
  const files = walk(EXTENSION_DIR).map((file) => path.relative(EXTENSION_DIR, file));
  for (const file of files) {
    expect(file.split("/").some((part) => part.startsWith("_")), file).toBe(false);
    expect(file, file).not.toMatch(/node_modules|\.spec\.|\.test\.|(^|\/)tests?\//);
  }
  const sources = files.filter((file) => /\.(js|html)$/.test(file))
    .map((file) => fs.readFileSync(path.join(EXTENSION_DIR, file), "utf8"));
  for (const source of sources) {
    expect(source).not.toMatch(/console\.|eval\(|new Function|clipboard|fetch\(|XMLHttpRequest|https?:\/\/(?!127\.0\.0\.1)/);
  }
});
