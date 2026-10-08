// The tests start Helium themselves (support/fixtures.mjs): never Google
// Chrome and never a browser that Playwright downloads.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 2,
  reporter: [["list"]],
  forbidOnly: Boolean(process.env.CI),
});
