import { defineConfig } from "astro/config";

// A static site. wrangler.jsonc serves dist/ as the assets of the Worker in
// worker/index.ts, which adds the download routes.
export default defineConfig({
  site: "https://apassy.wyderka.cc",
  output: "static",
  // The screenshots (docs/images) and CHANGELOG.md live outside site/.
  vite: { server: { fs: { allow: [".."] } } },
});
