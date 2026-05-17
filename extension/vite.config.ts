// VITE BUILD CONFIGURATION
//
// Vite is a build tool that bundles our TypeScript files and their imports
// into single output files. This solves the Chrome extension limitation where
// content scripts and service workers can't use ES module 'import' statements
// at runtime — Vite resolves all imports at build time and inlines them.
//
// The Chrome extension has three independent entry points, each compiled
// into its own output file:
//   src/content/content.ts       -> dist/content/content.js
//   src/background/background.ts -> dist/background/background.js
//   src/popup/popup.ts           -> dist/popup/popup.js
//
// popup.html and popup.css are NOT processed by Vite — the build script
// copies them separately with the 'copyfiles' command in package.json.

import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    // Delete the dist/ folder before each build so stale files don't accumulate.
    emptyOutDir: true,
    rollupOptions: {
      // Three entry points. One per Chrome extension context.
      // Vite resolves these paths relative to the folder where vite.config.ts lives
      // (the extension/ folder), so no need for path.resolve() or __dirname.
      input: {
        content:    "src/content/content.ts",
        background: "src/background/background.ts",
        popup:      "src/popup/popup.ts",
      },
      output: {
        // Output each entry as dist/<name>/<name>.js
        // "content"    → dist/content/content.js    (manifest points here)
        // "background" → dist/background/background.js (manifest points here)
        // "popup"      → dist/popup/popup.js         (popup.html loads this)
        entryFileNames: "[name]/[name].js",
        // Use ES module format: Rollup's IIFE format does not support multiple
        // inputs. Since Vite resolves all imports at build time and our entry
        // points have no top-level exports, the bundled output contains no
        // import/export statements and runs correctly as a classic script in
        // Chrome's content-script, service-worker, and popup contexts.
        format: "es",
      },
    },
  },
});
