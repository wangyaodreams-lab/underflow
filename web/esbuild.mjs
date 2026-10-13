// Bundles the TypeScript frontend into web/dist with esbuild.
// Type-checking is done separately via `npm run typecheck`.
import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "dist");
mkdirSync(dist, { recursive: true });

copyFileSync(resolve(here, "index.html"), resolve(dist, "index.html"));

await esbuild.build({
  entryPoints: [resolve(here, "src/main.ts")],
  bundle: true,
  format: "esm",
  target: ["es2020"],
  outfile: resolve(dist, "app.js"),
  minify: true,
  legalComments: "none",
  logLevel: "info",
});

await esbuild.build({
  entryPoints: [resolve(here, "src/styles.css")],
  bundle: true,
  outfile: resolve(dist, "app.css"),
  minify: true,
  logLevel: "info",
});

console.log("frontend built into web/dist");
