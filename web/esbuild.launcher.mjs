// Bundles the launcher UI into a single self-contained HTML page.
//
// The launcher serves only "/", so the page must carry its own styles and
// script inline. The result is written to internal/launcher/dist/index.html,
// where the Go embed directive picks it up.
import * as esbuild from "esbuild";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export async function buildLauncher() {
  const result = await esbuild.build({
    entryPoints: [resolve(here, "src/launcher/main.ts")],
    bundle: true,
    format: "iife",
    target: ["es2020"],
    minify: true,
    legalComments: "none",
    write: false,
    logLevel: "warning",
  });

  const script = result.outputFiles[0]?.text ?? "";
  const shell = readFileSync(resolve(here, "launcher/index.html"), "utf8");
  const style = readFileSync(resolve(here, "launcher/launcher.css"), "utf8");

  const page = shell
    .replace(
      '<link rel="stylesheet" href="/launcher.css" />',
      `<style>\n${style.trim()}\n</style>`,
    )
    .replace(
      '<script type="module" src="/launcher.js"></script>',
      `<script>\n${script.trim()}\n</script>`,
    );

  if (page.includes("/launcher.css") || page.includes("/launcher.js")) {
    throw new Error("launcher shell: external asset references were not replaced");
  }

  const out = resolve(here, "../internal/launcher/dist");
  mkdirSync(out, { recursive: true });
  writeFileSync(resolve(out, "index.html"), page);
  console.log(
    `launcher UI built into internal/launcher/dist/index.html (${(page.length / 1024).toFixed(1)} KiB)`,
  );
}
