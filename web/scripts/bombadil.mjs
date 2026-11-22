// Explores the built browser preview (dist-preview, `vp build --mode preview`)
// with Bombadil, which clicks, types and navigates at random and checks the
// properties in bombadil/spec.ts in every state it reaches. Run it with
// `task gui/bombadil`; it exits 2 when a property fails. The trace it writes,
// bombadil-trace.bin, opens with `bombadil browser inspect bombadil-trace.bin`
// and replays with `task gui/bombadil -- --reproduce bombadil-trace.bin`.
//
// ENBU_BOMBADIL_TIME_LIMIT sets how long it explores (default 1m).
// ENBU_A11Y_CHROMIUM overrides the Chromium binary (a preinstalled browser).
import { spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { servePreview } from "./preview-server.mjs";

const web = fileURLToPath(new URL("..", import.meta.url));
// A fixed port: a trace records the URL, and replaying one needs the same.
const port = 41730;
// `node scripts/bombadil.mjs --reproduce TRACE` replays a trace instead.
const reproduce = process.argv.slice(2);
const explore = [
  "--exit-on-violation",
  `--time-limit=${process.env.ENBU_BOMBADIL_TIME_LIMIT || "1m"}`,
  "--output-path=bombadil-trace.bin",
  "--output-path-overwrite",
];
const server = await servePreview(port);
let status;
try {
  // Asynchronously: this process serves the preview while Bombadil runs.
  status = await new Promise((resolve, reject) => {
    const child = spawn(
      join(web, "node_modules", ".bin", "bombadil"),
      [
        "browser",
        "test",
        "--headless",
        // Playwright launches its Chromium without the sandbox too: CI runners
        // do not allow the unprivileged user namespaces it needs.
        "--no-sandbox",
        ...(reproduce.length ? reproduce : explore),
        server.url,
        "bombadil/spec.ts",
      ],
      {
        cwd: web,
        stdio: "inherit",
        env: {
          ...process.env,
          CHROME: process.env.ENBU_A11Y_CHROMIUM || chromium.executablePath(),
        },
      },
    );
    child.on("error", reject);
    child.on("exit", (code) => resolve(code ?? 1));
  });
} finally {
  server.close();
}
process.exit(status);
