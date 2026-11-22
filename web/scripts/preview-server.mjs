// Serves the built browser preview (dist-preview, `vp build --mode preview`)
// on a free loopback port, for the checks that drive it in a browser
// (a11y.mjs, bombadil.mjs). Unknown paths get index.html, as on GitHub Pages.
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist-preview/", import.meta.url));
// The preview's base (vite.config.ts); it also selects the preview backend.
const base = "/enbu/web/";

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".wasm": "application/wasm",
  ".json": "application/json",
};

/** Starts the server and returns the preview's URL and a function that stops it. */
export async function servePreview() {
  if (!existsSync(join(root, "index.html"))) {
    console.error("dist-preview/index.html is missing: run `vp build --mode preview` first.");
    process.exit(2);
  }
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
    let file = path.startsWith(base) ? normalize(join(root, path.slice(base.length))) : "";
    if (!file.startsWith(root) || !existsSync(file) || statSync(file).isDirectory()) {
      file = join(root, "index.html");
    }
    res.writeHead(200, { "Content-Type": types[extname(file)] ?? "application/octet-stream" });
    createReadStream(file).pipe(res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { url: `http://127.0.0.1:${port}${base}`, close: () => server.close() };
}
