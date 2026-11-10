// Checks the built browser preview (dist-preview, `vp build --mode preview`)
// against WCAG 2.2 A and AA with axe-core in Chromium: every dashboard tab and
// the popovers and dialogs it opens, in the light and the dark theme, in
// English and Japanese, and in a narrow window. Any violation fails the run. Run it with `task gui/a11y`.
//
// ENBU_A11Y_CHROMIUM overrides the Chromium binary (a preinstalled browser).
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

const root = fileURLToPath(new URL("../dist-preview/", import.meta.url));
// The preview's base (vite.config.ts); it also selects the preview backend.
const base = "/enbu/web/";

const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];
// Every theme in both languages, and a narrow window (the sidebar collapses).
const runs = ["light", "dark"].flatMap((theme) => [
  { theme, locale: "en", width: 1280 },
  { theme, locale: "ja", width: 1280 },
  { theme, locale: "en", width: 400 },
]);

// One control of each kind that opens a popover or a dialog, in both languages.
const openers = [
  'button[aria-label^="Current environment"]',
  'button[aria-label^="現在の環境"]',
  'button[aria-haspopup="dialog"]',
  'button[aria-label^="Delete: "]',
  'button[aria-label^="削除: "]',
  'button:text-is("Approve")',
  'button:text-is("承認")',
];

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
const url = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}${base}`;

const browser = await chromium.launch({
  executablePath: process.env.ENBU_A11Y_CHROMIUM || undefined,
});

/** Runs axe on the page and returns its violations, labelled with where they were found. */
async function audit(page, where) {
  await page.evaluate(axeSource);
  const result = await page.evaluate(
    (runTags) =>
      // eslint-disable-next-line no-undef
      axe.run(document, { runOnly: { type: "tag", values: runTags }, resultTypes: ["violations"] }),
    tags,
  );
  console.log(`${result.violations.length ? "FAIL" : "ok  "} ${where}`);
  return result.violations.map((violation) => ({ where, ...violation }));
}

const violations = [];
let audits = 0;
try {
  for (const { theme, locale, width } of runs) {
    {
      const run = `${theme}/${locale}/${width}px`;
      const context = await browser.newContext({
        colorScheme: theme,
        locale,
        viewport: { width, height: 800 },
        reducedMotion: "reduce",
      });
      await context.addInitScript(
        ([savedTheme, savedLocale]) => {
          localStorage.setItem("enbu-theme", savedTheme);
          localStorage.setItem("PARAGLIDE_LOCALE", savedLocale);
        },
        [theme, locale],
      );
      const page = await context.newPage();
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(url);
      const tabs = page.getByRole("tab");
      await tabs.first().waitFor();
      const count = await tabs.count();
      const opened = new Set();
      for (let i = 0; i < count; i++) {
        const tab = tabs.nth(i);
        const name = (await tab.getAttribute("aria-label")) ?? `tab ${i + 1}`;
        await tab.click();
        await page.waitForLoadState("networkidle");
        // Let transitions and the tab's first backend calls settle.
        await page.waitForTimeout(300);
        violations.push(...(await audit(page, `${run}: ${name}`)));
        audits++;
        // Popovers and dialogs the tab opens, each checked open and then closed,
        // once per page for a control every tab shares.
        for (const selector of openers) {
          const opener = page.locator(`${selector}:visible:enabled`).first();
          if (!(await opener.count())) continue;
          const label = (
            (await opener.getAttribute("aria-label")) ?? (await opener.innerText())
          ).trim();
          if (opened.has(label)) continue;
          opened.add(label);
          await opener.click();
          await page.waitForTimeout(300);
          violations.push(...(await audit(page, `${run}: ${name} > ${label}`)));
          audits++;
          await page.keyboard.press("Escape");
          await page.waitForTimeout(200);
        }
      }
      if (errors.length) throw new Error(`page errors in ${run}: ${errors.join("; ")}`);
      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}

for (const violation of violations) {
  console.error(`\n[${violation.where}] ${violation.id} (${violation.impact}): ${violation.help}`);
  console.error(`  ${violation.helpUrl}`);
  for (const node of violation.nodes) {
    console.error(`  - ${node.target.join(" ")}`);
    console.error(`    ${node.failureSummary?.replaceAll("\n", "\n    ")}`);
  }
}
if (violations.length) {
  console.error(`\nWCAG check failed: ${violations.length} violation(s) in ${audits} screen(s).`);
  process.exit(1);
}
console.log(`WCAG 2.2 AA: no violations in ${audits} screen(s).`);
