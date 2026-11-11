// Runs Modern Web Guidance's legacy-scan (GoogleChrome/modern-web-guidance)
// over the UI and fails on any finding. The scan covers the guides with
// deterministic rules; the enbu Oxlint rules and src/index-html.test.ts check
// more of the guidance.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("..", import.meta.url));
const scanner = fileURLToPath(
  new URL(
    "../node_modules/modern-web-guidance/skills/modern-web-guidance/legacy-scan.mjs",
    import.meta.url,
  ),
);
const targets = ["src", "index.html"];

let failed = false;
for (const target of targets) {
  const run = spawnSync(process.execPath, [scanner, target, "--json"], {
    cwd: web,
    encoding: "utf8",
    env: { ...process.env, DISABLE_TELEMETRY: "1", NO_COLOR: "1" },
  });
  if (run.status !== 0) {
    process.stderr.write(run.stderr);
    console.error(`legacy-scan ${target} failed (exit ${run.status})`);
    process.exit(1);
  }
  const report = JSON.parse(run.stdout);
  for (const guide of report.guides ?? []) {
    for (const rule of guide.rules ?? []) {
      for (const finding of rule.findings ?? []) {
        failed = true;
        const file = target === "src" ? `src/${finding.file}` : target;
        console.error(`${file}:${finding.line}: ${finding.message}`);
        console.error(`  guide: npx modern-web-guidance retrieve ${guide.guideId}`);
      }
    }
  }
}

if (failed) process.exit(1);
console.log(`legacy-scan: no legacy patterns in ${targets.join(", ")}`);
