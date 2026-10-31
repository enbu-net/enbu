// Packages the extension as a VSIX for one VS Code target, with enbu inside.
//
//   node scripts/package.mjs --enbu PATH [--target TARGET] [--version VERSION] [--out FILE]
//
// The binary goes into bin/<target>/ (linux-x64, darwin-arm64, win32-x64, ...;
// default: this machine), so the Marketplace and `code --install-extension`
// install it with the extension. Run `vp run build` first.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { packagePlan } from "./plan.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({
  options: {
    enbu: { type: "string" },
    target: { type: "string" },
    version: { type: "string" },
    out: { type: "string" },
  },
});

for (const built of ["dist/extension.cjs", "media/web/index.html"]) {
  if (!existsSync(join(root, built))) {
    console.error(`${built} is missing. Run \`vp run build\` first.`);
    process.exit(1);
  }
}
const plan = packagePlan(values, process);

// bin/ holds only this package's binary, so a VSIX never carries another target's.
const dir = join(root, "bin", plan.target);
rmSync(join(root, "bin"), { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
copyFileSync(resolve(values.enbu), join(dir, plan.binaryName));
chmodSync(join(dir, plan.binaryName), 0o755);
copyFileSync(join(root, "..", "LICENSE"), join(root, "LICENSE"));

const args = ["package", "--no-dependencies", "--target", plan.target];
if (plan.version) args.push(plan.version, "--no-update-package-json", "--no-git-tag-version");
if (values.out) args.push("--out", resolve(values.out));
const vsce = join(root, "node_modules", "@vscode", "vsce", "vsce");
execFileSync(process.execPath, [vsce, ...args], { cwd: root, stdio: "inherit" });
