// Packages the extension as a VSIX.
//
//   node scripts/package.mjs [--enbu PATH [--target TARGET]] [--version VERSION] [--out FILE]
//
// With --enbu, the binary goes into bin/<target>/ and the VSIX is for that one
// VS Code target (linux-x64, darwin-arm64, win32-x64, ...; default: this
// machine). The Marketplace and `code --install-extension` then install the
// binary with the extension. Without --enbu, the VSIX runs enbu from enbu.path
// or PATH on any platform. Run `vp run build` first.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({
  options: {
    enbu: { type: "string" },
    target: { type: "string" },
    version: { type: "string" },
    out: { type: "string" },
  },
});

const fail = (message) => {
  console.error(message);
  process.exit(1);
};

for (const built of ["dist/extension.cjs", "media/web/index.html"]) {
  if (!existsSync(join(root, built))) fail(`${built} is missing. Run \`vp run build\` first.`);
}
if (values.target && !values.enbu) fail("--target needs --enbu: a target VSIX carries its binary.");

const target = values.enbu ? (values.target ?? `${process.platform}-${process.arch}`) : undefined;
// Release tags are v1.2.3; the VSIX version is plain semver.
const version = values.version?.replace(/^v/, "");

// bin/ holds only this package's binary, so a target VSIX never carries another's.
rmSync(join(root, "bin"), { recursive: true, force: true });
if (target) {
  const name = target.startsWith("win32-") ? "enbu.exe" : "enbu";
  const dir = join(root, "bin", target);
  mkdirSync(dir, { recursive: true });
  copyFileSync(resolve(values.enbu), join(dir, name));
  chmodSync(join(dir, name), 0o755);
}
copyFileSync(join(root, "..", "LICENSE"), join(root, "LICENSE"));

const args = ["package", "--no-dependencies"];
if (target) args.push("--target", target);
if (version) args.push(version, "--no-update-package-json", "--no-git-tag-version");
if (values.out) args.push("--out", resolve(values.out));
const vsce = join(root, "node_modules", "@vscode", "vsce", "vsce");
execFileSync(process.execPath, [vsce, ...args], { cwd: root, stdio: "inherit" });
