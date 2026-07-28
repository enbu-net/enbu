import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDirectory, "..");
const sourceRoot = path.join(webRoot, "src");

export function inspectSource(fileName, source) {
  const violations = [];

  const report = (index, message) => {
    const line = source.slice(0, index).split("\n").length;
    violations.push(`${fileName}:${line}: ${message}`);
  };

  const catchNames = new Set(
    [...source.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g)].map((match) => match[1]),
  );
  for (const name of catchNames) {
    const escaped = name.replaceAll("$", "\\$");
    const patterns = [
      [
        new RegExp(`\\b${escaped}\\s*\\.\\s*message\\b`, "g"),
        "user-visible errors must pass through toDisplayError",
      ],
      [
        new RegExp(`\\bString\\s*\\(\\s*${escaped}\\s*\\)`, "g"),
        "user-visible errors must not stringify caught values",
      ],
      [
        new RegExp(`\\$\\{\\s*${escaped}\\s*\\}`, "g"),
        "user-visible errors must not interpolate caught values",
      ],
    ];
    for (const [pattern, message] of patterns) {
      for (const match of source.matchAll(pattern)) report(match.index, message);
    }
  }

  if (fileName !== "src/lib/backend.ts") {
    for (const match of source.matchAll(/\bwindow\s*\.\s*go\b/g)) {
      report(match.index, "Wails bindings may only be accessed through src/lib/backend.ts");
    }
  }

  for (const match of source.matchAll(/<ErrorAlert\b[^>]*\bmessage\s*=/gs)) {
    report(match.index, "ErrorAlert accepts typed DisplayError through the error prop");
  }

  for (const match of source.matchAll(
    /\b([A-Za-z_$][\w$]*)\s+instanceof\s+Error\s*\?\s*\1\s*\.\s*message\s*:\s*String\s*\(\s*\1\s*\)/g,
  )) {
    report(match.index, "raw Error messages must not cross a user-visible boundary");
  }

  return violations;
}

function sourceFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "wailsjs") return [];
      return sourceFiles(fullPath);
    }
    if (
      !entry.name.match(/\.tsx?$/) ||
      entry.name.match(/\.test\.tsx?$/) ||
      entry.name.endsWith(".d.ts")
    ) {
      return [];
    }
    return [fullPath];
  });
}

export function run() {
  const violations = sourceFiles(sourceRoot).flatMap((fileName) => {
    const relative = path.relative(webRoot, fileName).replaceAll(path.sep, "/");
    return inspectSource(relative, fs.readFileSync(fileName, "utf8"));
  });
  for (const violation of violations) console.error(violation);
  return violations.length === 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href && !run()) {
  process.exitCode = 1;
}
