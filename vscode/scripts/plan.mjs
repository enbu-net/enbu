// What scripts/package.mjs packages, apart from any file system work.

/**
 * @param {{ enbu?: string; target?: string; version?: string }} options
 * @param {{ platform: string; arch: string }} host
 * @returns {{ target: string; binaryName: string; version: string | undefined }}
 */
export function packagePlan(options, host) {
  if (!options.enbu) throw new Error("--enbu is required: every VSIX carries its enbu binary.");
  const target = options.target ?? `${host.platform}-${host.arch}`;
  return {
    target,
    binaryName: target.startsWith("win32-") ? "enbu.exe" : "enbu",
    // Release tags are v1.2.3; the VSIX version is plain semver.
    version: options.version?.replace(/^v/, ""),
  };
}
