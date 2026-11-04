import { describe, expect, it } from "vite-plus/test";
import { resolveWorkspaceEnvironment } from "./use-workspace";

describe("resolveWorkspaceEnvironment", () => {
  it("keeps the requested environment when it exists", () => {
    expect(
      resolveWorkspaceEnvironment("production", [
        { name: "staging", current: true },
        { name: "production", current: false },
      ]),
    ).toBe("production");
  });

  it("falls back to the new repository's current environment", () => {
    expect(
      resolveWorkspaceEnvironment("dev", [
        { name: "staging", current: true },
        { name: "production", current: false },
      ]),
    ).toBe("staging");
  });

  it("falls back to the first environment, or none", () => {
    expect(resolveWorkspaceEnvironment("", [{ name: "a", current: false }])).toBe("a");
    expect(resolveWorkspaceEnvironment("dev", [])).toBe("");
  });
});
