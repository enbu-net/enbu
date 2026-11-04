import { describe, expect, it } from "vite-plus/test";
import { packagePlan } from "./plan.mjs";

const host = { platform: "linux", arch: "x64" };

describe("packagePlan", () => {
  it("packages for this machine by default", () => {
    expect(packagePlan({ enbu: "enbu" }, host)).toEqual({
      target: "linux-x64",
      binaryName: "enbu",
      version: undefined,
    });
  });

  it("names the Windows binary enbu.exe", () => {
    expect(packagePlan({ enbu: "enbu.exe", target: "win32-arm64" }, host)).toMatchObject({
      target: "win32-arm64",
      binaryName: "enbu.exe",
    });
  });

  it("turns a release tag into the VSIX version", () => {
    expect(packagePlan({ enbu: "enbu", version: "v1.2.3" }, host).version).toBe("1.2.3");
    expect(packagePlan({ enbu: "enbu", version: "1.2.3-rc.1" }, host).version).toBe("1.2.3-rc.1");
  });

  it("requires a binary", () => {
    expect(() => packagePlan({ target: "linux-x64" }, host)).toThrow("--enbu is required");
  });
});
