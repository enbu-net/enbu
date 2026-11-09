import { describe, expect, it } from "vite-plus/test";
import { refusalReason } from "./refusal";

describe("refusalReason", () => {
  it("allows local and WSL windows", () => {
    expect(refusalReason(undefined, true)).toBeUndefined();
    expect(refusalReason("wsl", true)).toBeUndefined();
  });

  it("refuses other remotes, where the extension host is another machine", () => {
    for (const remote of ["ssh-remote", "dev-container", "codespaces", "tunnel"]) {
      expect(refusalReason(remote, true)).toMatch(/local folders and WSL only/);
    }
  });

  it("refuses an untrusted workspace", () => {
    expect(refusalReason("wsl", false)).toBe("enbu needs a trusted workspace.");
  });
});
