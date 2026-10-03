// @vitest-environment node
import { createNodeDriver } from "@pandacss/dev/node";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";

describe("Panda CSS configuration", () => {
  it("compiles Park UI recipes and preserves pointer-gated hover styles", async () => {
    const driver = await createNodeDriver({
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
    });
    driver.parseFiles();
    const { css, diagnostics } = driver.cssgen();

    expect(diagnostics.filter((item) => item.severity === "error")).toEqual([]);
    expect(css).toContain(".alert__root");
    expect(css).toContain(".tabs__trigger");
    expect(css).toMatch(
      /@media\s*\(hover:\s*hover\)\s*and\s*\(pointer:\s*fine\)\s*\{\s*\.button[^{}]*:is\(:hover,\s*\[data-hover\]\)/,
    );
  });
});
