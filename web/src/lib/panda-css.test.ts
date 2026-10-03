// @vitest-environment node
import { createNodeDriver } from "@pandacss/dev/node";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";

describe("Panda CSS configuration", () => {
  it("compiles base utilities and Park UI recipes with WebKit-compatible variable defaults", async () => {
    const driver = await createNodeDriver({
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
    });
    driver.parseFiles();
    const { css, diagnostics } = driver.cssgen();

    expect(diagnostics).toEqual([]);
    expect(css).toContain(".alert__root");
    expect(css).toContain(".tabs__trigger");
    expect(css).toMatch(/\.d_flex\s*\{\s*display:\s*flex/);
    // Older WebKit ignores @property, so transforms also need plain defaults.
    expect(css).toMatch(
      /\*,\s*::before,\s*::after,\s*::backdrop\s*\{\s*--translate-x:\s*0;\s*--translate-y:\s*0;/,
    );
    expect(css).toMatch(
      /@media\s*\(hover:\s*hover\)\s*and\s*\(pointer:\s*fine\)\s*\{\s*\.button[^{}]*:is\(:hover,\s*\[data-hover\]\)/,
    );
  }, 30_000);
});
