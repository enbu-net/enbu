// @vitest-environment node
import { createNodeDriver } from "@pandacss/dev/node";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";
import config from "../../panda.config";

type TokenTree = { value?: unknown; [key: string]: unknown };

// Every leaf token of a semantic token group, by its dotted name.
function leaves(tree: TokenTree, prefix = ""): [string, unknown][] {
  if ("value" in tree) return [[prefix, tree.value]];
  return Object.entries(tree).flatMap(([key, child]) =>
    leaves(child as TokenTree, prefix ? `${prefix}.${key}` : key),
  );
}

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
      /\*,\s*::before,\s*::after,\s*::backdrop\s*\{[^}]*--translate-x:\s*0;\s*--translate-y:\s*0;/,
    );
    expect(css).toMatch(
      /@media\s*\(hover:\s*hover\)\s*and\s*\(pointer:\s*fine\)\s*\{\s*\.button[^{}]*:is\(:hover,\s*\[data-hover\]\)/,
    );
  }, 30_000);
});

describe("theme tokens", () => {
  it("give every app color and shadow a light and a dark value", () => {
    const semantic = config.theme?.extend?.semanticTokens as Record<string, TokenTree>;
    const tokens = [...leaves(semantic.colors), ...leaves(semantic.shadows)].filter(
      // The enbu.toml editor is dark in both themes.
      ([name]) => !name.startsWith("editor."),
    );

    expect(tokens.length).toBeGreaterThan(0);
    for (const [name, value] of tokens) {
      expect(value, name).toEqual({ _light: expect.any(String), _dark: expect.any(String) });
    }
  });

  it("switch to the dark values under the .dark class that src/lib/theme.ts sets", async () => {
    const driver = await createNodeDriver({
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
    });
    driver.parseFiles();
    const { css } = driver.cssgen();

    expect(css).toMatch(/\.dark\s*\{[^}]*--colors-bg-page:\s*#111113/);
    expect(css).toMatch(/:where\(:root,\s*\.light\)\s*\{[^}]*--colors-bg-page:\s*#f8f9fa/);
  }, 30_000);
});
