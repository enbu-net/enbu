// @vitest-environment node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vite-plus/test";
import config from "../panda.config";

const html = readFileSync(fileURLToPath(new URL("../index.html", import.meta.url)), "utf8");

// Parts of Modern Web Guidance that legacy-scan and the lint rules do not reach.
describe("index.html", () => {
  it("declares both color schemes before the first paint (dark-mode)", () => {
    expect(html).toMatch(/<meta name="color-scheme" content="light dark"/);
  });

  it("opts into the OS text scale (respect-os-text-scale)", () => {
    expect(html).toMatch(/<meta name="text-scale" content="scale"/);
  });

  it("loads nothing from another origin, so the app works offline and tells no one it runs (privacy)", () => {
    expect(html).not.toMatch(/\b(?:href|src)="(?:https?:)?\/\//);
  });
});

describe("text sizes", () => {
  it("are rem, so they follow the user's root font size (typography)", () => {
    const sizes = Object.values(config.theme?.extend?.tokens?.fontSizes ?? {}) as {
      value: string;
    }[];
    expect(sizes.length).toBeGreaterThan(0);
    for (const { value } of sizes) {
      expect(value).toMatch(/rem/);
      expect(value).not.toMatch(/\dpx/);
    }
  });
});
