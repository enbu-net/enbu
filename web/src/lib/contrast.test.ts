// @vitest-environment node
import { describe, expect, it } from "vite-plus/test";
import config from "../../panda.config";

// WCAG 2.2 contrast minimums: 1.4.3 for text, 1.4.11 for the parts of controls
// and the indicators people need to see.
const TEXT = 4.5;
const UI = 3;

type Tree = { [key: string]: unknown };
type Theme = "_light" | "_dark";

const tokens = config.theme?.extend?.tokens?.colors as Tree;
const semantic = config.theme?.extend?.semanticTokens?.colors as Tree;

function lookup(tree: Tree, path: string): unknown {
  let node: unknown = tree;
  for (const part of path.split(".")) node = (node as Tree | undefined)?.[part];
  return (node as { value?: unknown } | undefined)?.value;
}

/** The hex color a semantic or base color token has in a theme. */
function color(name: string, theme: Theme): string {
  let value = lookup(semantic, name) ?? lookup(tokens, name);
  if (value && typeof value === "object") value = (value as Record<Theme, unknown>)[theme];
  if (typeof value !== "string") throw new Error(`no color token ${name}`);
  const reference = /^\{colors\.(.+)\}$/.exec(value);
  if (reference) return color(reference[1], theme);
  if (!/^#[0-9a-f]{6}$/i.test(value))
    throw new Error(`${name} is not an opaque hex color: ${value}`);
  return value;
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [dark, light] = [luminance(a), luminance(b)].sort((x, y) => x - y);
  return (light + 0.05) / (dark + 0.05);
}

const surfaces = ["bg.page", "bg.default", "bg.surface", "bg.muted"];

// Each foreground token, the backgrounds it is drawn on, and the minimum ratio.
// Add a pair here when a component puts a token on a new background.
const pairs: [string, string[], number][] = [
  ["fg.default", [...surfaces, "accent.subtle"], TEXT],
  ["fg.muted", [...surfaces, "accent.subtle"], TEXT],
  ["fg.subtle", surfaces, TEXT],
  ["accent.fg", ["accent.default", "accent.emphasized"], TEXT],
  ["accent.text", [...surfaces, "accent.subtle"], TEXT],
  ["accent.default", surfaces, UI],
  ["border.strong", surfaces, UI],
  ["status.success", [...surfaces, "status.successMuted"], TEXT],
  ["status.danger", [...surfaces, "status.dangerMuted"], TEXT],
  ["status.dangerFg", ["status.dangerSolid"], TEXT],
  ["editor.fg", ["editor.bg", "editor.surface"], TEXT],
  ["editor.muted", ["editor.bg", "editor.surface"], TEXT],
  ["editor.accent", ["editor.bg", "editor.surface"], TEXT],
  ["editor.danger", ["editor.bg", "editor.surface"], TEXT],
];

describe("color tokens meet WCAG 2.2 AA contrast", () => {
  for (const theme of ["_light", "_dark"] as const) {
    for (const [fg, backgrounds, minimum] of pairs) {
      for (const bg of backgrounds) {
        it(`${fg} on ${bg} (${theme.slice(1)})`, () => {
          const ratio = contrast(color(fg, theme), color(bg, theme));
          expect(ratio, `${color(fg, theme)} on ${color(bg, theme)}`).toBeGreaterThanOrEqual(
            minimum,
          );
        });
      }
    }
  }

  it("computes the WCAG ratio", () => {
    expect(contrast("#000000", "#ffffff")).toBeCloseTo(21);
    expect(contrast("#767676", "#ffffff")).toBeCloseTo(4.54, 2);
  });
});
