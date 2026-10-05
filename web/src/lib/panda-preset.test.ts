// @vitest-environment node
import type { Preset } from "@pandacss/dev";
import { createPreset } from "@park-ui/panda-preset";
import blue from "@park-ui/panda-preset/colors/blue";
import slate from "@park-ui/panda-preset/colors/slate";
import { describe, expect, it } from "vite-plus/test";
import { fixFieldsetSiblingSelector } from "../../panda-preset";

const presetWith = (legend: Record<string, unknown>): Preset => ({
  name: "test",
  theme: {
    extend: {
      slotRecipes: {
        fieldset: { className: "fieldset", slots: ["legend"], base: { legend } as never },
        field: { className: "field", slots: ["root"], base: { root: { display: "flex" } } },
      },
    },
  },
});

const legendOf = (preset: Preset) => preset.theme?.extend?.slotRecipes?.fieldset?.base?.legend;

describe("fixFieldsetSiblingSelector", () => {
  it("rewrites the bare sibling selector and keeps the other styles", () => {
    const fixed = fixFieldsetSiblingSelector(
      presetWith({ float: "left", "+ *": { clear: "both" } }),
    );

    expect(legendOf(fixed)).toEqual({ float: "left", "& + *": { clear: "both" } });
    expect(fixed.theme?.extend?.slotRecipes?.field).toBeDefined();
  });

  it("leaves a preset that already uses the explicit selector untouched", () => {
    const preset = presetWith({ "& + *": { clear: "both" } });

    expect(fixFieldsetSiblingSelector(preset)).toBe(preset);
  });

  it("does not create a fieldset recipe when the preset has none", () => {
    const preset: Preset = { name: "test", theme: { extend: { slotRecipes: {} } } };

    const fixed = fixFieldsetSiblingSelector(preset);

    expect(fixed).toBe(preset);
    expect(fixed.theme?.extend?.slotRecipes).not.toHaveProperty("fieldset");
  });

  it("fixes the real Park UI preset", () => {
    const park = createPreset({ accentColor: blue, grayColor: slate, radius: "sm" });

    const legend = legendOf(fixFieldsetSiblingSelector(park)) as Record<string, unknown>;

    expect(legend).toHaveProperty("& + *", { clear: "both" });
    expect(legend).not.toHaveProperty("+ *");
  });
});
