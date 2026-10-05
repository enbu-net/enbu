import type { Preset } from "@pandacss/dev";

type StyleObject = Record<string, unknown>;

// Park UI 0.43 writes the fieldset legend sibling selector as `"+ *"`, which Panda 2.1
// treats as a CSS property (nested_property warning) so the style never applies.
// Rewrite it to the explicit `"& + *"` selector. Once Park UI uses `"& + *"` itself
// (or drops the recipe) the preset is returned unchanged.
export function fixFieldsetSiblingSelector<T extends Preset>(preset: T): T {
  const fieldset = preset.theme?.extend?.slotRecipes?.fieldset;
  const legend = fieldset?.base?.legend as StyleObject | undefined;
  if (!fieldset || !legend || !("+ *" in legend)) return preset;

  const { "+ *": sibling, ...rest } = legend;
  return {
    ...preset,
    theme: {
      ...preset.theme,
      extend: {
        ...preset.theme?.extend,
        slotRecipes: {
          ...preset.theme?.extend?.slotRecipes,
          fieldset: {
            ...fieldset,
            base: { ...fieldset.base, legend: { ...rest, "& + *": sibling } },
          },
        },
      },
    },
  };
}
