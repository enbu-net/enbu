import { defineConfig } from "@pandacss/dev";
import { createPreset } from "@park-ui/panda-preset";
import blue from "@park-ui/panda-preset/colors/blue";
import slate from "@park-ui/panda-preset/colors/slate";
import { fixFieldsetSiblingSelector } from "./panda-preset";

const basePreset = createPreset({ accentColor: blue, grayColor: slate, radius: "sm" });

const parkPreset = fixFieldsetSiblingSelector(basePreset);

export default defineConfig({
  preflight: true,
  jsxFramework: "react",
  include: ["./src/**/*.{ts,tsx}"],
  exclude: [],
  outdir: "styled-system",
  // Wails can run on WebKit versions that do not support CSS @property yet.
  optimize: { propertyFallback: true },

  presets: [
    "@pandacss/preset-base",
    {
      ...parkPreset,
      // Park UI 0.43 uses an array condition, which Panda 2 no longer supports.
      conditions: {
        ...parkPreset.conditions,
        extend: {
          ...parkPreset.conditions?.extend,
          hover: {
            "@media (hover: hover) and (pointer: fine)": {
              "&:is(:hover, [data-hover])": "@slot",
            },
          },
        },
      },
    },
  ],

  theme: {
    extend: {
      tokens: {
        fonts: {
          body: {
            value:
              '"BIZ UDGothic", Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          },
          heading: {
            value:
              '"BIZ UDGothic", Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          },
          mono: {
            value: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
          },
        },
        colors: {
          brand: {
            50: { value: "#eef4ff" },
            100: { value: "#dbe4ff" },
            200: { value: "#bfcfff" },
            300: { value: "#93acff" },
            400: { value: "#607dff" },
            500: { value: "#2563eb" },
            600: { value: "#1d53cc" },
            700: { value: "#1640a0" },
            800: { value: "#113177" },
            900: { value: "#0c2454" },
          },
          enbu: {
            editorBg: { value: "#1b1b22" },
            editorSurface: { value: "#22222a" },
            editorBorder: { value: "#303039" },
            editorFg: { value: "#d6d6de" },
            editorMuted: { value: "#a8a8b2" },
            editorAccent: { value: "#9f98ed" },
          },
        },
        radii: {
          sm: { value: "4px" },
          md: { value: "6px" },
          lg: { value: "8px" },
          full: { value: "9999px" },
        },
        fontSizes: {
          "2xs": { value: "11px" },
          xs: { value: "12px" },
          sm: { value: "13px" },
          md: { value: "14px" },
          lg: { value: "15px" },
          xl: { value: "16px" },
          "2xl": { value: "20px" },
          "3xl": { value: "28px" },
          "4xl": { value: "34px" },
        },
        fontWeights: {
          normal: { value: "400" },
          medium: { value: "500" },
          semibold: { value: "650" },
          bold: { value: "700" },
          extrabold: { value: "750" },
        },
        sizes: {
          "control-sm": { value: "30px" },
          control: { value: "38px" },
        },
        spacing: {
          "4.5": { value: "18px" },
        },
      },
      // Every color a component uses is a semantic token with a light (_light) and
      // a dark (_dark) value; src/lib/theme.ts switches between them with the
      // `.dark` class on <html>. Do not use raw colors in components.
      semanticTokens: {
        shadows: {
          app: { value: { _light: "0 24px 80px rgba(15, 23, 42, 0.12)", _dark: "0 24px 80px rgba(0, 0, 0, 0.5)" } },
          dropdown: { value: { _light: "0 16px 40px rgba(31, 35, 40, 0.16)", _dark: "0 16px 40px rgba(0, 0, 0, 0.56)" } },
        },
        colors: {
          bg: {
            // The page behind every surface; Park UI's bg.canvas stays the recipes' own.
            page: { value: { _light: "#f8f9fa", _dark: "#111113" } },
            default: { value: { _light: "#ffffff", _dark: "#18191b" } },
            surface: { value: { _light: "#ffffff", _dark: "#18191b" } },
            muted: { value: { _light: "#f8f9fa", _dark: "#212225" } },
            // Behind dialogs.
            backdrop: { value: { _light: "rgba(15, 23, 42, 0.48)", _dark: "rgba(0, 0, 0, 0.64)" } },
          },
          fg: {
            default: { value: { _light: "#1f2328", _dark: "#edeef0" } },
            muted: { value: { _light: "#667085", _dark: "#9ba1a6" } },
            subtle: { value: { _light: "#475467", _dark: "#b0b4ba" } },
          },
          border: {
            default: { value: { _light: "#d8dee4", _dark: "#363a3f" } },
            strong: { value: { _light: "#b8c0cc", _dark: "#5a6169" } },
          },
          accent: {
            default: { value: { _light: "{colors.brand.500}", _dark: "#3b82f6" } },
            fg: { value: { _light: "#ffffff", _dark: "#ffffff" } },
            subtle: { value: { _light: "{colors.brand.50}", _dark: "#172448" } },
            border: { value: { _light: "{colors.brand.100}", _dark: "#203a72" } },
            emphasized: { value: { _light: "{colors.brand.600}", _dark: "#5b96f7" } },
          },
          status: {
            success: { value: { _light: "#16835d", _dark: "#3dd68c" } },
            successMuted: { value: { _light: "#eaf7f1", _dark: "#0f2a1f" } },
            successBorder: { value: { _light: "#b9e4d1", _dark: "#1f5a40" } },
            danger: { value: { _light: "#e5484d", _dark: "#e5484d" } },
            dangerMuted: { value: { _light: "#fff1f2", _dark: "#3b1219" } },
            // Text on a status.danger background.
            dangerFg: { value: { _light: "#ffffff", _dark: "#ffffff" } },
          },
          // The enbu.toml editor stays dark in both themes, like Monaco's vs-dark.
          editor: {
            bg: { value: "{colors.enbu.editorBg}" },
            surface: { value: "{colors.enbu.editorSurface}" },
            border: { value: "{colors.enbu.editorBorder}" },
            fg: { value: "{colors.enbu.editorFg}" },
            muted: { value: "{colors.enbu.editorMuted}" },
            accent: { value: "{colors.enbu.editorAccent}" },
          },
        },
      },
    },
  },
});
