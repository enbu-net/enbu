import { defineConfig } from "@pandacss/dev";
import { createPreset } from "@park-ui/panda-preset";
import blue from "@park-ui/panda-preset/colors/blue";
import slate from "@park-ui/panda-preset/colors/slate";

const parkPreset = createPreset({ accentColor: blue, grayColor: slate, radius: "sm" });

export default defineConfig({
  preflight: true,
  jsxFramework: "react",
  include: ["./src/**/*.{ts,tsx}"],
  exclude: [],
  outdir: "styled-system",

  presets: [
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
          canvas: { value: "#ffffff" },
          surface: { value: "#ffffff" },
          surfaceMuted: { value: "#f8f9fa" },
          enbu: {
            borderStrong: { value: "#b8c0cc" },
            statusSuccess: { value: "#16835d" },
            statusSuccessMuted: { value: "#eaf7f1" },
            statusSuccessBorder: { value: "#b9e4d1" },
            statusDanger: { value: "#e5484d" },
            statusDangerMuted: { value: "#fff1f2" },
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
        shadows: {
          app: { value: "0 24px 80px rgba(15, 23, 42, 0.12)" },
          dropdown: { value: "0 16px 40px rgba(31, 35, 40, 0.16)" },
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
      semanticTokens: {
        colors: {
          bg: {
            default: { value: "{colors.canvas}" },
            surface: { value: "{colors.surface}" },
            muted: { value: "{colors.surfaceMuted}" },
          },
          fg: {
            default: { value: "#1f2328" },
            muted: { value: "#667085" },
            subtle: { value: "#475467" },
          },
          border: {
            default: { value: "#d8dee4" },
            strong: { value: "{colors.enbu.borderStrong}" },
          },
          accent: {
            default: { value: "{colors.brand.500}" },
            fg: { value: "#fff" },
            subtle: { value: "{colors.brand.50}" },
            emphasized: { value: "{colors.brand.600}" },
          },
          status: {
            success: { value: "{colors.enbu.statusSuccess}" },
            successMuted: { value: "{colors.enbu.statusSuccessMuted}" },
            successBorder: { value: "{colors.enbu.statusSuccessBorder}" },
            danger: { value: "{colors.enbu.statusDanger}" },
            dangerMuted: { value: "{colors.enbu.statusDangerMuted}" },
          },
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
