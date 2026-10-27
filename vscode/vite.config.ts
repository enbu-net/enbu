import { defineConfig } from "vite-plus";

export default defineConfig({
  // The extension host loads one CommonJS file; vscode is provided at runtime.
  pack: {
    entry: ["src/extension.ts"],
    format: ["cjs"],
    platform: "node",
    target: "node20",
    outDir: "dist",
    deps: { neverBundle: ["vscode"] },
    sourcemap: true,
  },
  fmt: {
    ignorePatterns: ["dist/**", "media/**", "tsconfig.json"],
  },
  lint: {
    ignorePatterns: ["dist/**", "media/**"],
    options: {
      typeAware: true,
      typeCheck: true,
    },
    plugins: ["typescript", "oxc"],
    rules: {
      "typescript/no-floating-promises": "error",
      "typescript/no-unsafe-assignment": "warn",
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        files: ["**/*.test.ts"],
        rules: {
          "typescript/no-unsafe-assignment": "off",
          "typescript/unbound-method": "off",
        },
      },
      {
        files: ["scripts/**/*.mjs"],
        rules: {
          "typescript/no-unsafe-assignment": "off",
        },
      },
    ],
    jsPlugins: [
      {
        name: "vite-plus",
        specifier: "vite-plus/oxlint-plugin",
      },
    ],
  },
  test: {
    environment: "node",
  },
});
