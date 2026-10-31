import { defineConfig, lazyPlugins } from "vite-plus";
import { resolve } from "path";

const loadPlugins = async () => {
  const [{ TanStackRouterVite }, { default: react }] = await Promise.all([
    import("@tanstack/router-plugin/vite"),
    import("@vitejs/plugin-react"),
  ]);

  return [TanStackRouterVite(), react()];
};

// Vite 0.2.9's recursive PluginOption type exceeds TypeScript's comparison depth.
const lazyPluginFactory = loadPlugins as unknown as Parameters<typeof lazyPlugins>[0];

// The VS Code extension loads the UI from its own files through webview URIs,
// so that build uses relative asset paths.
const bases: Record<string, string> = {
  preview: process.env.PREVIEW_BASE ?? "/enbu/web/",
  vscode: "./",
};
const outDirs: Record<string, string> = { preview: "dist-preview", vscode: "dist-vscode" };

export default defineConfig(({ mode }) => ({
  base: bases[mode],
  build: {
    outDir: outDirs[mode] ?? "dist",
  },
  fmt: {
    ignorePatterns: [
      "dist/**",
      "dist-preview/**",
      "dist-vscode/**",
      "index.html",
      "panda.config.ts",
      "postcss.config.cjs",
      "src/components/**",
      "src/routeTree.gen.ts",
      "src/bindings/**",
      "styled-system/**",
      "tsconfig*.json",
    ],
  },
  lint: {
    ignorePatterns: [
      "dist/**",
      "dist-preview/**",
      "dist-vscode/**",
      "src/routeTree.gen.ts",
      "src/bindings/**",
      "styled-system/**",
    ],
    options: {
      typeAware: true,
      typeCheck: true,
    },
    plugins: ["react", "typescript", "oxc"],
    rules: {
      "enbu/no-direct-wails-binding": "error",
      "enbu/no-error-alert-message": "error",
      "enbu/no-raw-error-display": "error",
      "react/rules-of-hooks": "error",
      "react/only-export-components": "off",
      "typescript/no-floating-promises": "error",
      "typescript/no-unsafe-assignment": "warn",
      "vite-plus/prefer-vite-plus-imports": "error",
    },
    overrides: [
      {
        files: ["**/*.test.ts", "**/*.test.tsx"],
        rules: {
          "typescript/no-unsafe-assignment": "off",
          // expect(vi.mocked(backend).method) reads a mock, never calls it unbound.
          "typescript/unbound-method": "off",
        },
      },
      {
        files: ["scripts/**/*.mjs"],
        rules: {
          "typescript/no-unsafe-assignment": "off",
        },
      },
      {
        files: [
          "src/lib/backend.ts",
          "src/lib/platform.ts",
          "src/lib/types.ts",
          "src/lib/vscode.ts",
          "src/lib/*.test.ts",
        ],
        rules: {
          "enbu/no-direct-wails-binding": "off",
        },
      },
    ],
    jsPlugins: [
      {
        name: "enbu",
        specifier: "./scripts/oxlint-plugin-enbu.mjs",
      },
      {
        name: "vite-plus",
        specifier: "vite-plus/oxlint-plugin",
      },
    ],
  },
  plugins: lazyPlugins(lazyPluginFactory),
  resolve: {
    alias: {
      "styled-system": resolve(__dirname, "styled-system"),
      "~/components": resolve(__dirname, "src/components"),
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/teardown.ts"],
    coverage: {
      provider: "v8",
      reportsDirectory: "../.tmp/coverage/frontend",
      reporter: ["text", "html", "lcov", "json-summary"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/routeTree.gen.ts", "src/bindings/**", "src/test/**"],
      reportOnFailure: true,
    },
  },
}));
