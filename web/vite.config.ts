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

export default defineConfig(({ mode }) => ({
  base: mode === "preview" ? (process.env.PREVIEW_BASE ?? "/enbu/web/") : undefined,
  build: {
    outDir: mode === "preview" ? "dist-preview" : "dist",
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        tui: resolve(__dirname, "tui.html"),
      },
    },
  },
  fmt: {
    ignorePatterns: [
      "dist/**",
      "dist-preview/**",
      "index.html",
      "panda.config.ts",
      "postcss.config.cjs",
      "src/components/**",
      "src/routeTree.gen.ts",
      "src/wailsjs/**",
      "styled-system/**",
      "tsconfig*.json",
    ],
  },
  lint: {
    ignorePatterns: [
      "dist/**",
      "dist-preview/**",
      "src/routeTree.gen.ts",
      "src/wailsjs/**",
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
        },
      },
      {
        files: ["scripts/**/*.mjs"],
        rules: {
          "typescript/no-unsafe-assignment": "off",
        },
      },
      {
        files: ["src/lib/backend.test.ts", "src/lib/backend.ts"],
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
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:3939",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
  },
}));
