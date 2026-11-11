import { defineConfig, lazyPlugins } from "vite-plus";
import { resolve } from "path";

const loadPlugins = async () => {
  const [{ TanStackRouterVite }, { default: react }, { paraglideVitePlugin }] = await Promise.all([
    import("@tanstack/router-plugin/vite"),
    import("@vitejs/plugin-react"),
    import("@inlang/paraglide-js"),
  ]);

  return [
    TanStackRouterVite(),
    react(),
    // Keep these options in step with the compile in package.json's prepare script.
    paraglideVitePlugin({
      project: "./project.inlang",
      outdir: "./src/paraglide",
      strategy: ["localStorage", "preferredLanguage", "baseLocale"],
      emitTsDeclarations: true,
    }),
  ];
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
      "src/paraglide/**",
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
      "src/paraglide/**",
      "styled-system/**",
    ],
    options: {
      typeAware: true,
      typeCheck: true,
    },
    plugins: ["react", "typescript", "oxc", "jsx-a11y"],
    rules: {
      "enbu/no-direct-wails-binding": "error",
      "enbu/no-error-alert-message": "error",
      "enbu/no-raw-error-display": "error",
      "jsx-a11y/alt-text": "error",
      "jsx-a11y/anchor-ambiguous-text": "error",
      "jsx-a11y/anchor-has-content": "error",
      "jsx-a11y/anchor-is-valid": "error",
      "jsx-a11y/aria-activedescendant-has-tabindex": "error",
      "jsx-a11y/aria-props": "error",
      "jsx-a11y/aria-proptypes": "error",
      "jsx-a11y/aria-role": "error",
      "jsx-a11y/aria-unsupported-elements": "error",
      "jsx-a11y/autocomplete-valid": "error",
      "jsx-a11y/click-events-have-key-events": "error",
      "jsx-a11y/control-has-associated-label": "error",
      "jsx-a11y/heading-has-content": "error",
      "jsx-a11y/html-has-lang": "error",
      "jsx-a11y/iframe-has-title": "error",
      "jsx-a11y/img-redundant-alt": "error",
      "jsx-a11y/interactive-supports-focus": "error",
      "jsx-a11y/label-has-associated-control": "error",
      "jsx-a11y/lang": "error",
      "jsx-a11y/media-has-caption": "error",
      "jsx-a11y/mouse-events-have-key-events": "error",
      "jsx-a11y/no-access-key": "error",
      "jsx-a11y/no-aria-hidden-on-focusable": "error",
      "jsx-a11y/no-autofocus": "error",
      "jsx-a11y/no-distracting-elements": "error",
      "jsx-a11y/no-interactive-element-to-noninteractive-role": "error",
      "jsx-a11y/no-noninteractive-element-interactions": "error",
      "jsx-a11y/no-noninteractive-element-to-interactive-role": "error",
      "jsx-a11y/no-noninteractive-tabindex": "error",
      "jsx-a11y/no-redundant-roles": "error",
      "jsx-a11y/no-static-element-interactions": "error",
      "jsx-a11y/prefer-tag-over-role": "off",
      "jsx-a11y/role-has-required-aria-props": "error",
      "jsx-a11y/role-supports-aria-props": "error",
      "jsx-a11y/scope": "error",
      "jsx-a11y/tabindex-no-positive": "error",
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
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/routeTree.gen.ts",
        "src/bindings/**",
        "src/paraglide/**",
        "src/test/**",
      ],
      reportOnFailure: true,
    },
  },
}));
