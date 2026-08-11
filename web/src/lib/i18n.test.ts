import { beforeEach, describe, expect, it } from "vite-plus/test";
import { detectLocale, translate } from "./i18n";

const storage = new Map<string, string>();

beforeEach(() => {
  storage.clear();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      clear: () => storage.clear(),
    },
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { language: "en-US" },
  });
});

describe("i18n", () => {
  it("uses saved locale first", () => {
    localStorage.setItem("enbu_locale", "ja");
    expect(detectLocale()).toBe("ja");
  });

  it("falls back to English for unsupported locale", () => {
    localStorage.setItem("enbu_locale", "fr");
    expect(detectLocale()).toBe("en");
  });

  it("translates with interpolation", () => {
    expect(translate("en", "workspace.current", { workspace: "alpha" })).toBe("Workspace alpha");
    expect(translate("ja", "workspace.title")).toBe("暗号化リソース");
  });

  it("has ARIA label keys", () => {
    expect(translate("en", "app.language")).toBe("Language");
    expect(translate("ja", "app.language")).toBe("言語");
  });
});
