import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import {
  applyFontSize,
  defaultSettings,
  getSettings,
  loadSettings,
  parseSettings,
  readSettings,
  settingsStorageKey,
  SettingsError,
  startTextSize,
  updateSettings,
} from "./settings";

beforeEach(() => {
  localStorage.clear();
  loadSettings();
  document.documentElement.style.removeProperty("--enbu-text-scale");
});

describe("parseSettings", () => {
  it("fills missing keys with defaults", () => {
    expect(parseSettings({ fontSize: 16 })).toEqual({ ...defaultSettings, fontSize: 16 });
  });

  it("refuses unknown keys, bad values and non-objects", () => {
    expect(() => parseSettings({ fontsize: 16 })).toThrow(SettingsError);
    expect(() => parseSettings({ theme: "sepia" })).toThrow(SettingsError);
    expect(() => parseSettings({ fontSize: 9 })).toThrow(SettingsError);
    expect(() => parseSettings({ fontSize: 14.5 })).toThrow(SettingsError);
    expect(() => parseSettings({ clipboardClearSeconds: -1 })).toThrow(SettingsError);
    expect(() => parseSettings([])).toThrow(SettingsError);
    expect(() => parseSettings(null)).toThrow(SettingsError);
  });

  it("accepts the extra keys the caller allows", () => {
    expect(parseSettings({ language: "ja" }, ["language"])).toEqual(defaultSettings);
  });
});

describe("readSettings", () => {
  it("keeps the valid saved values and drops the rest", () => {
    localStorage.setItem(
      settingsStorageKey,
      JSON.stringify({ theme: "dark", fontSize: 99, clipboardClearSeconds: 0 }),
    );
    expect(readSettings()).toEqual({ theme: "dark", fontSize: 14, clipboardClearSeconds: 0 });
  });

  it("falls back to the defaults on broken JSON or refused storage", () => {
    localStorage.setItem(settingsStorageKey, "{");
    expect(readSettings()).toEqual(defaultSettings);
    const getItem = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    expect(readSettings()).toEqual(defaultSettings);
    getItem.mockRestore();
  });
});

describe("updateSettings", () => {
  it("saves the whole object and refuses an invalid change", () => {
    updateSettings({ fontSize: 18 });
    expect(getSettings().fontSize).toBe(18);
    expect(JSON.parse(localStorage.getItem(settingsStorageKey) ?? "")).toEqual({
      ...defaultSettings,
      fontSize: 18,
    });
    expect(() => updateSettings({ fontSize: 30 })).toThrow(SettingsError);
    expect(getSettings().fontSize).toBe(18);
  });
});

describe("text size", () => {
  it("scales the text tokens from the default size and follows changes", () => {
    applyFontSize(21);
    expect(document.documentElement.style.getPropertyValue("--enbu-text-scale")).toBe("1.5");

    const stop = startTextSize();
    expect(document.documentElement.style.getPropertyValue("--enbu-text-scale")).toBe("1");
    updateSettings({ fontSize: 24 });
    expect(document.documentElement.style.getPropertyValue("--enbu-text-scale")).toBe(
      String(24 / 14),
    );
    stop();
  });
});
