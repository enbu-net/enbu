import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { applyTheme, resolveTheme, setThemePreference, startTheme, systemTheme } from "./theme";
import { loadSettings, settingsStorageKey } from "./settings";

function saveTheme(theme: string) {
  localStorage.setItem(settingsStorageKey, JSON.stringify({ theme }));
  loadSettings();
}

function savedTheme() {
  return JSON.parse(localStorage.getItem(settingsStorageKey) ?? "{}").theme;
}

// jsdom has no matchMedia; this one answers prefers-color-scheme and lets a test flip it.
function stubMatchMedia(dark: boolean) {
  const listeners = new Set<() => void>();
  const media = {
    get matches() {
      return dark;
    },
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
  };
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => media),
  );
  return {
    set(next: boolean) {
      dark = next;
      for (const listener of listeners) listener();
    },
    listeners,
  };
}

const root = document.documentElement;
let stop = () => {};

beforeEach(() => {
  localStorage.clear();
  loadSettings();
  root.className = "";
  root.style.colorScheme = "";
  document.body.removeAttribute("data-vscode-theme-kind");
});

afterEach(() => {
  stop();
  stop = () => {};
  vi.unstubAllGlobals();
});

describe("theme preference", () => {
  it("resolves system to the host's theme and keeps an explicit choice", () => {
    expect(resolveTheme("system", "dark")).toBe("dark");
    expect(resolveTheme("light", "dark")).toBe("light");
    expect(resolveTheme("dark", "light")).toBe("dark");
  });
});

describe("applyTheme", () => {
  it("sets the dark class and color-scheme on <html>", () => {
    applyTheme("dark");
    expect(root.classList.contains("dark")).toBe(true);
    expect(root.style.colorScheme).toBe("dark");
    applyTheme("light");
    expect(root.classList.contains("dark")).toBe(false);
    expect(root.style.colorScheme).toBe("light");
  });
});

describe("systemTheme", () => {
  it("follows prefers-color-scheme in the desktop app", () => {
    stubMatchMedia(true);
    expect(systemTheme("desktop")).toBe("dark");
  });

  it("follows the editor's theme kind in VS Code, not the OS", () => {
    stubMatchMedia(true);
    for (const [kind, theme] of [
      ["vscode-light", "light"],
      ["vscode-high-contrast-light", "light"],
      ["vscode-dark", "dark"],
      ["vscode-high-contrast", "dark"],
    ] as const) {
      document.body.setAttribute("data-vscode-theme-kind", kind);
      expect(systemTheme("vscode")).toBe(theme);
    }
  });

  it("falls back to prefers-color-scheme when VS Code has not set a theme kind", () => {
    stubMatchMedia(false);
    expect(systemTheme("vscode")).toBe("light");
  });
});

describe("startTheme", () => {
  it("shows the saved preference before anything renders", () => {
    stubMatchMedia(false);
    saveTheme("dark");
    stop = startTheme("desktop");
    expect(root.classList.contains("dark")).toBe(true);
  });

  it("follows the OS while the preference is system, and stops once a theme is picked", () => {
    const media = stubMatchMedia(false);
    stop = startTheme("desktop");
    expect(root.classList.contains("dark")).toBe(false);

    media.set(true);
    expect(root.classList.contains("dark")).toBe(true);

    setThemePreference("light");
    expect(savedTheme()).toBe("light");
    media.set(true);
    expect(root.classList.contains("dark")).toBe(false);

    setThemePreference("system");
    expect(savedTheme()).toBe("system");
    expect(root.classList.contains("dark")).toBe(true);
  });

  it("follows VS Code when the editor's theme changes", async () => {
    stubMatchMedia(false);
    document.body.setAttribute("data-vscode-theme-kind", "vscode-light");
    stop = startTheme("vscode");
    expect(root.classList.contains("dark")).toBe(false);

    document.body.setAttribute("data-vscode-theme-kind", "vscode-dark");
    await Promise.resolve(); // MutationObserver callbacks run as microtasks.
    expect(root.classList.contains("dark")).toBe(true);
  });

  it("stops following the host once stopped", () => {
    const media = stubMatchMedia(false);
    stop = startTheme("desktop");
    stop();
    expect(media.listeners.size).toBe(0);
  });
});
