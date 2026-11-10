import { useSyncExternalStore } from "react";
import { host as currentHost, type Host } from "./host";

/**
 * Light and dark themes.
 *
 * Colors live only in the semantic tokens of panda.config.ts, each with a
 * light value and a `_dark` value. A theme is a class on <html>: `.dark` turns
 * on the `_dark` values (Park UI's own condition), and no class means light.
 * Components never name a raw color, so a new theme is a new condition and a
 * new value on each token, not a change to components.
 *
 * The person picks a preference; "system" follows the host: the OS setting in
 * the desktop app and the browser preview, and the editor's color theme in VS
 * Code (a webview's prefers-color-scheme reports the OS, not the editor). The
 * preference is saved in localStorage, like the language, so each host keeps
 * its own.
 */

export const themePreferences = ["system", "light", "dark"] as const;
export type ThemePreference = (typeof themePreferences)[number];
export type Theme = "light" | "dark";

export const themeStorageKey = "enbu-theme";

const darkQuery = "(prefers-color-scheme: dark)";
// VS Code sets this on the webview's <body> and updates it when the editor's theme changes.
const vscodeThemeKind = "data-vscode-theme-kind";

function isPreference(value: unknown): value is ThemePreference {
  return themePreferences.includes(value as ThemePreference);
}

/** The saved preference, or "system" when there is none or storage is unavailable. */
export function readThemePreference(): ThemePreference {
  try {
    const saved = localStorage.getItem(themeStorageKey);
    return isPreference(saved) ? saved : "system";
  } catch {
    return "system";
  }
}

function saveThemePreference(preference: ThemePreference) {
  try {
    if (preference === "system") localStorage.removeItem(themeStorageKey);
    else localStorage.setItem(themeStorageKey, preference);
  } catch {
    // Without storage the choice lasts until the page reloads.
  }
}

/** The theme the host asks for: VS Code's color theme in a webview, the OS setting elsewhere. */
export function systemTheme(host: Host = currentHost): Theme {
  if (host === "vscode") {
    const kind = document.body?.getAttribute(vscodeThemeKind);
    if (kind)
      return kind === "vscode-light" || kind === "vscode-high-contrast-light" ? "light" : "dark";
  }
  return window.matchMedia?.(darkQuery).matches ? "dark" : "light";
}

/** Calls onChange when the host's theme may have changed; returns the unsubscribe function. */
export function watchSystemTheme(onChange: () => void, host: Host = currentHost): () => void {
  const media = window.matchMedia?.(darkQuery);
  media?.addEventListener("change", onChange);
  let observer: MutationObserver | undefined;
  if (host === "vscode" && document.body) {
    observer = new MutationObserver(onChange);
    observer.observe(document.body, { attributes: true, attributeFilter: [vscodeThemeKind] });
  }
  return () => {
    media?.removeEventListener("change", onChange);
    observer?.disconnect();
  };
}

export function resolveTheme(preference: ThemePreference, system: Theme): Theme {
  return preference === "system" ? system : preference;
}

/** Shows a theme: the class Panda's `_dark` condition matches, and color-scheme for native controls. */
export function applyTheme(theme: Theme, root: HTMLElement = document.documentElement) {
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}

let preference: ThemePreference = "system";
let activeHost: Host = currentHost;
const listeners = new Set<() => void>();

function render() {
  applyTheme(resolveTheme(preference, systemTheme(activeHost)));
}

/**
 * Shows the saved theme and keeps following the host while the preference is
 * "system". Call it before the first render so the page never flashes the
 * other theme. Returns the function that stops following.
 */
export function startTheme(host: Host = currentHost): () => void {
  activeHost = host;
  preference = readThemePreference();
  render();
  return watchSystemTheme(render, host);
}

export function getThemePreference(): ThemePreference {
  return preference;
}

/** Saves and shows a preference at once; no reload, unlike the language. */
export function setThemePreference(next: ThemePreference) {
  preference = next;
  saveThemePreference(next);
  render();
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useThemePreference(): [ThemePreference, (next: ThemePreference) => void] {
  return [useSyncExternalStore(subscribe, getThemePreference), setThemePreference];
}
