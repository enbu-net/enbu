import {
  getSettings,
  subscribeSettings,
  updateSettings,
  useSettings,
  type ThemePreference,
} from "./settings";
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
 * preference is one of the settings (see settings.ts), so each host keeps its
 * own.
 */

export { themePreferences, type ThemePreference } from "./settings";
export type Theme = "light" | "dark";

const darkQuery = "(prefers-color-scheme: dark)";
// VS Code sets this on the webview's <body> and updates it when the editor's theme changes.
const vscodeThemeKind = "data-vscode-theme-kind";

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

let activeHost: Host = currentHost;

function render() {
  applyTheme(resolveTheme(getSettings().theme, systemTheme(activeHost)));
}

/**
 * Shows the saved theme and keeps following the host while the preference is
 * "system". Call it before the first render so the page never flashes the
 * other theme. Returns the function that stops following.
 */
export function startTheme(host: Host = currentHost): () => void {
  activeHost = host;
  render();
  const stopHost = watchSystemTheme(render, host);
  const stopSettings = subscribeSettings(render);
  return () => {
    stopHost();
    stopSettings();
  };
}

/** Saves and shows a preference at once; no reload, unlike the language. */
export function setThemePreference(next: ThemePreference) {
  updateSettings({ theme: next });
  render();
}

export function useThemePreference(): [ThemePreference, (next: ThemePreference) => void] {
  return [useSettings().theme, setThemePreference];
}
