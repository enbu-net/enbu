import { useSyncExternalStore } from "react";

/**
 * The person's display and clipboard settings, one JSON object like VS Code's
 * settings.json. The settings screen edits it as a form or as JSON; both
 * write the same object. It lives in localStorage, so each host (the desktop
 * app, VS Code, the browser preview) keeps its own. The language is not here:
 * Paraglide keeps it, and the settings screen shows it beside these.
 */

export const themePreferences = ["system", "light", "dark"] as const;
export type ThemePreference = (typeof themePreferences)[number];

export type Settings = {
  theme: ThemePreference;
  /** The body text size in px; every other text size scales with it. */
  fontSize: number;
  /** Seconds after which a copied secret value is cleared from the clipboard; 0 keeps it. */
  clipboardClearSeconds: number;
};

export const defaultSettings: Settings = {
  theme: "system",
  fontSize: 14,
  clipboardClearSeconds: 30,
};

export const fontSizeRange = { min: 10, max: 24 } as const;
export const clipboardClearRange = { min: 0, max: 600 } as const;

export const settingsStorageKey = "enbu-settings";

/** Why a settings value was refused: the key, and what it must be. */
export class SettingsError extends Error {
  constructor(
    readonly key: string,
    readonly expected: string,
  ) {
    super(`${key}: ${expected}`);
    this.name = "SettingsError";
  }
}

function integerIn(value: unknown, range: { min: number; max: number }): value is number {
  return (
    Number.isInteger(value) && (value as number) >= range.min && (value as number) <= range.max
  );
}

const checks: { [K in keyof Settings]: (value: unknown) => string | null } = {
  theme: (value) =>
    themePreferences.includes(value as ThemePreference)
      ? null
      : themePreferences.map((name) => `"${name}"`).join(" | "),
  fontSize: (value) =>
    integerIn(value, fontSizeRange) ? null : `${fontSizeRange.min}-${fontSizeRange.max}`,
  clipboardClearSeconds: (value) =>
    integerIn(value, clipboardClearRange)
      ? null
      : `${clipboardClearRange.min}-${clipboardClearRange.max}`,
};

export const settingKeys = Object.keys(checks) as (keyof Settings)[];

/**
 * Checks settings a person wrote. Missing keys take their defaults; an
 * unknown key or a bad value throws SettingsError, so a typo is reported
 * instead of being ignored.
 */
export function parseSettings(value: unknown, allowed: readonly string[] = []): Settings {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SettingsError("", "a JSON object");
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!(key in checks) && !allowed.includes(key)) throw new SettingsError(key, "unknown setting");
  }
  const next = { ...defaultSettings };
  for (const key of settingKeys) {
    if (!(key in record)) continue;
    const expected = checks[key](record[key]);
    if (expected) throw new SettingsError(key, expected);
    (next as Record<string, unknown>)[key] = record[key];
  }
  return next;
}

/** The saved settings; a value that is missing or invalid takes its default. */
export function readSettings(): Settings {
  let saved: unknown;
  try {
    saved = JSON.parse(localStorage.getItem(settingsStorageKey) ?? "{}");
  } catch {
    return { ...defaultSettings };
  }
  if (typeof saved !== "object" || saved === null) return { ...defaultSettings };
  const next = { ...defaultSettings };
  for (const key of settingKeys) {
    const value = (saved as Record<string, unknown>)[key];
    if (checks[key](value) === null) (next as Record<string, unknown>)[key] = value;
  }
  return next;
}

function saveSettings(settings: Settings) {
  try {
    localStorage.setItem(settingsStorageKey, JSON.stringify(settings));
  } catch {
    // Without storage the settings last until the page reloads.
  }
}

let current: Settings = readSettings();
const listeners = new Set<() => void>();

export function getSettings(): Settings {
  return current;
}

/** Reads the saved settings again, as on startup. */
export function loadSettings(): Settings {
  current = readSettings();
  for (const listener of listeners) listener();
  return current;
}

/** Saves and applies settings at once. Throws SettingsError for an invalid value. */
export function updateSettings(change: Partial<Settings>) {
  const next = parseSettings({ ...current, ...change });
  current = next;
  saveSettings(next);
  for (const listener of listeners) listener();
}

export function subscribeSettings(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useSettings(): Settings {
  return useSyncExternalStore(subscribeSettings, getSettings);
}

const textScaleVariable = "--enbu-text-scale";

/** Scales every text size token (see panda.config.ts) so the body text is fontSize px. */
export function applyFontSize(fontSize: number, root: HTMLElement = document.documentElement) {
  root.style.setProperty(textScaleVariable, String(fontSize / defaultSettings.fontSize));
}

/** Shows the saved text size and keeps it in step with the settings. */
export function startTextSize(): () => void {
  applyFontSize(getSettings().fontSize);
  return subscribeSettings(() => applyFontSize(getSettings().fontSize));
}
