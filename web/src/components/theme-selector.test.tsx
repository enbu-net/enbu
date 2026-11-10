import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { localStorageKey } from "../paraglide/runtime";
import { getSettings } from "../lib/settings";
import { setThemePreference } from "../lib/theme";
import { ThemeSelector } from "./theme-selector";

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  localStorage.setItem(localStorageKey, "en");
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  act(() => setThemePreference("system"));
  localStorage.clear();
  document.documentElement.className = "";
});

describe("ThemeSelector", () => {
  it("shows a chevron so the select reads as a list to pick from", () => {
    act(() => root.render(<ThemeSelector />));
    const select = container.querySelector("#theme-select");
    expect(select?.parentElement?.querySelector("svg")).toBeTruthy();
    expect(select?.parentElement?.style.width).toBe("148px");
  });

  it("lists the preferences and applies the one picked without a reload", () => {
    act(() => root.render(<ThemeSelector />));

    const select = container.querySelector("select");
    expect(container.textContent).toContain("Theme");
    expect(select?.value).toBe("system");
    expect(Array.from(select?.options ?? []).map((option) => option.text)).toEqual([
      "System",
      "Light",
      "Dark",
    ]);

    act(() => {
      if (!select) return;
      select.value = "dark";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });

    expect(select?.value).toBe("dark");
    expect(getSettings().theme).toBe("dark");
    expect(JSON.parse(localStorage.getItem("enbu-settings") ?? "{}").theme).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
