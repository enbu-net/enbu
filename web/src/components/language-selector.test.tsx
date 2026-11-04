import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { localStorageKey } from "../paraglide/runtime";
import { LanguageSelector } from "./language-selector";

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
  localStorage.removeItem(localStorageKey);
});

describe("LanguageSelector", () => {
  it("lists both locales and saves the one picked", () => {
    act(() => root.render(<LanguageSelector />));

    const select = container.querySelector("select");
    expect(container.textContent).toContain("Language");
    expect(Array.from(select?.options ?? []).map((option) => option.text)).toEqual([
      "English",
      "日本語",
    ]);

    act(() => {
      if (!select) return;
      select.value = "ja";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });

    // The page reloads to show the new locale; what it reloads with is saved.
    expect(localStorage.getItem(localStorageKey)).toBe("ja");
  });
});
