import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import { displayError } from "../lib/app-error";
import { ImportDialog } from "./import-dialog";

function typeInto(textarea: HTMLTextAreaElement | null, value: string) {
  if (!textarea) throw new Error("no textarea");
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(textarea, value);
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
}

describe("ImportDialog", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  const onImport = vi.fn();

  beforeEach(() => {
    onImport.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => {
      root.render(
        <I18nProvider>
          <ImportDialog
            open
            environment="prod"
            loading={false}
            onClose={() => {}}
            onImport={onImport}
          />
        </I18nProvider>,
      );
    });
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  const importButton = () =>
    Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
      (b) => b.textContent?.trim() === "Import",
    );

  it("names the environment and waits for contents", () => {
    expect(container.textContent).toContain("Import into prod");
    expect(importButton()?.disabled).toBe(true);
  });

  it("passes pasted contents and the overwrite choice", () => {
    act(() => typeInto(container.querySelector("textarea"), "A=1\nB=2\n"));
    act(() => container.querySelector<HTMLInputElement>('input[type="checkbox"]')?.click());
    act(() => importButton()?.click());
    expect(onImport).toHaveBeenCalledWith("A=1\nB=2\n", true);
  });

  it("shows why the last import failed", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <ImportDialog
            open
            environment="prod"
            loading={false}
            error={displayError("secret_already_exists", { key: "A, B" })}
            onClose={() => {}}
            onImport={onImport}
          />
        </I18nProvider>,
      );
    });
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("A, B");
  });

  it("does not overwrite unless asked", () => {
    act(() => typeInto(container.querySelector("textarea"), "A=1\n"));
    act(() => importButton()?.click());
    expect(onImport).toHaveBeenCalledWith("A=1\n", false);
  });
});
