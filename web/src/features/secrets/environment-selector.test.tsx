import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { I18nProvider } from "../../lib/i18n";
import { container, queryButton, root, setupDom } from "../../test/dom";
import { EnvironmentNameModal, EnvironmentSelector } from "./environment-selector";

setupDom();

describe("environment selector", () => {
  it("switches environments and exposes environment creation as the last action", async () => {
    const onSelect = vi.fn();
    const onAdd = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <EnvironmentSelector
            environments={[
              { name: "default", current: true },
              { name: "staging", current: false },
            ]}
            value="default"
            onSelect={onSelect}
            onAdd={onAdd}
          />
        </I18nProvider>,
      );
    });

    const trigger = document.querySelector<HTMLButtonElement>(
      'button[aria-label="Current environment"]',
    );
    await act(async () => {
      trigger?.click();
      await Promise.resolve();
    });
    const menuButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"));
    const staging = menuButtons.find((button) => button.textContent?.includes("staging"));
    expect(menuButtons.at(-1)?.textContent).toContain("Add environment");
    await act(async () => {
      staging?.click();
      await Promise.resolve();
    });
    expect(onSelect).toHaveBeenCalledWith("staging");

    await act(async () => {
      trigger?.click();
      await Promise.resolve();
    });
    const reopenedAdd = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find(
      (button) => button.textContent?.includes("Add environment"),
    );
    await act(async () => {
      reopenedAdd?.click();
      await Promise.resolve();
    });
    expect(onAdd).toHaveBeenCalledTimes(1);
  });

  it("creates an environment from the modal", () => {
    const onCreate = vi.fn();
    const onClose = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <EnvironmentNameModal
            open
            value="staging"
            loading={false}
            onValueChange={() => {}}
            onClose={onClose}
            onCreate={onCreate}
          />
        </I18nProvider>,
      );
    });
    expect(document.querySelector('[role="dialog"]')).toBeTruthy();
    act(() => {
      queryButton("Create")?.click();
    });
    expect(onCreate).toHaveBeenCalledTimes(1);
  });
});

describe("accessibility: EnvironmentNameModal focus", () => {
  it("dialog has aria-modal and aria-labelledby", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <EnvironmentNameModal
            open={true}
            value=""
            loading={false}
            onValueChange={() => {}}
            onClose={() => {}}
            onCreate={() => {}}
          />
        </I18nProvider>,
      );
    });
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute("aria-modal")).toBe("true");
    expect(dialog?.getAttribute("aria-labelledby")).toBeTruthy();
    const titleId = dialog?.getAttribute("aria-labelledby");
    expect(container.querySelector(`[id="${titleId ?? ""}"]`)).toBeTruthy();
  });
});
