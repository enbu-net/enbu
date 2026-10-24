import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import type { Environment } from "../lib/api";
import { EnvironmentsPanel } from "./environments-panel";

const environments: Environment[] = [
  { name: "default", current: true },
  { name: "staging", current: false, incarnation: "0b8e1f6c-1d3e-4c55-9a51-6f3d2c1b0a99" },
];

function type(input: HTMLInputElement | null, value: string) {
  if (!input) throw new Error("no input");
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

describe("EnvironmentsPanel", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  const onRename = vi.fn(async () => {});
  const onDelete = vi.fn(async (_name: string, purge: boolean) => (purge ? 4 : 0));
  const onPurgeIncarnation = vi.fn(async () => 2);
  const onError = vi.fn();

  function render(admin: boolean) {
    act(() => {
      root.render(
        <I18nProvider>
          <EnvironmentsPanel
            environments={environments}
            admin={admin}
            onRename={onRename}
            onDelete={onDelete}
            onPurgeIncarnation={onPurgeIncarnation}
            onError={onError}
          />
        </I18nProvider>,
      );
    });
  }

  const button = (label: string) =>
    container.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
  const dialogButton = (text: string) =>
    Array.from(container.querySelectorAll<HTMLButtonElement>('[role="dialog"] button')).find(
      (b) => b.textContent?.trim() === text,
    );

  beforeEach(() => {
    for (const fn of [onRename, onDelete, onPurgeIncarnation, onError]) fn.mockClear();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("renames an environment", async () => {
    render(false);
    act(() => button("Rename: staging")?.click());
    act(() => type(container.querySelector('[role="dialog"] input'), "prod"));
    await act(async () => {
      dialogButton("Rename")?.click();
      await Promise.resolve();
    });
    expect(onRename).toHaveBeenCalledWith("staging", "prod");
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("does not delete the current environment", () => {
    render(true);
    expect(button("Delete: default")?.disabled).toBe(true);
  });

  it("keeps stored revisions unless an admin opts in", async () => {
    render(false);
    act(() => button("Delete: staging")?.click());
    // A member who is not an admin is not offered purging at all.
    expect(container.querySelector('[role="dialog"] input[type="checkbox"]')).toBeNull();
    await act(async () => {
      dialogButton("Delete")?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledWith("staging", false);
    expect(container.textContent).not.toContain("Deleted");
    // The incarnation is how an admin finds the kept revisions later.
    expect(container.textContent).toContain("0b8e1f6c-1d3e-4c55-9a51-6f3d2c1b0a99");
  });

  it("deletes stored revisions when an admin asks", async () => {
    render(true);
    act(() => button("Delete: staging")?.click());
    act(() =>
      container.querySelector<HTMLInputElement>('[role="dialog"] input[type="checkbox"]')?.click(),
    );
    await act(async () => {
      dialogButton("Delete")?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledWith("staging", true);
    expect(container.textContent).toContain("Deleted 4 stored revision(s).");
  });

  it("purges an incarnation only for admins and after confirmation", async () => {
    render(false);
    expect(container.textContent).not.toContain("Delete stored revisions");
    render(true);
    const incarnation = "0b8e1f6c-1d3e-4c55-9a51-6f3d2c1b0a99";
    act(() => type(container.querySelector('input[placeholder^="0000"]'), incarnation));
    act(() =>
      Array.from(container.querySelectorAll("button"))
        .find((b) => b.textContent?.trim() === "Delete revisions")
        ?.click(),
    );
    expect(onPurgeIncarnation).not.toHaveBeenCalled();
    expect(container.querySelector('[role="dialog"]')?.textContent).toContain(incarnation);
    await act(async () => {
      dialogButton("Delete revisions")?.click();
      await Promise.resolve();
    });
    expect(onPurgeIncarnation).toHaveBeenCalledWith(incarnation);
    expect(container.textContent).toContain("Deleted 2 stored revision(s).");
  });

  it("reports a failure and closes the dialog", async () => {
    onRename.mockRejectedValueOnce(new Error("boom"));
    render(false);
    act(() => button("Rename: staging")?.click());
    act(() => type(container.querySelector('[role="dialog"] input'), "prod"));
    await act(async () => {
      dialogButton("Rename")?.click();
      await Promise.resolve();
    });
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: "internal" }));
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });
});
