import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import type { DiffResult, HistoryEntry } from "../lib/api";
import { HistoryDialog } from "./history-dialog";

const entries: HistoryEntry[] = [
  { index: 1, timestamp: "2026-10-01T09:00:00Z", tag: "a" },
  { index: 2, timestamp: "2026-10-02T09:00:00Z", tag: "b" },
  { index: 3, timestamp: "2026-10-03T09:00:00Z", tag: "c" },
];

describe("HistoryDialog", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  const listHistory = vi.fn(async () => entries);
  const diffHistory = vi.fn(
    async (): Promise<DiffResult> => ({ added: ["NEW"], removed: ["GONE"], modified: [] }),
  );
  const restoreHistory = vi.fn(async () => {});
  const onRestored = vi.fn();
  const onClose = vi.fn();

  beforeEach(async () => {
    for (const fn of [listHistory, diffHistory, restoreHistory, onRestored, onClose])
      fn.mockClear();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    await act(async () => {
      root.render(
        <I18nProvider>
          <HistoryDialog
            environment="prod"
            listHistory={listHistory}
            diffHistory={diffHistory}
            restoreHistory={restoreHistory}
            onRestored={onRestored}
            onClose={onClose}
          />
        </I18nProvider>,
      );
    });
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  const button = (text: string) =>
    Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
      (b) => b.textContent?.trim() === text,
    );

  it("lists revisions newest first and marks the latest", () => {
    const text = container.textContent ?? "";
    expect(text.indexOf("#3")).toBeLessThan(text.indexOf("#1"));
    expect(text).toContain("latest");
    // The latest cannot be compared with itself.
    expect(container.querySelector('button[aria-label="Compare: #3"]')).toBeNull();
  });

  it("compares an older revision with the latest by key name", async () => {
    await act(async () => {
      container.querySelector<HTMLButtonElement>('button[aria-label="Compare: #1"]')?.click();
    });
    expect(diffHistory).toHaveBeenCalledWith(1, 3);
    expect(container.textContent).toContain("GONE: only in this revision");
    expect(container.textContent).toContain("NEW: added since");
  });

  it("ignores a comparison that finishes after a newer selection", async () => {
    let finishFirst!: (diff: DiffResult) => void;
    diffHistory
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finishFirst = resolve;
          }),
      )
      .mockResolvedValueOnce({ added: [], removed: [], modified: ["SECOND"] });
    await act(async () => {
      container.querySelector<HTMLButtonElement>('button[aria-label="Compare: #1"]')?.click();
    });
    await act(async () => {
      container.querySelector<HTMLButtonElement>('button[aria-label="Compare: #2"]')?.click();
    });
    await act(async () => {
      finishFirst({ added: ["FIRST"], removed: [], modified: [] });
    });
    expect(container.textContent).toContain("SECOND: value changed since");
    expect(container.textContent).not.toContain("FIRST");
  });

  it("restores only after a second confirmation", async () => {
    await act(async () => {
      container.querySelector<HTMLButtonElement>('button[aria-label="Compare: #2"]')?.click();
    });
    act(() => button("Restore")?.click());
    expect(restoreHistory).not.toHaveBeenCalled();
    expect(container.textContent).toContain("Publish this revision's secrets as the latest?");
    await act(async () => {
      button("Restore")?.click();
    });
    expect(restoreHistory).toHaveBeenCalledWith(2);
    expect(onRestored).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("shows a failed restore as a displayable error and stays open", async () => {
    restoreHistory.mockRejectedValueOnce(new Error("boom"));
    await act(async () => {
      container.querySelector<HTMLButtonElement>('button[aria-label="Compare: #2"]')?.click();
    });
    act(() => button("Restore")?.click());
    await act(async () => {
      button("Restore")?.click();
    });
    expect(container.querySelector('[role="alert"]')).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });
});
