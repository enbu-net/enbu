import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import { displayError, type DisplayError } from "../lib/app-error";
import type { ProgressStep } from "../lib/types";
import { TransferModal } from "./transfer-modal";

const progress = vi.hoisted(() => {
  const listeners = new Set<(step: ProgressStep) => void>();
  return {
    listeners,
    emit: (step: ProgressStep) => listeners.forEach((listener) => listener(step)),
  };
});

vi.mock("../lib/platform", () => ({
  onProgress: (listener: (step: ProgressStep) => void) => {
    progress.listeners.add(listener);
    return () => progress.listeners.delete(listener);
  },
}));

describe("TransferModal", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  const onClose = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    onClose.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.useRealTimers();
  });

  function renderModal(error?: DisplayError) {
    act(() => {
      root.render(
        <I18nProvider>
          <TransferModal
            open
            operation="add"
            error={error}
            onClose={onClose}
          />
        </I18nProvider>,
      );
    });
  }

  it("simulates fallback steps and classifies transfer direction", () => {
    renderModal();
    expect(container.textContent).toContain("Fetching recipient public keys");
    expect(container.querySelector("[data-transfer-direction]")?.getAttribute("data-transfer-direction")).toBe("download");

    void act(() => vi.advanceTimersByTime(2400));
    expect(container.textContent).toContain("Encrypting for every member with age");
    expect(container.querySelector("[data-transfer-direction]")?.getAttribute("data-transfer-direction")).toBe("local");

    void act(() => vi.advanceTimersByTime(1200));
    expect(container.textContent).toContain("Publishing the signed revision to storage");
    expect(container.querySelector("[data-transfer-direction]")?.getAttribute("data-transfer-direction")).toBe("upload");
  });

  it("shows backend progress and terminal completion", () => {
    renderModal();
    act(() => progress.emit({ op: "add", step: "push", status: "start" }));
    expect(container.textContent).toContain("Publishing the signed revision to storage");

    act(() => progress.emit({ op: "add", step: "push", status: "done" }));
    expect(container.textContent).toContain("Done ✓");
    void act(() => vi.advanceTimersByTime(2400));
    expect(container.textContent).toContain("Done ✓");
  });

  it("unsubscribes from progress events when closed", () => {
    renderModal();
    expect(progress.listeners.size).toBe(1);
    act(() => root.unmount());
    expect(progress.listeners.size).toBe(0);
    root = createRoot(container);
  });

  it("exposes dialog semantics and dismisses errors by button or Escape", () => {
    renderModal(displayError("internal"));
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute("aria-modal")).toBe("true");
    expect(dialog?.getAttribute("aria-labelledby")).toBeTruthy();
    expect(container.textContent).toContain("An unexpected error occurred");

    act(() => container.querySelector<HTMLButtonElement>("button")?.click());
    expect(onClose).toHaveBeenCalledTimes(1);
    void act(() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })));
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
