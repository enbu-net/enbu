import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import { TransferModal, type ProgressStep } from "./transfer-modal";

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
    Reflect.deleteProperty(window, "runtime");
    vi.useRealTimers();
  });

  function renderModal(error?: string) {
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
    expect(container.textContent).toContain("Encrypting with age X25519");
    expect(container.querySelector("[data-transfer-direction]")?.getAttribute("data-transfer-direction")).toBe("local");

    void act(() => vi.advanceTimersByTime(1200));
    expect(container.textContent).toContain("Pushing OCI artifact to GHCR");
    expect(container.querySelector("[data-transfer-direction]")?.getAttribute("data-transfer-direction")).toBe("upload");
  });

  it("handles CustomEvent progress and terminal completion", () => {
    renderModal();
    act(() => {
      window.dispatchEvent(
        new CustomEvent<ProgressStep>("enbu:progress", {
          detail: { op: "export", step: "export", status: "done" },
        }),
      );
    });
    expect(container.textContent).not.toContain("Done ✓");
    expect(container.textContent).toContain("Fetching recipient public keys");

    act(() => {
      window.dispatchEvent(
        new CustomEvent<ProgressStep>("enbu:progress", {
          detail: { op: "add", step: "encrypt", status: "done" },
        }),
      );
    });
    expect(container.textContent).not.toContain("Done ✓");
    expect(container.textContent).toContain("Encrypting with age X25519");

    act(() => {
      window.dispatchEvent(
        new CustomEvent<ProgressStep>("enbu:progress", {
          detail: { op: "add", step: "push", status: "start" },
        }),
      );
    });
    expect(container.textContent).toContain("Pushing OCI artifact to GHCR");

    act(() => {
      window.dispatchEvent(
        new CustomEvent<ProgressStep>("enbu:progress", {
          detail: { op: "add", step: "push", status: "done" },
        }),
      );
    });
    expect(container.textContent).toContain("Done ✓");
    void act(() => vi.advanceTimersByTime(2400));
    expect(container.textContent).toContain("Done ✓");
  });

  it("subscribes to Wails progress events", () => {
    let callback: ((step: ProgressStep) => void) | undefined;
    const unsubscribe = vi.fn();
    Object.defineProperty(window, "runtime", {
      configurable: true,
      value: {
        EventsOn: vi.fn((name: string, handler: (step: ProgressStep) => void) => {
          expect(name).toBe("enbu:progress");
          callback = handler;
          return unsubscribe;
        }),
      },
    });
    renderModal();
    act(() => callback?.({ op: "add", step: "encrypt", status: "start" }));
    expect(container.textContent).toContain("Encrypting with age X25519");
    act(() => root.unmount());
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    root = createRoot(container);
  });

  it("exposes dialog semantics and dismisses errors by button or Escape", () => {
    renderModal("network failed");
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute("aria-modal")).toBe("true");
    expect(dialog?.getAttribute("aria-labelledby")).toBeTruthy();
    expect(container.textContent).toContain("network failed");

    act(() => container.querySelector<HTMLButtonElement>("button")?.click());
    expect(onClose).toHaveBeenCalledTimes(1);
    void act(() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })));
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
