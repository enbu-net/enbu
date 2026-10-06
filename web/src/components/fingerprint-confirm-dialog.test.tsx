import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { FingerprintConfirmDialog } from "./fingerprint-confirm-dialog";

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function renderDialog(props: Partial<Parameters<typeof FingerprintConfirmDialog>[0]> = {}) {
  const onClose = vi.fn();
  const onConfirm = vi.fn();
  act(() => {
    root.render(
      <FingerprintConfirmDialog
        open
        title="Approve this device?"
        fingerprint="1111-2222-3333-4444-5555"
        warning="Approved devices can read every secret."
        acknowledgeLabel="The fingerprint matches."
        cancelLabel="Cancel"
        confirmLabel="Approve"
        loading={false}
        onClose={onClose}
        onConfirm={onConfirm}
        {...props}
      />,
    );
  });
  return { onClose, onConfirm };
}

const confirmButton = () =>
  Array.from(container.querySelectorAll("button")).find((b) => b.textContent?.trim() === "Approve");

describe("FingerprintConfirmDialog", () => {
  it("renders nothing while closed", () => {
    renderDialog({ open: false });
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("shows the fingerprint to compare and labels the dialog", () => {
    renderDialog();
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute("aria-modal")).toBe("true");
    expect(container.querySelector('[data-testid="fingerprint"]')?.textContent).toBe(
      "1111-2222-3333-4444-5555",
    );
    expect(container.textContent).toContain("Approved devices can read every secret.");
  });

  it("cannot be confirmed until the fingerprint is acknowledged", () => {
    const { onConfirm } = renderDialog();
    expect(confirmButton()?.hasAttribute("disabled")).toBe(true);
    act(() => confirmButton()?.click());
    expect(onConfirm).not.toHaveBeenCalled();

    act(() => container.querySelector<HTMLInputElement>('input[type="checkbox"]')?.click());
    expect(confirmButton()?.hasAttribute("disabled")).toBe(false);
    act(() => confirmButton()?.click());
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape unless an action is running", () => {
    const { onClose } = renderDialog();
    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    expect(onClose).toHaveBeenCalledTimes(1);

    const busy = renderDialog({ loading: true });
    act(() => {
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    expect(busy.onClose).not.toHaveBeenCalled();
  });

  it("forgets the acknowledgement when it is closed and reopened", () => {
    renderDialog();
    act(() => container.querySelector<HTMLInputElement>('input[type="checkbox"]')?.click());
    renderDialog({ open: false });
    renderDialog();
    expect(container.querySelector<HTMLInputElement>('input[type="checkbox"]')?.checked).toBe(
      false,
    );
  });

  it("describes itself with the warning so screen readers read it", () => {
    renderDialog();
    const dialog = container.querySelector('[role="dialog"]');
    const describedBy = dialog?.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(container.querySelector(`[id="${describedBy ?? ""}"]`)?.textContent).toContain(
      "Approved devices can read every secret.",
    );
  });

  it("closes from Cancel and from a click on the backdrop", () => {
    const first = renderDialog();
    const cancel = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.trim() === "Cancel",
    );
    act(() => cancel?.click());
    expect(first.onClose).toHaveBeenCalledTimes(1);

    const second = renderDialog();
    const backdrop = container.querySelector('[role="dialog"]')?.parentElement;
    act(() => {
      backdrop?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    expect(second.onClose).toHaveBeenCalledTimes(1);
  });

  it("ignores a click inside the dialog", () => {
    const { onClose } = renderDialog();
    act(() => {
      container
        .querySelector('[role="dialog"]')
        ?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    expect(onClose).not.toHaveBeenCalled();
  });

  it("locks every control while an action is running", () => {
    const { onClose, onConfirm } = renderDialog({ loading: true });
    const buttons = Array.from(container.querySelectorAll("button"));
    expect(buttons.every((b) => b.hasAttribute("disabled"))).toBe(true);
    expect(container.querySelector<HTMLInputElement>('input[type="checkbox"]')?.disabled).toBe(true);
    const backdrop = container.querySelector('[role="dialog"]')?.parentElement;
    act(() => {
      backdrop?.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    });
    expect(onClose).not.toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
