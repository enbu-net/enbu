import { useRef, useState } from "react";
import { act } from "react-dom/test-utils";
import { describe, expect, it, vi } from "vite-plus/test";
import { ModalDialog } from "./modal-dialog";
import {
  clickBackdrop,
  container,
  openDialog,
  pressEscape,
  queryButton,
  root,
  setupDom,
} from "../test/dom";

setupDom();

function Harness({
  dismissible = true,
  onClose = () => {},
}: {
  dismissible?: boolean;
  onClose?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      {open && (
        <ModalDialog
          labelledBy="title"
          dismissible={dismissible}
          initialFocusRef={inputRef}
          onClose={() => {
            onClose();
            setOpen(false);
          }}
        >
          <h2 id="title">Title</h2>
          <button type="button">First</button>
          <input ref={inputRef} aria-label="Name" />
        </ModalDialog>
      )}
    </>
  );
}

describe("ModalDialog", () => {
  it("opens as a native modal named by its title, focusing the chosen control", () => {
    act(() => root.render(<Harness />));
    act(() => queryButton("Open")?.click());
    const dialog = openDialog();
    expect(dialog?.dataset.modal).toBe("true");
    expect(dialog?.getAttribute("aria-labelledby")).toBe("title");
    // The native modal brings its own role and modality.
    expect(dialog?.hasAttribute("role")).toBe(false);
    expect(dialog?.hasAttribute("aria-modal")).toBe(false);
    expect(document.activeElement?.getAttribute("aria-label")).toBe("Name");
  });

  it("closes on Esc and from the backdrop, but not from a click inside", () => {
    const onClose = vi.fn();
    act(() => root.render(<Harness onClose={onClose} />));
    act(() => queryButton("Open")?.click());
    act(() => clickBackdrop({ x: 0, y: 0 }));
    expect(onClose).not.toHaveBeenCalled();
    act(() => pressEscape());
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(openDialog()).toBeNull();

    act(() => queryButton("Open")?.click());
    act(() => clickBackdrop());
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("stays open while it is not dismissible", () => {
    const onClose = vi.fn();
    act(() => root.render(<Harness dismissible={false} onClose={onClose} />));
    act(() => queryButton("Open")?.click());
    expect(openDialog()?.getAttribute("closedby")).toBe("none");
    act(() => pressEscape());
    act(() => clickBackdrop());
    expect(onClose).not.toHaveBeenCalled();
    expect(openDialog()).toBeTruthy();
  });

  it("closes the native dialog when the parent hides it", () => {
    act(() => root.render(<Harness />));
    act(() => queryButton("Open")?.click());
    const dialog = openDialog();
    const close = vi.spyOn(dialog!, "close");
    act(() => pressEscape());
    expect(close).toHaveBeenCalled();
    expect(container.querySelector("dialog")).toBeNull();
  });
});
