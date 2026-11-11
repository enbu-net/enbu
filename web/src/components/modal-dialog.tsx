import { type ReactNode, type RefObject, useEffectEvent, useLayoutEffect, useRef } from "react";
import { styled } from "styled-system/jsx";

// Safari and WebKitGTK have no closedby yet; there a click on the backdrop is
// detected by position, since the <dialog> is also the target of clicks on its
// own padding.
const supportsClosedBy =
  typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype;

function outside(event: { clientX: number; clientY: number }, dialog: HTMLDialogElement) {
  const r = dialog.getBoundingClientRect();
  return (
    event.clientX < r.left ||
    event.clientX > r.right ||
    event.clientY < r.top ||
    event.clientY > r.bottom
  );
}

/**
 * A modal native <dialog>, shown with showModal() while it is mounted: the
 * browser makes the page inert, keeps focus inside, closes on Esc and returns
 * focus to the control that opened it.
 *
 * dismissible false (while an action runs) keeps Esc and the backdrop from
 * closing it. A dismissible dialog closes from the backdrop too.
 *
 * onClose reports a dialog the browser already closed (Esc, the backdrop), so
 * the parent must stop rendering ModalDialog then: a dialog kept mounted after
 * onClose stays closed and does not show again.
 */
export function ModalDialog({
  labelledBy,
  describedBy,
  dismissible = true,
  initialFocusRef,
  returnFocusRef,
  wide = false,
  blur = false,
  onClose,
  children,
}: {
  labelledBy: string;
  describedBy?: string;
  dismissible?: boolean;
  /** The control to focus first, when it is not the first one in the dialog. */
  initialFocusRef?: RefObject<HTMLElement | null>;
  /**
   * Where focus goes after closing, when the control that opened the dialog
   * is gone by then (such as an item of a menu that closed).
   */
  returnFocusRef?: RefObject<HTMLElement | null>;
  /** 480px wide in place of 440px. */
  wide?: boolean;
  /** Blurs the page behind the backdrop. */
  blur?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const handleClose = useEffectEvent(() => onClose());
  const isDismissible = useEffectEvent(() => dismissible);
  const pressedOutside = useRef(false);

  // A layout effect: its cleanup runs while the <dialog> is still in the
  // document, so close() can return focus to the control that opened it.
  useLayoutEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const returnTo = returnFocusRef?.current;
    if (!dialog.open) dialog.showModal();
    initialFocusRef?.current?.focus();
    const onCancel = (event: Event) => {
      // Esc closes the dialog natively; the parent learns of it from close.
      if (!isDismissible()) event.preventDefault();
    };
    const onNativeClose = () => handleClose();
    dialog.addEventListener("cancel", onCancel);
    dialog.addEventListener("close", onNativeClose);
    return () => {
      dialog.removeEventListener("cancel", onCancel);
      dialog.removeEventListener("close", onNativeClose);
      if (dialog.open) dialog.close();
      returnTo?.focus();
    };
  }, [initialFocusRef, returnFocusRef]);

  return (
    <styled.dialog
      ref={ref}
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      {...({ closedby: dismissible ? "any" : "none" } as object)}
      onPointerDown={(event) => {
        pressedOutside.current = outside(event, event.currentTarget);
      }}
      onPointerUp={(event) => {
        if (supportsClosedBy || !dismissible) return;
        // The press and the release both outside, so a text selection that
        // ends on the backdrop does not dismiss.
        if (pressedOutside.current && outside(event, event.currentTarget)) {
          event.currentTarget.close();
        }
      }}
      w="calc(100% - 2rem)"
      maxW={wide ? "480px" : "440px"}
      maxH="calc(100% - 2rem)"
      m="auto"
      p="5"
      color="fg.default"
      bg="bg.surface"
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="2xl"
      boxShadow="xl"
      overflowY="auto"
      css={{
        // Without both rules, scrolling over the backdrop or inside the dialog
        // scrolls the page behind it.
        "&:modal": { overscrollBehavior: "contain" },
        _backdrop: {
          bg: "bg.backdrop",
          overflow: "hidden",
          overscrollBehavior: "contain",
          backdropFilter: blur ? "blur(4px)" : undefined,
        },
      }}
    >
      {children}
    </styled.dialog>
  );
}
