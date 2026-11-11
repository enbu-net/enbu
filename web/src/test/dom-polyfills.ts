// jsdom has <dialog> and the popover attribute but none of their behavior.
// These stand-ins keep the parts the components rely on: showModal() and
// close() toggle `open` and fire close (pressEscape in dom.ts plays Esc), and
// popovers fire toggle when they hide.

if (typeof HTMLDialogElement !== "undefined" && !HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute("open", "");
    this.dataset.modal = "true";
    const first = this.querySelector<HTMLElement>(
      "[autofocus], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex='-1'])",
    );
    first?.focus();
  };
  HTMLDialogElement.prototype.show = function show(this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement, value?: string) {
    if (!this.hasAttribute("open")) return;
    this.removeAttribute("open");
    delete this.dataset.modal;
    if (value !== undefined) this.returnValue = value;
    this.dispatchEvent(new Event("close"));
  };
  Object.defineProperty(HTMLDialogElement.prototype, "open", {
    configurable: true,
    get(this: HTMLDialogElement) {
      return this.hasAttribute("open");
    },
    set(this: HTMLDialogElement, value: boolean) {
      this.toggleAttribute("open", value);
    },
  });
}

if (typeof HTMLElement !== "undefined" && !("showPopover" in HTMLElement.prototype)) {
  Object.assign(HTMLElement.prototype, {
    showPopover(this: HTMLElement) {
      this.dataset.popoverOpen = "true";
    },
    hidePopover(this: HTMLElement) {
      if (this.dataset.popoverOpen !== "true") return;
      delete this.dataset.popoverOpen;
      const toggle = new Event("toggle");
      Object.assign(toggle, { oldState: "open", newState: "closed" });
      this.dispatchEvent(toggle);
    },
  });
}
