import type { ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, vi } from "vite-plus/test";
import { SessionContext, type Session } from "../lib/session";
import { noRepo } from "../lib/types";

/** The element each test renders into; setupDom replaces it before every test. */
export let container: HTMLDivElement;
export let clipboardWrite: ReturnType<typeof vi.fn>;
export let root: Root;

/** Gives every test of the calling file a fresh container and browser stubs. */
export function setupDom() {
  beforeEach(() => {
    localStorage.clear();
    class ResizeObserverMock {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
    Object.defineProperty(globalThis, "ResizeObserver", {
      configurable: true,
      value: ResizeObserverMock,
    });
    clipboardWrite = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: clipboardWrite },
    });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.useRealTimers();
  });
}

export function render(ui: ReactNode) {
  act(() => root.render(ui));
}

/** Renders and lets the effects' first backend calls settle. */
export async function renderAndSettle(ui: ReactNode) {
  await act(async () => root.render(ui));
  await settle();
}

export function unmount() {
  act(() => root.unmount());
  root = createRoot(container);
}

/** Lets pending promise callbacks, and the renders they cause, run. */
export async function settle(rounds = 6) {
  await act(async () => {
    for (let i = 0; i < rounds; i++) await Promise.resolve();
  });
}

export function testSession(overrides: Partial<Session> = {}): Session {
  return {
    status: { authenticated: true, workspace_configured: false, username: "u" },
    loading: false,
    repo: noRepo,
    refresh: async () => {},
    setRepo: () => {},
    reloadRepo: async () => {},
    ...overrides,
  };
}

export function withSession(ui: ReactNode, overrides: Partial<Session> = {}) {
  return <SessionContext.Provider value={testSession(overrides)}>{ui}</SessionContext.Provider>;
}

export function queryButton(label: string, scope: ParentNode = container) {
  return (
    Array.from(scope.querySelectorAll<HTMLButtonElement>("button")).find(
      (b) => b.textContent?.includes(label) || b.getAttribute("aria-label") === label,
    ) ?? null
  );
}

export function queryInput(value: string) {
  return (
    Array.from(container.querySelectorAll<HTMLInputElement>("input")).find(
      (el) => el.value === value || el.defaultValue === value,
    ) ?? null
  );
}

/** Types into a controlled input the way React notices. */
export function typeInto(input: HTMLInputElement | null, value: string) {
  act(() => {
    if (!input) return;
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

/** The open modal dialog, if any. */
export function openDialog(): HTMLDialogElement | null {
  return document.querySelector<HTMLDialogElement>("dialog[open]");
}

/** Plays Esc on a modal dialog: a cancelable cancel event, then close unless prevented. */
export function pressEscape(dialog: HTMLDialogElement | null = openDialog()) {
  if (!dialog) return;
  const cancel = new Event("cancel", { cancelable: true });
  dialog.dispatchEvent(cancel);
  if (!cancel.defaultPrevented) dialog.close();
}

/**
 * Presses and releases the pointer at a point, by default outside the open
 * dialog (jsdom lays every element out at 0,0 with no size).
 */
export function clickBackdrop(
  { x, y }: { x: number; y: number } = { x: 500, y: 500 },
  dialog: HTMLDialogElement | null = openDialog(),
) {
  for (const type of ["pointerdown", "pointerup"]) {
    dialog?.dispatchEvent(new MouseEvent(type, { bubbles: true, clientX: x, clientY: y }));
  }
}

/** The control a visible <label> with this text names. */
export function labelledInput(text: string, scope: ParentNode = container) {
  const label = Array.from(scope.querySelectorAll("label")).find(
    (el) => el.textContent?.trim() === text,
  );
  return label?.htmlFor
    ? (document.getElementById(label.htmlFor) as HTMLInputElement | null)
    : null;
}

/** Submits a form the way Enter in one of its fields does. */
export function submitForm(field: HTMLElement | null) {
  field?.closest("form")?.requestSubmit();
}
