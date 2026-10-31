import type { ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, vi } from "vite-plus/test";
import { SessionContext, type Session } from "../lib/session";

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
    repo: { selected: false },
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
