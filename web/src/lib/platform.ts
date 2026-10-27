import { Browser, Events } from "@wailsio/runtime";
import * as BackendEvents from "../bindings/events";
import type { ProgressStep } from "./types";
import { isPreview } from "./preview";

/**
 * Desktop services the UI needs besides the backend calls: opening links in
 * the OS browser and listening to backend events. The browser preview has no
 * desktop shell, so it falls back to window.open and window events.
 */

export function openURL(url: string): void {
  if (isPreview) {
    window.open(url, "_blank", "noopener,noreferrer");
    return;
  }
  Browser.OpenURL(url).catch((err: unknown) => console.error("opening URL failed", err));
}

/** Subscribes to the backend's progress events; returns the unsubscribe function. */
export function onProgress(callback: (step: ProgressStep) => void): () => void {
  if (isPreview) {
    const listener = (event: Event) => callback((event as CustomEvent<ProgressStep>).detail);
    window.addEventListener(BackendEvents.EnbuProgress, listener);
    return () => window.removeEventListener(BackendEvents.EnbuProgress, listener);
  }
  return Events.On(BackendEvents.EnbuProgress, (event) => callback(event.data));
}

/** Lets the preview backend report progress the way the desktop backend does. */
export function emitPreviewProgress(step: ProgressStep): void {
  window.dispatchEvent(new CustomEvent(BackendEvents.EnbuProgress, { detail: step }));
}

let installed = false;

/**
 * A desktop webview would open links with target=_blank, or window.open, as a
 * new app window. Send them to the OS browser instead.
 */
export function installExternalLinkHandling(): void {
  if (installed || isPreview) return;
  installed = true;

  document.addEventListener("click", (event) => {
    const anchor = (event.target as Element | null)?.closest?.("a[target='_blank']");
    if (!(anchor instanceof HTMLAnchorElement)) return;
    event.preventDefault();
    openURL(anchor.href);
  });

  const originalOpen = window.open.bind(window);
  window.open = (url?: string | URL, target?: string, features?: string): WindowProxy | null => {
    const href = url?.toString() ?? "";
    if (!href) return originalOpen(url, target, features);
    openURL(href);
    return null;
  };
}
