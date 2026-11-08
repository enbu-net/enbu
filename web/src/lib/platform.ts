import {
  Browser,
  Events,
  objectNames,
  setTransport,
  type RuntimeTransport,
} from "@wailsio/runtime";
import * as BackendEvents from "../bindings/events";
import type { ProgressStep } from "./types";
import { host } from "./host";
import { vscodeBridge, type VsCodeBridge } from "./vscode";

/**
 * Desktop services the UI needs besides the backend calls: opening links in
 * the OS browser and listening to backend events. In VS Code the extension host
 * does both. The browser preview has no desktop shell, so it falls back to
 * window.open and window events.
 */

/**
 * The runtime transport of a VS Code webview: the generated bindings' calls go
 * to the extension host by method name, and come back as the desktop app's do.
 * The webview has no other Wails runtime to call, nor a way to cancel a call.
 */
export function vscodeTransport(bridge: VsCodeBridge): RuntimeTransport {
  return {
    async call(objectID, _method, _windowName, args) {
      if (objectID !== objectNames.Call) return undefined;
      const call = args as { methodName: string; args?: unknown[] };
      const method = call.methodName.slice(call.methodName.lastIndexOf(".") + 1);
      return bridge.call(method, call.args ?? []);
    },
  };
}

if (host === "vscode" && vscodeBridge) setTransport(vscodeTransport(vscodeBridge));

export function openURL(url: string): void {
  if (host === "vscode") {
    vscodeBridge?.openExternal(url);
    return;
  }
  if (host === "preview") {
    window.open(url, "_blank", "noopener,noreferrer");
    return;
  }
  Browser.OpenURL(url).catch((err: unknown) => console.error("opening URL failed", err));
}

/** Subscribes to the backend's progress events; returns the unsubscribe function. */
export function onProgress(callback: (step: ProgressStep) => void): () => void {
  if (host === "vscode") {
    return (
      vscodeBridge?.on(BackendEvents.EnbuProgress, (data) => callback(data as ProgressStep)) ??
      (() => {})
    );
  }
  if (host === "preview") {
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
 * A desktop or VS Code webview would open links with target=_blank, or
 * window.open, as a new window or not at all. Send them to the OS browser
 * instead.
 */
export function installExternalLinkHandling(): void {
  if (installed || host === "preview") return;
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
