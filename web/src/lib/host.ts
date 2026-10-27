import { isPreview } from "./preview";
import { inVsCode } from "./vscode";

/**
 * Where the UI runs: the desktop app's window, a VS Code webview, or the
 * browser preview. Each has its own backend and its own way to open links and
 * deliver backend events.
 */
export type Host = "desktop" | "vscode" | "preview";

export const host: Host = inVsCode ? "vscode" : isPreview ? "preview" : "desktop";
