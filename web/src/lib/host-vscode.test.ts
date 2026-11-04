import { describe, expect, it, vi } from "vite-plus/test";
import type { WebviewMessage } from "./vscode";

// VS Code injects acquireVsCodeApi into its webviews before any script runs.
const posted: WebviewMessage[] = [];
vi.stubGlobal("acquireVsCodeApi", () => ({
  postMessage: (message: WebviewMessage) => posted.push(message),
}));

// Importing the real Wails runtime starts timers that outlive jsdom (see
// platform.test.ts).
vi.useFakeTimers();
const { host } = await import("./host");
const { backend } = await import("./backend");
const { onProgress, openURL } = await import("./platform");
vi.clearAllTimers();
vi.useRealTimers();

describe("in a VS Code webview", () => {
  it("is detected as the VS Code host", () => {
    expect(host).toBe("vscode");
  });

  it("sends backend calls to the extension host", async () => {
    posted.length = 0;
    const version = backend.appVersion();
    expect(posted).toEqual([{ type: "call", id: 1, method: "GetAppVersion", params: [] }]);
    window.dispatchEvent(
      new MessageEvent("message", { data: { type: "result", id: 1, result: "1.2.3" } }),
    );
    await expect(version).resolves.toBe("1.2.3");
  });

  it("asks the extension host to open links", () => {
    posted.length = 0;
    openURL("https://github.com/enbu-net/enbu");
    expect(posted).toEqual([{ type: "openExternal", url: "https://github.com/enbu-net/enbu" }]);
  });

  it("passes progress events from the extension host to the listener", () => {
    const listener = vi.fn();
    const off = onProgress(listener);
    const step = { op: "add", step: "push", status: "start" };
    window.dispatchEvent(
      new MessageEvent("message", { data: { type: "event", name: "enbu:progress", data: step } }),
    );
    off();
    expect(listener).toHaveBeenCalledWith(step);
  });
});
