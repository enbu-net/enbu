import { describe, expect, it, vi } from "vite-plus/test";
import { AppError, toDisplayError } from "./app-error";
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
    const version = backend.GetAppVersion();
    expect(posted).toEqual([{ type: "call", id: 1, method: "GetAppVersion", params: [] }]);
    window.dispatchEvent(
      new MessageEvent("message", { data: { type: "result", id: 1, result: "1.2.3" } }),
    );
    await expect(version).resolves.toBe("1.2.3");
  });

  /** Answers the call the webview just posted. */
  function reply(message: Record<string, unknown>) {
    const { id } = posted.at(-1) as { id: number };
    window.dispatchEvent(new MessageEvent("message", { data: { id, ...message } }));
  }

  it("calls the desktop service methods by name with the desktop app's arguments", async () => {
    posted.length = 0;
    const call = backend.ImportSecrets("default", "A=1\n", true);
    await Promise.resolve();
    expect(posted.at(-1)).toMatchObject({
      type: "call",
      method: "ImportSecrets",
      params: ["default", "A=1\n", true],
    });
    reply({ type: "result", result: { environment: "default" } });
    await expect(call).resolves.toMatchObject({ environment: "default", added: [] });
  });

  it("builds results like the generated bindings, so Go's null lists become empty", async () => {
    const envs = backend.ListEnvironments();
    await Promise.resolve();
    reply({ type: "result", result: null });
    await expect(envs).resolves.toEqual([]);

    const secrets = backend.ListSecrets("dev");
    await Promise.resolve();
    reply({ type: "result", result: { environment: "dev", secrets: null } });
    await expect(secrets).resolves.toMatchObject({ environment: "dev", secrets: [] });
  });

  it("rejects with the AppError the service returned", async () => {
    const call = backend.SyncSecrets("dev");
    await Promise.resolve();
    reply({ type: "error", error: { code: "secret_conflict", message: "raw", params: {} } });
    const err = await call.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect(toDisplayError(err).code).toBe("secret_conflict");
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
