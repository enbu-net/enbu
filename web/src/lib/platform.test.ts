import { describe, expect, it, vi } from "vite-plus/test";

const runtime = vi.hoisted(() => ({
  OpenURL: vi.fn(async () => {}),
  On: vi.fn(() => () => {}),
}));
vi.mock("@wailsio/runtime", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wailsio/runtime")>()),
  Browser: { OpenURL: runtime.OpenURL },
  Events: { On: runtime.On },
}));

// Importing the real runtime starts a window.setInterval that polls for its
// environment. A tick after jsdom tears the window down throws an unhandled
// ReferenceError, so the runtime's timers are registered as fakes and dropped.
vi.useFakeTimers();
const { installExternalLinkHandling, onProgress, openURL } = await import("./platform");
expect(vi.getTimerCount()).toBeGreaterThan(0);
vi.clearAllTimers();
vi.useRealTimers();

describe("platform", () => {
  it("opens links in the OS browser", () => {
    openURL("https://github.com/enbu-net/enbu");
    expect(runtime.OpenURL).toHaveBeenCalledWith("https://github.com/enbu-net/enbu");
  });

  it("passes the progress event's data to the listener", () => {
    const listener = vi.fn();
    onProgress(listener);
    const [name, handler] = runtime.On.mock.lastCall as unknown as [
      string,
      (event: { data: unknown }) => void,
    ];
    expect(name).toBe("enbu:progress");
    handler({ data: { op: "add", step: "push", status: "start" } });
    expect(listener).toHaveBeenCalledWith({ op: "add", step: "push", status: "start" });
  });

  it("sends new-window links and window.open to the OS browser", () => {
    installExternalLinkHandling();
    runtime.OpenURL.mockClear();

    const anchor = document.createElement("a");
    anchor.href = "https://example.com/docs";
    anchor.target = "_blank";
    const label = document.createElement("span");
    anchor.append(label);
    document.body.append(anchor);
    const click = new MouseEvent("click", { bubbles: true, cancelable: true });
    label.dispatchEvent(click);
    anchor.remove();

    expect(click.defaultPrevented).toBe(true);
    expect(runtime.OpenURL).toHaveBeenCalledWith("https://example.com/docs");
    expect(window.open("https://example.com/other")).toBeNull();
    expect(runtime.OpenURL).toHaveBeenLastCalledWith("https://example.com/other");
  });
});
