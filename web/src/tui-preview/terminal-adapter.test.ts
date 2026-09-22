import { describe, expect, it, vi } from "vite-plus/test";
import type { Terminal } from "ghostty-web";
import { attachNavigationKeyReporting, resolveRuntimeURL } from "./terminal-adapter";

describe("attachNavigationKeyReporting", () => {
  it("uses portable VT sequences for unmodified navigation keys", () => {
    let handler: ((event: KeyboardEvent) => boolean) | undefined;
    const input = vi.fn();
    const terminal = {
      attachCustomKeyEventHandler: vi.fn((next) => {
        handler = next;
      }),
      input,
    } as unknown as Terminal;

    attachNavigationKeyReporting(terminal);
    expect(handler?.(new KeyboardEvent("keydown", { key: "ArrowUp" }))).toBe(true);
    expect(handler?.(new KeyboardEvent("keydown", { key: "ArrowDown" }))).toBe(true);
    expect(input).toHaveBeenNthCalledWith(1, "\x1b[A", true);
    expect(input).toHaveBeenNthCalledWith(2, "\x1b[B", true);
  });

  it("leaves printable and modified keys to Ghostty", () => {
    let handler: ((event: KeyboardEvent) => boolean) | undefined;
    const input = vi.fn();
    const terminal = {
      attachCustomKeyEventHandler: (next: (event: KeyboardEvent) => boolean) => {
        handler = next;
      },
      input,
    } as unknown as Terminal;

    attachNavigationKeyReporting(terminal);
    expect(handler?.(new KeyboardEvent("keydown", { key: "1" }))).toBe(false);
    expect(handler?.(new KeyboardEvent("keydown", { key: "ArrowUp", ctrlKey: true }))).toBe(false);
    expect(input).not.toHaveBeenCalled();
  });
});

describe("resolveRuntimeURL", () => {
  it("resolves the WASI module beside the preview root", () => {
    expect(resolveRuntimeURL("https://example.test/enbu/pr-35/web/tui.html")).toBe(
      "https://example.test/enbu/pr-35/tui/out.wasm.gz",
    );
  });
});
