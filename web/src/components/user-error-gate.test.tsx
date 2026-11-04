import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { setLocale } from "../paraglide/runtime";
import { UserErrorGate } from "./user-error-gate";

describe("UserErrorGate", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(async () => {
    await setLocale("ja", { reload: false });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it("localizes unhandled rejection errors without exposing their details", async () => {
    act(() => {
      root.render(
        <>
          <UserErrorGate>
            <div>content</div>
          </UserErrorGate>
        </>,
      );
    });

    const event = new Event("unhandledrejection");
    Object.defineProperty(event, "reason", {
      value: new Error("secret backend detail"),
    });
    await act(async () => window.dispatchEvent(event));

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      "予期しないエラーが発生しました。",
    );
    expect(container.textContent).not.toContain("secret backend detail");
  });

  it("localizes React render errors without exposing their details", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});

    function Broken(): never {
      throw new Error("sensitive render detail");
    }

    await act(async () => {
      root.render(
        <>
          <UserErrorGate>
            <Broken />
          </UserErrorGate>
        </>,
      );
      await Promise.resolve();
    });

    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      "予期しないエラーが発生しました。",
    );
    expect(container.textContent).not.toContain("sensitive render detail");
    expect(container.querySelector<HTMLButtonElement>('button[aria-label="閉じる"]')).toBeTruthy();
  });
});
