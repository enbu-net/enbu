import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { I18nProvider } from "../lib/i18n";
import type { ConflictSet } from "../lib/types";
import { ConflictPanel } from "./conflict-panel";

const set: ConflictSet = {
  environment: "prod",
  heads: ["h1", "h2"],
  conflicts: [
    {
      key: "API_KEY",
      candidates: [
        { value: "alice", deleted: false },
        { value: "bob", deleted: false },
      ],
    },
    {
      key: "OLD",
      candidates: [
        { value: "kept", deleted: false },
        { value: "", deleted: true },
      ],
    },
  ],
};

describe("ConflictPanel", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;
  const onResolve = vi.fn();

  beforeEach(() => {
    onResolve.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => {
      root.render(
        <I18nProvider>
          <ConflictPanel set={set} loading={false} onResolve={onResolve} />
        </I18nProvider>,
      );
    });
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  const resolveButton = () =>
    [...container.querySelectorAll("button")].find((b) => b.textContent?.includes("Use these values"));
  const radios = (key: string) =>
    [...container.querySelectorAll<HTMLInputElement>(`[data-conflict-key="${key}"] input[type=radio]`)];

  it("shows every candidate, including a deletion", () => {
    expect(container.textContent).toContain("API_KEY");
    expect(container.textContent).toContain("alice");
    expect(container.textContent).toContain("bob");
    expect(container.textContent).toContain("(deleted)");
  });

  it("chooses nothing until every key is decided", () => {
    expect(resolveButton()?.disabled).toBe(true);
    act(() => radios("API_KEY")[1]?.click());
    expect(resolveButton()?.disabled).toBe(true);
    expect(onResolve).not.toHaveBeenCalled();
  });

  it("passes one decision per key, deleting where the deletion was chosen", () => {
    act(() => radios("API_KEY")[1]?.click());
    act(() => radios("OLD")[1]?.click());
    expect(resolveButton()?.disabled).toBe(false);
    act(() => resolveButton()?.click());
    expect(onResolve).toHaveBeenCalledWith([
      { key: "API_KEY", value: "bob", delete: false },
      { key: "OLD", value: "", delete: true },
    ]);
  });
});
