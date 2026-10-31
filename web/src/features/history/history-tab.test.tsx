import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { container, queryButton, renderAndSettle, settle, setupDom } from "../../test/dom";
import { testWorkspace } from "../../test/workspace";
import { HistoryTab } from "./history-tab";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);
const environments = [
  { name: "default", current: true },
  { name: "staging", current: false },
];
const entries = [1, 2, 3].map((index) => ({
  index,
  timestamp: `2026-10-0${index}T00:00:00Z`,
  tag: `tag-${index}`,
}));

describe("HistoryTab", () => {
  it("lists the current environment's revisions newest first", async () => {
    mocked.listHistory.mockResolvedValue(entries);
    await renderAndSettle(<HistoryTab workspace={testWorkspace(environments)} />);

    expect(mocked.listHistory).toHaveBeenCalledWith("default");
    const text = container.textContent ?? "";
    expect(text.indexOf("Revision 3")).toBeLessThan(text.indexOf("Revision 1"));
    // The latest revision is what the environment holds; only older ones restore.
    expect(queryButton("Restore: Revision 3")).toBeNull();
    expect(queryButton("Restore: Revision 1")).not.toBeNull();
  });

  it("compares the two latest revisions by default", async () => {
    mocked.listHistory.mockResolvedValue(entries);
    mocked.diffHistory.mockResolvedValueOnce({ added: ["NEW"], removed: ["OLD"], modified: [] });
    await renderAndSettle(<HistoryTab workspace={testWorkspace(environments)} />);

    await act(async () => queryButton("Compare")?.click());
    await settle();

    expect(mocked.diffHistory).toHaveBeenCalledWith("default", 2, 3);
    expect(container.textContent).toContain("+ NEW");
    expect(container.textContent).toContain("- OLD");
  });

  it("restores a revision and reloads history and secrets", async () => {
    mocked.listHistory.mockResolvedValue(entries);
    const workspace = testWorkspace(environments);
    await renderAndSettle(<HistoryTab workspace={workspace} />);
    mocked.listHistory.mockClear();

    await act(async () => queryButton("Restore: Revision 1")?.click());
    await settle();

    expect(mocked.restoreHistory).toHaveBeenCalledWith("default", 1);
    expect(mocked.listHistory).toHaveBeenCalledWith("default");
    expect(workspace.refresh).toHaveBeenCalled();
    expect(container.textContent).toContain("Restored revision 1");
  });

  it("loads another environment's history when picked", async () => {
    mocked.listHistory.mockResolvedValue([]);
    await renderAndSettle(<HistoryTab workspace={testWorkspace(environments)} />);
    const select = container.querySelector("select")!;

    await act(async () => {
      select.value = "staging";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await settle();

    expect(mocked.listHistory).toHaveBeenLastCalledWith("staging");
    expect(container.textContent).toContain("No revisions changed this environment yet.");
  });
});
