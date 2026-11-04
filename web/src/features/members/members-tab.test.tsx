import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { Member } from "../../lib/types";
import { container, queryButton, root, settle, setupDom } from "../../test/dom";
import { MembersTab } from "./members-tab";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

const member = (fingerprint: string): Member => ({
  device_id: "d".repeat(64),
  fingerprint,
  algorithm: "p256",
  admin: false,
  self: false,
  post_quantum: false,
});

const runTransfer = async (_op: string, task: () => Promise<void>) => task();

function renderTab(repoPath: string, transfer = runTransfer) {
  act(() => {
    root.render(
      <>
        <MembersTab repoPath={repoPath} environment="default" transfer={transfer} />
      </>,
    );
  });
}

describe("MembersTab", () => {
  it("reloads members by repository path and ignores stale completions", async () => {
    let resolveA!: (value: Member[]) => void;
    let resolveB!: (value: Member[]) => void;
    mocked.listMembers
      .mockImplementationOnce(() => new Promise((resolve) => (resolveA = resolve)))
      .mockImplementationOnce(() => new Promise((resolve) => (resolveB = resolve)));

    renderTab("/a");
    renderTab("/b");
    expect(mocked.listMembers).toHaveBeenCalledTimes(2);

    await act(async () => resolveB([member("new-key")]));
    await settle();
    expect(container.textContent).toContain("new-key");

    await act(async () => resolveA([member("old-key")]));
    await settle();
    expect(container.textContent).toContain("new-key");
    expect(container.textContent).not.toContain("old-key");
  });

  it("syncs the current environment and reloads the members", async () => {
    mocked.listMembers.mockResolvedValue([]);
    const transfer = vi.fn(runTransfer);
    renderTab("/a", transfer);
    await settle();
    mocked.listMembers.mockClear();

    await act(async () => queryButton("Sync")?.click());
    await settle();

    expect(transfer).toHaveBeenCalledWith("sync", expect.any(Function));
    expect(mocked.syncSecrets).toHaveBeenCalledWith("default");
    expect(mocked.listMembers).toHaveBeenCalledTimes(1);
  });

  it("shows a failed sync as a display error", async () => {
    mocked.listMembers.mockResolvedValue([]);
    mocked.syncSecrets.mockRejectedValueOnce(new Error("registry down"));
    renderTab("/a");
    await settle();

    await act(async () => queryButton("Sync")?.click());
    await settle();

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("registry down");
  });
});
