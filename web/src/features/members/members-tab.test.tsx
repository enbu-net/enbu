import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { MemberInfo } from "../../lib/types";
import { container, queryButton, root, settle, setupDom } from "../../test/dom";
import { MembersTab } from "./members-tab";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

const member = (fingerprint: string): MemberInfo => ({
  device_id: "d".repeat(64),
  fingerprint,
  recipient: "age1pq1test",
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
    let resolveA!: (value: MemberInfo[]) => void;
    let resolveB!: (value: MemberInfo[]) => void;
    mocked.ListMembers.mockImplementationOnce(
      () => new Promise((resolve) => (resolveA = resolve)),
    ).mockImplementationOnce(() => new Promise((resolve) => (resolveB = resolve)));

    renderTab("/a");
    renderTab("/b");
    expect(mocked.ListMembers).toHaveBeenCalledTimes(2);

    await act(async () => resolveB([member("new-key")]));
    await settle();
    expect(container.textContent).toContain("new-key");

    await act(async () => resolveA([member("old-key")]));
    await settle();
    expect(container.textContent).toContain("new-key");
    expect(container.textContent).not.toContain("old-key");
  });

  it("syncs the current environment and reloads the members", async () => {
    mocked.ListMembers.mockResolvedValue([]);
    const transfer = vi.fn(runTransfer);
    renderTab("/a", transfer);
    await settle();
    mocked.ListMembers.mockClear();

    await act(async () => queryButton("Sync")?.click());
    await settle();

    expect(transfer).toHaveBeenCalledWith("sync", expect.any(Function));
    expect(mocked.SyncSecrets).toHaveBeenCalledWith("default");
    expect(mocked.ListMembers).toHaveBeenCalledTimes(1);
  });

  it("shows a failed sync as a display error", async () => {
    mocked.ListMembers.mockResolvedValue([]);
    mocked.SyncSecrets.mockRejectedValueOnce(new Error("registry down"));
    renderTab("/a");
    await settle();

    await act(async () => queryButton("Sync")?.click());
    await settle();

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("registry down");
  });
});
