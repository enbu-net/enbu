import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { Session } from "../../lib/session";
import { container, queryButton, root, settle, setupDom, withSession } from "../../test/dom";
import { AccountList } from "./account-list";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

async function renderList(session: Partial<Session>) {
  await act(async () => {
    root.render(<>{withSession(<AccountList />, session)}</>);
  });
  await settle();
}

function rows() {
  return Array.from(container.querySelectorAll<HTMLElement>("[data-account]")).map(
    (row) => row.dataset.account,
  );
}

describe("AccountList", () => {
  it("lists the accounts and marks the one in use", async () => {
    await renderList({
      status: {
        authenticated: true,
        workspace_configured: false,
        username: "octo",
        accounts: ["octo", "hubot"],
      },
    });
    expect(rows()).toEqual(["octo", "hubot"]);
    const inUse = container.querySelector('[data-account="octo"]');
    expect(inUse?.textContent).toContain("In use");
    expect(queryButton("Use: octo")).toBeNull();
    expect(queryButton("Use: hubot")).not.toBeNull();
  });

  it("switches to another account and reloads the session", async () => {
    const refresh = vi.fn(async () => {});
    const reloadRepo = vi.fn(async () => {});
    await renderList({
      status: {
        authenticated: true,
        workspace_configured: false,
        username: "octo",
        accounts: ["octo", "hubot"],
      },
      refresh,
      reloadRepo,
    });
    await act(async () => queryButton("Use: hubot")?.click());
    await settle();
    expect(backend.switchAccount).toHaveBeenCalledWith("hubot");
    expect(refresh).toHaveBeenCalledWith({ force: true, invalidate: true });
    expect(reloadRepo).toHaveBeenCalled();
  });

  it("signs out one account and shows why it failed", async () => {
    vi.mocked(backend).logout.mockRejectedValueOnce({ code: "keyring_locked" });
    await renderList({
      status: {
        authenticated: true,
        workspace_configured: false,
        username: "octo",
        accounts: ["octo", "hubot"],
      },
    });
    await act(async () => queryButton("Log out: hubot")?.click());
    await settle();
    expect(backend.logout).toHaveBeenCalledWith("hubot");
    expect(container.textContent).toContain("The OS keyring is locked.");
  });

  it("shows a GITHUB_TOKEN user without actions", async () => {
    await renderList({
      status: { authenticated: true, workspace_configured: false, username: "ci", accounts: [] },
    });
    expect(rows()).toEqual(["ci"]);
    expect(container.textContent).toContain("From GITHUB_TOKEN");
    expect(queryButton("Log out: ci")).toBeNull();
  });

  it("says no account is signed in and offers to add one", async () => {
    await renderList({ status: { authenticated: false, workspace_configured: false } });
    expect(container.textContent).toContain("No GitHub account is signed in.");
    expect(queryButton("Add account")).not.toBeNull();
  });
});
