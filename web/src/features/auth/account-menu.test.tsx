import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { Session } from "../../lib/session";
import { queryButton, root, settle, setupDom, withSession } from "../../test/dom";
import { AccountMenu } from "./account-menu";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

async function openMenu(session: Partial<Session>) {
  await act(async () => {
    root.render(<>{withSession(<AccountMenu />, session)}</>);
  });
  await act(async () => queryButton("Account menu")?.click());
}

describe("AccountMenu", () => {
  it("does not show another GitHub connect action when signed out", async () => {
    await openMenu({ status: { authenticated: false, workspace_configured: true } });

    expect(document.body.textContent).toContain("Language");
    expect(document.body.textContent).toContain("Account");
    expect(document.body.textContent).not.toContain("Connect GitHub");
  });

  it("signs out and reloads the session even when the backend fails", async () => {
    const refresh = vi.fn(async () => {});
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(backend).logout.mockRejectedValueOnce(new Error("keyring locked"));
    await openMenu({
      status: { authenticated: true, workspace_configured: false, username: "octo" },
      refresh,
    });

    await act(async () => queryButton("Log out", document.body)?.click());
    await settle();

    expect(backend.logout).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith({ force: true });
    log.mockRestore();
  });
});
