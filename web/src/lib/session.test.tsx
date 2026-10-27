import { useEffect } from "react";
import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "./backend";
import { SessionProvider, useSession, type Session } from "./session";
import { root, settle, setupDom } from "../test/dom";

vi.mock("./backend", async () => ({
  backend: (await import("../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

async function renderSession() {
  const latest: { session?: Session } = {};
  function Probe() {
    const session = useSession();
    useEffect(() => {
      latest.session = session;
    });
    return null;
  }
  await act(async () => {
    root.render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
  });
  await settle();
  return () => latest.session!;
}

describe("SessionProvider", () => {
  it("loads who is signed in and the selected repository", async () => {
    mocked.authStatus.mockResolvedValue({ authenticated: true, workspace_configured: false });
    mocked.repoStatus.mockResolvedValueOnce({ selected: false });
    const session = await renderSession();

    expect(session().loading).toBe(false);
    expect(session().status?.authenticated).toBe(true);
    expect(session().repo).toEqual({ selected: false });
  });

  it("asks again who is signed in when the repository changes", async () => {
    const session = await renderSession();
    mocked.authStatus.mockClear();
    mocked.authStatus.mockResolvedValue({ authenticated: false, workspace_configured: true });

    const repo = {
      selected: true,
      repo: {
        path: "/s3",
        initialized: true,
        has_git: false,
        has_remote: false,
        storage_configured: true,
      },
    };
    await act(async () => session().setRepo(repo));
    await settle();

    expect(session().repo).toEqual(repo);
    expect(mocked.authStatus).toHaveBeenCalledTimes(1);
    expect(session().status?.workspace_configured).toBe(true);
  });

  it("falls back to repository selection when the repository cannot load", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    mocked.repoStatus.mockRejectedValueOnce(new Error("config unreadable"));
    const session = await renderSession();
    expect(session().repo).toEqual({ selected: false });
    log.mockRestore();
  });
});
