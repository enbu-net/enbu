import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../lib/backend";
import type { Session } from "../lib/session";
import type { RepoInfo } from "../lib/types";
import { container, queryButton, root, settle, setupDom, withSession } from "../test/dom";
import { HomePage } from "./index";

vi.mock("../lib/backend", async () => ({
  backend: (await import("../test/backend-mock")).createBackendMock(),
}));
vi.mock("../lib/platform", () => ({
  openURL: vi.fn(),
  onProgress: () => () => {},
}));

setupDom();

function repoInfo(overrides: Partial<RepoInfo> = {}): RepoInfo {
  return {
    path: "/workspace",
    owner: "acme",
    repo: "workspace",
    initialized: true,
    has_git: true,
    has_remote: true,
    storage_configured: true,
    ...overrides,
  };
}

async function renderHome(session: Partial<Session>) {
  await act(async () => {
    root.render(<>{withSession(<HomePage />, session)}</>);
  });
  await settle();
}

describe("HomePage", () => {
  it("waits for the session before choosing a screen", async () => {
    await renderHome({ loading: true });
    expect(container.querySelector('[role="status"]')?.textContent).toContain("Loading");
  });

  it("asks to sign in when no workspace is configured", async () => {
    await renderHome({ status: { authenticated: false, workspace_configured: false } });
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });

  it("asks for a repository once signed in", async () => {
    await renderHome({ repo: { selected: false } });
    expect(container.querySelector("h1")?.textContent).toContain("Select repository");
  });

  it("walks a new folder through Git setup", async () => {
    await renderHome({
      repo: {
        selected: true,
        repo: repoInfo({ initialized: false, has_git: false, storage_configured: false }),
      },
    });
    expect(queryButton("Initialize Git")).toBeTruthy();
  });

  it("opens a configured workspace without GitHub login or Git setup", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: true },
      repo: { selected: true, repo: repoInfo({ has_git: false, has_remote: false }) },
    });
    expect(backend.listSecrets).toHaveBeenCalled();
    expect(container.textContent).not.toContain("Connect with GitHub");
    expect(container.textContent).not.toContain("Initialize Git");
  });
});
