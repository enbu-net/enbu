import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../lib/backend";
import type { Session } from "../lib/session";
import { noRepo, type RepoInfo } from "../lib/types";
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

  it("welcomes without asking to sign in first", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: false },
      repo: noRepo,
    });
    expect(container.querySelector("h1")?.textContent).toBe("enbu");
    expect(container.textContent).toContain("Open folder…");
  });

  it("asks to sign in once a repository on GHCR is chosen", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: false },
      repo: repoInfo(),
    });
    expect(container.querySelector("h1")?.textContent).toBe("Sign in to GitHub");
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });

  it("guides a folder without Git to GitHub", async () => {
    await renderHome({
      repo: repoInfo({ initialized: false, has_git: false, storage_configured: false }),
    });
    expect(container.textContent).toContain("This folder is not on GitHub yet");
  });

  it("opens a configured workspace without GitHub login or Git setup", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: true },
      repo: repoInfo({ has_git: false, has_remote: false }),
    });
    expect(backend.ListSecrets).toHaveBeenCalled();
    expect(container.textContent).not.toContain("Connect with GitHub");
    expect(container.textContent).not.toContain("This folder is not on GitHub yet");
  });
});
