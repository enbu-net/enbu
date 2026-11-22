import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../lib/backend";
import type { Session } from "../lib/session";
import { noRepo, type RepoInfo } from "../lib/types";
import { container, queryButton, root, settle, setupDom, typeInto, withSession } from "../test/dom";
import { HomePage } from "./index";

vi.mock("../lib/backend", async () => ({
  backend: (await import("../test/backend-mock")).createBackendMock(),
}));
vi.mock("../lib/platform", () => ({
  openURL: vi.fn(),
  onProgress: () => () => {},
}));

vi.mock("../features/auth/add-account", () => ({
  AddAccount: ({ onDone }: { onDone: () => void }) => (
    <button type="button" onClick={onDone}>
      Return from GitHub
    </button>
  ),
}));

setupDom();

function repoInfo(overrides: Partial<RepoInfo> = {}): RepoInfo {
  return {
    path: "/workspace",
    owner: "acme",
    repo: "workspace",
    initialized: true,
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

  it("founds a workspace in a folder without Git", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: false },
      repo: repoInfo({ initialized: false, has_remote: false, storage_configured: false }),
    });
    expect(container.textContent).toContain("This folder has no enbu.toml yet");
    expect(container.querySelector("#init-storage")).toBeTruthy();
  });

  it("resets storage input when moving between unconfigured folders", async () => {
    const repo = repoInfo({ initialized: false, storage_configured: false });
    await renderHome({ repo });
    typeInto(container.querySelector("#init-storage"), "s3://first/team");
    await renderHome({ repo: { ...repo, path: "/other" } });
    expect(container.querySelector("#init-storage")).toHaveProperty("value", "");
  });

  it("keeps a typed GHCR URL when returning from sign-in", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: false },
      repo: repoInfo({ initialized: false, storage_configured: false }),
    });
    const url = "oci://ghcr.io/example/workspace";
    typeInto(container.querySelector("#init-storage"), url);
    await act(async () => queryButton("Connect with GitHub")?.click());
    await act(async () => queryButton("Return from GitHub")?.click());
    await settle();
    expect(container.querySelector("#init-storage")).toHaveProperty("value", url);
  });

  it("opens a configured workspace without GitHub login or Git setup", async () => {
    await renderHome({
      status: { authenticated: false, workspace_configured: true },
      repo: repoInfo({ has_remote: false }),
    });
    expect(backend.ListSecrets).toHaveBeenCalled();
    expect(container.textContent).not.toContain("Connect with GitHub");
    expect(container.textContent).not.toContain("This folder has no enbu.toml yet");
  });
});
