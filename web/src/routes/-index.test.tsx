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
    const connect = queryButton("Connect with GitHub");
    expect(connect).toBeTruthy();
    await act(async () => connect!.click());
    const back = queryButton("Return from GitHub");
    expect(back).toBeTruthy();
    await act(async () => back!.click());
    await settle();
    expect(container.querySelector("#init-storage")).toHaveProperty("value", url);
  });

  it("offers the GHCR suggestion after clearing a saved storage URL", async () => {
    const url = "oci://ghcr.io/acme/workspace";
    vi.mocked(backend.SuggestStorage).mockResolvedValueOnce(url);
    await renderHome({
      repo: repoInfo({
        initialized: false,
        storage_configured: false,
        storage_draft: {
          url: "s3://bucket/team",
          region: "",
          endpoint: "",
          path_style: false,
          plain_http: false,
        },
      }),
    });
    const input = container.querySelector("#init-storage");
    expect(input).toHaveProperty("value", "s3://bucket/team");
    typeInto(input, "");
    const option = queryButton(url);
    expect(option).toBeTruthy();
    await act(async () => option!.click());
    expect(input).toHaveProperty("value", url);
  });

  it("completes an S3 workspace using saved settings without GitHub sign-in", async () => {
    const storage = {
      url: "s3://bucket/team",
      region: "test-region",
      endpoint: "https://storage.example.test",
      path_style: true,
      plain_http: false,
    };
    const status = { authenticated: false, workspace_configured: false };
    const repo = repoInfo({
      initialized: false,
      storage_configured: false,
      storage_draft: storage,
    });
    const refresh = vi.fn(async () => {});
    const reloadRepo = vi.fn(async () => {
      root.render(
        withSession(<HomePage />, {
          repo: repoInfo(),
          status: { ...status, workspace_configured: true },
        }),
      );
    });
    vi.mocked(backend.Initialize).mockResolvedValue({
      founded: true,
      pending: false,
      storage: storage.url,
      fingerprint: "test-fingerprint",
    } as Awaited<ReturnType<typeof backend.Initialize>>);
    await renderHome({ status, repo, refresh, reloadRepo });
    expect(container.querySelector("#init-storage")).toHaveProperty("value", storage.url);
    const found = queryButton("Found workspace");
    expect(found).toBeTruthy();
    await act(async () => found!.click());
    expect(backend.Initialize).toHaveBeenCalledWith(storage, false);
    const next = queryButton("Continue");
    expect(next).toBeTruthy();
    await act(async () => next!.click());
    await settle();
    expect(refresh).toHaveBeenCalled();
    expect(reloadRepo).toHaveBeenCalled();
    expect(container.querySelector('[role="tab"]')).toBeTruthy();
    expect(queryButton("Connect with GitHub")).toBeNull();
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
