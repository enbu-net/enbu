import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { RepoInfo } from "../../lib/types";
import {
  container,
  queryButton,
  root,
  settle,
  setupDom,
  typeInto,
  withSession,
} from "../../test/dom";
import { RepositorySelect, RepositorySetup, setupStep } from "./repository-setup";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

function repoInfo(overrides: Partial<RepoInfo> = {}): RepoInfo {
  return {
    path: "/home/octo/app",
    initialized: false,
    has_git: false,
    has_remote: false,
    storage_configured: false,
    ...overrides,
  };
}

describe("setupStep", () => {
  it("asks for Git, then a remote, then enbu", () => {
    expect(setupStep(repoInfo())).toBe("git");
    expect(setupStep(repoInfo({ has_git: true }))).toBe("remote");
    expect(setupStep(repoInfo({ has_git: true, has_remote: true }))).toBe("enbu");
    expect(setupStep(repoInfo({ has_git: true, has_remote: true, initialized: true }))).toBeNull();
  });

  it("skips Git and the remote when enbu.toml already names the storage", () => {
    expect(setupStep(repoInfo({ storage_configured: true }))).toBe("enbu");
    expect(setupStep(repoInfo({ storage_configured: true, initialized: true }))).toBeNull();
  });
});

describe("RepositorySelect", () => {
  function renderSelect(setRepo = vi.fn()) {
    act(() => {
      root.render(<>{withSession(<RepositorySelect />, { setRepo })}</>);
    });
    return setRepo;
  }

  it("labels the path input and titles the screen with h1", () => {
    renderSelect();
    expect(container.querySelector("input[aria-label]")?.getAttribute("aria-label")).toBe(
      "C:\\Users\\you\\src\\your-repo",
    );
    expect(container.querySelector("h1")?.textContent).toContain("Select repository");
  });

  it("selects the typed path on Enter and continues only with a path", async () => {
    const selected = { selected: true, repo: repoInfo() };
    mocked.selectRepository.mockResolvedValueOnce(selected);
    const setRepo = renderSelect();
    expect(queryButton("Continue")?.disabled).toBe(true);

    const input = container.querySelector<HTMLInputElement>("input");
    typeInto(input, " /home/octo/app ");
    expect(queryButton("Continue")?.disabled).toBe(false);
    await act(async () => {
      input?.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });
    await settle();

    expect(mocked.selectRepository).toHaveBeenCalledWith("/home/octo/app");
    expect(setRepo).toHaveBeenCalledWith(selected);
  });

  it("keeps the screen when the folder picker is cancelled", async () => {
    mocked.browseRepository.mockResolvedValueOnce({ selected: false });
    const setRepo = renderSelect();
    await act(async () => queryButton("Browse")?.click());
    await settle();
    expect(setRepo).not.toHaveBeenCalled();
  });

  it("shows a failed selection as a display error", async () => {
    mocked.selectRepository.mockRejectedValueOnce(new Error("EACCES /secret/path"));
    renderSelect();
    typeInto(container.querySelector<HTMLInputElement>("input"), "/x");
    await act(async () => queryButton("Continue")?.click());
    await settle();
    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("EACCES");
  });
});

describe("RepositorySetup", () => {
  it("shows the command for a folder without Git and checks again", async () => {
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="git" />, { reloadRepo })));
    expect(container.querySelector("pre")?.textContent).toBe("git init");

    await act(async () => queryButton("Check again")?.click());
    await settle();
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("asks for a GitHub remote instead of creating a repository", () => {
    act(() => root.render(withSession(<RepositorySetup step="remote" />)));
    expect(container.textContent).toContain("Add a GitHub remote");
    expect(container.querySelector("pre")?.textContent).toContain("git remote add origin");
    expect(queryButton("Create repository")).toBeNull();
  });

  it("initializes enbu and reloads the repository", async () => {
    mocked.initialize.mockResolvedValueOnce({
      public_key: "age1test",
      username: "octo",
      environment: "default",
      device_id: "d".repeat(64),
      fingerprint: "aaaa-bbbb",
      pending: false,
    });
    const reloadRepo = vi.fn(async () => {});
    act(() => {
      root.render(<>{withSession(<RepositorySetup step="enbu" />, { reloadRepo })}</>);
    });
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenCalledTimes(1);
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });
});
