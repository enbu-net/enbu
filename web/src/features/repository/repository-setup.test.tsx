import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import type { InitResult, RepoInfo } from "../../lib/types";
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
  it("asks for Git, then founds a workspace", () => {
    expect(setupStep(repoInfo())).toBe("git");
    expect(setupStep(repoInfo({ has_git: true }))).toBe("found");
    expect(setupStep(repoInfo({ has_git: true, has_remote: true }))).toBe("found");
    expect(setupStep(repoInfo({ has_git: true, initialized: true }))).toBeNull();
  });

  it("joins the workspace enbu.toml already names", () => {
    expect(setupStep(repoInfo({ storage_configured: true }))).toBe("join");
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

  it("founds a workspace in the suggested storage and tells how to share it", async () => {
    mocked.suggestStorage.mockResolvedValueOnce("oci://ghcr.io/octo/app-enbu");
    mocked.initialize.mockResolvedValueOnce(
      initResult({ founded: true, storage: "oci://ghcr.io/octo/app-enbu" }),
    );
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="found" />, { reloadRepo })));
    await settle();
    expect(container.querySelector<HTMLInputElement>("#init-storage")?.value).toBe(
      "oci://ghcr.io/octo/app-enbu",
    );

    await act(async () => queryButton("Found workspace")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenCalledWith("oci://ghcr.io/octo/app-enbu", false);
    expect(container.textContent).toContain("Inherit access from repository");
    expect(container.textContent).toContain("app-enbu");
    expect(reloadRepo).not.toHaveBeenCalled();

    await act(async () => queryButton("Continue")?.click());
    await settle();
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("asks for a storage or a GitHub remote when there is no suggestion", async () => {
    act(() => root.render(withSession(<RepositorySetup step="found" />)));
    await settle();
    expect(container.querySelector("pre")?.textContent).toContain("git remote add origin");
    expect(queryButton("Found workspace")?.disabled).toBe(true);

    const input = container.querySelector<HTMLInputElement>("#init-storage")!;
    await act(async () => typeInto(input, "s3://bucket/team"));
    await act(async () => queryButton("Found workspace")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenCalledWith("s3://bucket/team", false);
  });

  it("joins the workspace in enbu.toml and reloads", async () => {
    mocked.initialize.mockResolvedValueOnce(initResult());
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="join" />, { reloadRepo })));
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenCalledWith("", false);
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("shows the fingerprint to compare while waiting for approval", async () => {
    mocked.initialize.mockResolvedValueOnce(initResult({ pending: true }));
    act(() => root.render(withSession(<RepositorySetup step="join" />)));
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(container.textContent).toContain("Waiting for approval");
    expect(container.textContent).toContain("aaaa-bbbb");
  });

  it("offers to trust a changed root only after trust_root_changed", async () => {
    mocked.initialize
      .mockRejectedValueOnce(createAppError("trust_root_changed"))
      .mockResolvedValueOnce(initResult({ replaced_genesis: "c-old" }));
    act(() => root.render(withSession(<RepositorySetup step="join" />)));
    expect(queryButton("Trust the new root")).toBeNull();
    await act(async () => queryButton("Set up")?.click());
    await settle();

    await act(async () => queryButton("Trust the new root")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenLastCalledWith("", true);
    expect(container.textContent).toContain("c-old");
  });
});

function initResult(overrides: Partial<InitResult> = {}): InitResult {
  return {
    public_key: "age1test",
    username: "octo",
    environment: "default",
    device_id: "d".repeat(64),
    fingerprint: "aaaa-bbbb",
    pending: false,
    storage: "oci://registry.example/team",
    founded: false,
    ...overrides,
  };
}
