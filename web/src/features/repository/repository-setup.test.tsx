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
import { RepositoryOwnerSelect } from "./repository-owner-select";
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

describe("RepositoryOwnerSelect", () => {
  it("renders personal and organization owners and reports the selection", async () => {
    const onChange = vi.fn();
    act(() => {
      root.render(
        <>
          <RepositoryOwnerSelect
            owners={[
              { login: "octo", organization: false },
              { login: "octo-org", organization: true },
            ]}
            value="octo"
            loading={false}
            onChange={onChange}
          />
        </>,
      );
    });

    const trigger = container.querySelector<HTMLButtonElement>("#repository-owner");
    expect(trigger?.textContent).toContain("octo");
    expect(trigger?.textContent).toContain("Personal account");
    await act(async () => {
      trigger?.click();
      await Promise.resolve();
    });
    const organizationOption = Array.from(
      document.querySelectorAll<HTMLButtonElement>("button"),
    ).find((button) => button.textContent?.includes("octo-org"));
    expect(organizationOption?.textContent).toContain("Organization");
    await act(async () => {
      organizationOption?.click();
      await Promise.resolve();
    });
    expect(onChange).toHaveBeenCalledWith("octo-org");
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
  it("preselects the signed-in account as the new repository's owner", async () => {
    mocked.listRepositoryOwners.mockResolvedValueOnce([
      { login: "octo-org", organization: true },
      { login: "octo", organization: false },
    ]);
    const created = { selected: true, repo: repoInfo({ has_git: true, has_remote: true }) };
    mocked.gitCreateRemote.mockResolvedValueOnce(created);
    const setRepo = vi.fn();
    await act(async () => {
      root.render(
        <>
          {withSession(<RepositorySetup repo={repoInfo({ has_git: true })} step="remote" />, {
            status: { authenticated: true, workspace_configured: false, username: "octo" },
            setRepo,
          })}
        </>,
      );
    });
    await settle();

    expect(container.querySelector("#repository-owner")?.textContent).toContain("octo");
    expect(
      container.querySelector<HTMLInputElement>('input[aria-label="Repository name"]')?.value,
    ).toBe("app");
    await act(async () => queryButton("Create repository")?.click());
    await settle();
    expect(mocked.gitCreateRemote).toHaveBeenCalledWith("/home/octo/app", "octo", "app", true);
    expect(setRepo).toHaveBeenCalledWith(created);
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
      root.render(
        <>
          {withSession(
            <RepositorySetup repo={repoInfo({ has_git: true, has_remote: true })} step="enbu" />,
            { reloadRepo },
          )}
        </>,
      );
    });
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(mocked.initialize).toHaveBeenCalledTimes(1);
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });
});
