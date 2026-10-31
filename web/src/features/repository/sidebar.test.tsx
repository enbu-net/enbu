import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { RepoInfo } from "../../lib/types";
import { container, queryButton, root, settle, setupDom, withSession } from "../../test/dom";
import { RepositoryContextMenu, Sidebar } from "./sidebar";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

function repoInfo(path: string, owner = "", repo = ""): RepoInfo {
  return {
    path,
    owner,
    repo,
    initialized: true,
    has_git: true,
    has_remote: true,
    storage_configured: true,
  };
}

describe("RepositoryContextMenu", () => {
  it("removes a repository from the right-click menu", () => {
    const onRemove = vi.fn();
    act(() => {
      root.render(
        <>
          <RepositoryContextMenu x={20} y={30} removing={false} onRemove={onRemove} />
        </>,
      );
    });
    const menu = container.querySelector<HTMLElement>('[role="menu"]');
    expect(menu).toBeTruthy();
    expect(menu?.style.left).toBe("20px");
    expect(menu?.style.top).toBe("30px");
    act(() => {
      queryButton("Remove")?.click();
    });
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it("removes the final repository after confirmation", async () => {
    let repositories = [repoInfo("C:\\repo", "enbu-net", "test")];
    const backendMock = vi.mocked(backend);
    backendMock.listRepositories.mockImplementation(async () => repositories);
    backendMock.removeRepository.mockImplementation(async () => {
      repositories = [];
    });
    await act(async () => {
      root.render(
        <>{withSession(<Sidebar />, { repo: { selected: true, repo: repoInfo("C:\\repo") } })}</>,
      );
      await Promise.resolve();
      await Promise.resolve();
    });

    const repositoryRow = container.querySelector<HTMLElement>("[data-repository-path]");
    expect(repositoryRow).toBeTruthy();
    expect(repositoryRow?.dataset.repositoryPath).toBe("C:\\repo");
    act(() => {
      repositoryRow?.dispatchEvent(
        new MouseEvent("contextmenu", { bubbles: true, clientX: 20, clientY: 20 }),
      );
    });
    const menu = container.querySelector<HTMLElement>('[role="menu"]');
    expect(menu).toBeTruthy();
    expect(menu?.style.left).toBe("20px");
    expect(menu?.style.top).toBe("20px");
    act(() => {
      queryButton("Remove")?.click();
    });
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).toBeTruthy();
    expect(dialog?.textContent).toContain("Remove enbu-net/test from enbu?");
    await act(async () => {
      dialog?.querySelector<HTMLButtonElement>('button[aria-label^="Remove:"]')?.click();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(container.textContent).not.toContain("enbu-net/test");
    expect(container.textContent).toContain("No repositories yet.");
  });
});

describe("accessibility: sidebar keyboard", () => {
  it("sidebar repo items have role=button and tabIndex", async () => {
    vi.mocked(backend).listRepositories.mockResolvedValue([repoInfo("/a", "acme", "app")]);
    act(() => {
      root.render(
        <>{withSession(<Sidebar />, { repo: { selected: true, repo: repoInfo("/b") } })}</>,
      );
    });
    await act(async () => {});
    const items = container.querySelectorAll('[role="button"]');
    expect(items.length).toBeGreaterThan(0);
    const item = items[0] as HTMLElement;
    expect(item.getAttribute("tabindex")).toBe("0");
    const selectRepository = vi.mocked(backend).selectRepository;
    selectRepository.mockClear();
    await act(async () => {
      item.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      await Promise.resolve();
    });
    expect(selectRepository).toHaveBeenLastCalledWith("/a");
    selectRepository.mockClear();
    await act(async () => {
      item.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
      await Promise.resolve();
    });
    expect(selectRepository).toHaveBeenLastCalledWith("/a");
  });
});

describe("Sidebar", () => {
  it("shows why the repository list could not load", async () => {
    vi.mocked(backend).listRepositories.mockRejectedValueOnce(new Error("disk unavailable"));
    await act(async () => {
      root.render(<>{withSession(<Sidebar />)}</>);
    });
    await settle();
    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("disk unavailable");
  });

  it("marks the active repository and switches to another one", async () => {
    const setRepo = vi.fn();
    const next = { selected: true, repo: repoInfo("/a", "acme", "app") };
    vi.mocked(backend).listRepositories.mockResolvedValue([
      repoInfo("/a", "acme", "app"),
      repoInfo("/b", "acme", "api"),
    ]);
    vi.mocked(backend).selectRepository.mockResolvedValueOnce(next);
    await act(async () => {
      root.render(
        <>
          {withSession(<Sidebar />, { repo: { selected: true, repo: repoInfo("/b") }, setRepo })}
        </>,
      );
    });
    await settle();
    const active = container.querySelector('[aria-current="true"]');
    expect(active?.getAttribute("data-repository-path")).toBe("/b");
    await act(async () => {
      container.querySelector<HTMLElement>('[data-repository-path="/a"]')?.click();
    });
    await settle();
    expect(setRepo).toHaveBeenCalledWith(next);
  });
});
