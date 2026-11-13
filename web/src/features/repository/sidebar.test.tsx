import { defaultSettings, getSettings, loadSettings, updateSettings } from "../../lib/settings";
import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { RepoInfo } from "../../lib/types";
import {
  container,
  openDialog,
  queryButton,
  root,
  settle,
  setupDom,
  withSession,
} from "../../test/dom";
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
    has_remote: true,
    storage_configured: true,
  };
}

describe("sidebar resizing", () => {
  it("keeps room for the content when a saved sidebar width is wider than a half-screen window", async () => {
    const originalWidth = window.innerWidth;
    try {
      updateSettings({ sidebarWidth: 420 });
      Object.defineProperty(window, "innerWidth", { configurable: true, value: 800 });
      act(() => root.render(withSession(<Sidebar />)));
      await settle();
      const sidebar = container.querySelector<HTMLElement>("#repository-sidebar")!;
      expect(sidebar.style.width).toBe("280px");
      expect(container.querySelector('[role="separator"]')?.getAttribute("aria-valuenow")).toBe(
        "280",
      );
      expect(getSettings().sidebarWidth).toBe(420);
    } finally {
      Object.defineProperty(window, "innerWidth", { configurable: true, value: originalWidth });
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
    }
  });

  it("resizes with the keyboard, clamps the range and persists the width", async () => {
    loadSettings();
    act(() => root.render(withSession(<Sidebar />)));
    await settle();
    const handle = container.querySelector<HTMLElement>('[role="separator"]')!;
    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
    });
    expect(getSettings().sidebarWidth).toBe(defaultSettings.sidebarWidth + 10);
    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { key: "End", bubbles: true }));
    });
    expect(handle.getAttribute("aria-valuenow")).toBe("420");
    act(() => {
      handle.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
    });
    expect(getSettings().sidebarWidth).toBe(420);
    act(() => {
      handle.dispatchEvent(new MouseEvent("dblclick", { bubbles: true }));
    });
    expect(getSettings().sidebarWidth).toBe(defaultSettings.sidebarWidth);
  });
  it("drags the edge and releases pointer capture", async () => {
    loadSettings();
    act(() => root.render(withSession(<Sidebar />)));
    await settle();
    const handle = container.querySelector<HTMLElement>('[role="separator"]')!;
    let captured = false;
    handle.setPointerCapture = () => {
      captured = true;
    };
    handle.hasPointerCapture = () => captured;
    handle.releasePointerCapture = () => {
      captured = false;
    };
    const dispatch = (type: string, x: number) => {
      const event = new Event(type, { bubbles: true });
      Object.assign(event, { pointerId: 1, button: 0, clientX: x });
      act(() => {
        handle.dispatchEvent(event);
      });
    };
    dispatch("pointerdown", 248);
    dispatch("pointermove", 340);
    expect(getSettings().sidebarWidth).toBe(340);
    dispatch("pointerup", 340);
    dispatch("pointermove", 400);
    expect(getSettings().sidebarWidth).toBe(340);
    expect(captured).toBe(false);
  });
});

describe("RepositoryContextMenu", () => {
  it("keeps the menu through the opening button release and dismisses on the next outside press", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([repoInfo("/a", "acme", "app")]);
    await act(async () => root.render(withSession(<Sidebar />)));
    const row = container.querySelector<HTMLButtonElement>("button[data-repository-path]");
    act(() => {
      row?.dispatchEvent(
        new MouseEvent("contextmenu", { bubbles: true, clientX: 20, clientY: 20 }),
      );
    });
    const menu = container.querySelector<HTMLElement>("[popover]");
    expect(menu?.getAttribute("popover")).toBe("manual");
    act(() => {
      document.body.dispatchEvent(new Event("pointerup", { bubbles: true }));
    });
    expect(menu?.dataset.popoverOpen).toBe("true");
    act(() => {
      document.body.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    });
    expect(container.querySelector("[popover]")).toBeNull();
  });

  it("opens a fresh menu when right-clicking another repository", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([repoInfo("/a"), repoInfo("/b")]);
    await act(async () => root.render(withSession(<Sidebar />)));
    const rows = container.querySelectorAll<HTMLButtonElement>("button[data-repository-path]");
    act(() => {
      rows[0].dispatchEvent(
        new MouseEvent("contextmenu", { bubbles: true, clientX: 20, clientY: 20 }),
      );
    });
    const first = container.querySelector<HTMLElement>("[popover]");
    act(() => {
      rows[1].dispatchEvent(
        new MouseEvent("contextmenu", { bubbles: true, clientX: 40, clientY: 40 }),
      );
    });
    const second = container.querySelector<HTMLElement>("[popover]");
    expect(second).not.toBe(first);
    expect(second?.dataset.popoverOpen).toBe("true");
    expect(second?.style.left).toBe("40px");
  });

  it("removes a repository from the right-click menu", () => {
    const onRemove = vi.fn();
    act(() => {
      root.render(
        <>
          <RepositoryContextMenu x={20} y={30} removing={false} onRemove={onRemove} />
        </>,
      );
    });
    const menu = container.querySelector<HTMLElement>("[popover]");
    expect(menu?.dataset.popoverOpen).toBe("true");
    expect(menu?.getAttribute("aria-label")).toBe("Repository options");
    expect(menu?.style.left).toBe("20px");
    expect(menu?.style.top).toBe("30px");
    // Focus moves into the menu, so the keyboard can use it at once.
    expect(document.activeElement?.textContent).toContain("Remove");
    act(() => {
      queryButton("Remove")?.click();
    });
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it("removes the final repository after confirmation", async () => {
    let repositories = [repoInfo("C:\\repo", "enbu-net", "test")];
    const backendMock = vi.mocked(backend);
    backendMock.ListRepositories.mockImplementation(async () => repositories);
    backendMock.RemoveRepository.mockImplementation(async () => {
      repositories = [];
    });
    await act(async () => {
      root.render(<>{withSession(<Sidebar />, { repo: repoInfo("C:\\repo") })}</>);
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
    const menu = container.querySelector<HTMLElement>("[popover]");
    expect(menu?.dataset.popoverOpen).toBe("true");
    expect(menu?.style.left).toBe("20px");
    expect(menu?.style.top).toBe("20px");
    act(() => {
      queryButton("Remove")?.click();
    });
    const dialog = openDialog();
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

describe("sidebar paths", () => {
  it("lists Japanese paths, and keeps repositories that differ only in letter case", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([
      repoInfo("/home/山田 太郎/マイ リポジトリ"),
      repoInfo("/srv/App"),
      repoInfo("/srv/app"),
    ]);
    act(() => {
      root.render(
        <>{withSession(<Sidebar />, { repo: repoInfo("/home/山田 太郎/マイ リポジトリ") })}</>,
      );
    });
    await act(async () => {});
    const rows = container.querySelectorAll<HTMLButtonElement>("button[data-repository-path]");
    expect([...rows].map((row) => row.dataset.repositoryPath)).toEqual([
      "/home/山田 太郎/マイ リポジトリ",
      "/srv/App",
      "/srv/app",
    ]);
    expect(rows[0].getAttribute("aria-current")).toBe("true");
    expect(rows[0].textContent).toContain("/home/山田 太郎/マイ リポジトリ");
  });
});

describe("accessibility: sidebar keyboard", () => {
  it("lists repositories as buttons, the current one marked", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([
      repoInfo("/a", "acme", "app"),
      repoInfo("/b", "acme", "web"),
    ]);
    act(() => {
      root.render(<>{withSession(<Sidebar />, { repo: repoInfo("/b") })}</>);
    });
    await act(async () => {});
    const rows = container.querySelectorAll<HTMLButtonElement>("button[data-repository-path]");
    expect(rows).toHaveLength(2);
    expect(rows[0].getAttribute("aria-current")).toBeNull();
    expect(rows[1].getAttribute("aria-current")).toBe("true");
    const selectRepository = vi.mocked(backend).SelectRepository;
    selectRepository.mockClear();
    await act(async () => {
      rows[0].click();
      await Promise.resolve();
    });
    expect(selectRepository).toHaveBeenLastCalledWith("/a");
  });

  it("opens the menu from the keyboard below the focused repository", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([repoInfo("/a", "acme", "app")]);
    act(() => {
      root.render(<>{withSession(<Sidebar />)}</>);
    });
    await act(async () => {});
    const row = container.querySelector<HTMLButtonElement>("button[data-repository-path]");
    // The context menu key and Shift+F10 report no pointer position.
    act(() => {
      row?.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, clientX: 0, clientY: 0 }));
    });
    const menu = container.querySelector<HTMLElement>("[popover]");
    expect(menu?.dataset.popoverOpen).toBe("true");
    expect(menu?.style.left).toBe("16px");
    expect(document.activeElement?.textContent).toContain("Remove");

    // Escape closes the manual popover and returns focus to the row.
    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    expect(container.querySelector("[popover]")).toBeNull();
    expect(document.activeElement).toBe(row);
  });
});

describe("Sidebar", () => {
  it("closes the settings once an added repository is selected", async () => {
    const setRepo = vi.fn();
    const onCloseSettings = vi.fn();
    const next = repoInfo("/c", "acme", "web");
    vi.mocked(backend).ListRepositories.mockResolvedValue([]);
    vi.mocked(backend).BrowseRepository.mockResolvedValueOnce(next);
    await act(async () => {
      root.render(
        <>{withSession(<Sidebar settingsOpen onCloseSettings={onCloseSettings} />, { setRepo })}</>,
      );
    });
    await settle();
    await act(async () => {
      queryButton("Add repository")?.click();
    });
    await settle();
    expect(setRepo).toHaveBeenCalledWith(next);
    expect(onCloseSettings).toHaveBeenCalledTimes(1);
  });

  it("keeps adding a repository above the list and the settings below it", async () => {
    vi.mocked(backend).ListRepositories.mockResolvedValue([repoInfo("/a", "acme", "app")]);
    await act(async () => {
      root.render(<>{withSession(<Sidebar onOpenSettings={() => {}} />)}</>);
    });
    await settle();
    const nav = container.querySelector("nav");
    const order = Array.from(nav?.querySelectorAll("button, [data-repository-path]") ?? []).map(
      (node) => node.getAttribute("data-repository-path") ?? node.textContent,
    );
    expect(order).toEqual(["Add repository", "/a", "Settings"]);
    expect(nav?.querySelector("button svg")).toBeTruthy();
  });

  it("shows why the repository list could not load", async () => {
    vi.mocked(backend).ListRepositories.mockRejectedValueOnce(new Error("disk unavailable"));
    await act(async () => {
      root.render(<>{withSession(<Sidebar />)}</>);
    });
    await settle();
    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("disk unavailable");
  });

  it("marks the active repository and switches to another one", async () => {
    const setRepo = vi.fn();
    const next = repoInfo("/a", "acme", "app");
    vi.mocked(backend).ListRepositories.mockResolvedValue([
      repoInfo("/a", "acme", "app"),
      repoInfo("/b", "acme", "api"),
    ]);
    vi.mocked(backend).SelectRepository.mockResolvedValueOnce(next);
    await act(async () => {
      root.render(<>{withSession(<Sidebar />, { repo: repoInfo("/b"), setRepo })}</>);
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

  it("opens the settings from the bottom button", async () => {
    const onOpenSettings = vi.fn();
    await act(async () => {
      root.render(<>{withSession(<Sidebar onOpenSettings={onOpenSettings} />)}</>);
    });
    await settle();
    await act(async () => queryButton("Settings")?.click());
    expect(onOpenSettings).toHaveBeenCalledTimes(1);
  });

  it("leaves the settings through the repository in use without selecting it again", async () => {
    const onCloseSettings = vi.fn();
    vi.mocked(backend).ListRepositories.mockResolvedValue([repoInfo("/b", "acme", "api")]);
    vi.mocked(backend).SelectRepository.mockClear();
    await act(async () => {
      root.render(
        <>
          {withSession(<Sidebar settingsOpen onCloseSettings={onCloseSettings} />, {
            repo: repoInfo("/b"),
          })}
        </>,
      );
    });
    await settle();
    expect(queryButton("Settings")?.getAttribute("aria-current")).toBe("page");
    await act(async () => {
      container.querySelector<HTMLElement>('[data-repository-path="/b"]')?.click();
    });
    await settle();
    expect(backend.SelectRepository).not.toHaveBeenCalled();
    expect(onCloseSettings).toHaveBeenCalledTimes(1);
  });
});
