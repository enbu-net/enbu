import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { AppError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { I18nProvider } from "../../lib/i18n";
import { openURL } from "../../lib/platform";
import type { RepoInfo } from "../../lib/types";
import { container, queryButton, root, settle, setupDom, typeInto } from "../../test/dom";
import { Dashboard } from "./dashboard";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));
vi.mock("../../lib/platform", () => ({
  openURL: vi.fn(),
  onProgress: () => () => {},
}));

setupDom();

const mocked = vi.mocked(backend);

const repo = (overrides: Partial<RepoInfo> = {}): RepoInfo => ({
  path: "/a",
  owner: "acme",
  repo: "a",
  initialized: true,
  has_git: true,
  has_remote: true,
  storage_configured: true,
  ...overrides,
});

async function renderDashboard(info = repo()) {
  await act(async () => {
    root.render(
      <I18nProvider>
        <Dashboard repo={info} />
      </I18nProvider>,
    );
  });
  await settle();
}

describe("Dashboard", () => {
  beforeEach(() => {
    mocked.listEnvironments.mockResolvedValue([{ name: "default", current: true }]);
    mocked.listSecrets.mockResolvedValue({
      environment: "default",
      secrets: [{ key: "KEY", value: "value" }],
    });
  });

  it("opens the GitHub repository from its title", async () => {
    await renderDashboard();
    expect(container.querySelector("h1")?.textContent).toContain("acme/a");
    act(() => queryButton("acme/a")?.click());
    expect(openURL).toHaveBeenCalledWith("https://github.com/acme/a");
  });

  it("names a repository without a GitHub remote by its folder", async () => {
    await renderDashboard(repo({ path: "/work/s3-team", owner: "", repo: "" }));
    expect(container.querySelector("h1")?.textContent).toBe("s3-team");
  });

  it("adds a secret on Enter and clears the form", async () => {
    await renderDashboard();
    const key = container.querySelector<HTMLInputElement>('input[aria-label="Key"]');
    typeInto(key, "NEW");
    typeInto(container.querySelector<HTMLInputElement>('input[aria-label="Value"]'), "v");
    vi.useFakeTimers();
    await act(async () => {
      key?.form?.requestSubmit();
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(mocked.addSecret).toHaveBeenCalledWith("NEW", "v", "default");
    expect(key?.value).toBe("");
  });

  it("shows a workspace that cannot load as a display error", async () => {
    mocked.listEnvironments.mockRejectedValueOnce(new Error("token=secret"));
    await renderDashboard();
    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("token=secret");
  });

  it("trims duplicate keys before validation and does not call the backend", async () => {
    mocked.addSecret.mockClear();
    await renderDashboard();

    typeInto(container.querySelector<HTMLInputElement>('input[aria-label="Key"]'), " KEY ");
    act(() => queryButton("Add")?.click());

    expect(mocked.addSecret).not.toHaveBeenCalled();
    expect(container.textContent).toContain('Secret "KEY" already exists.');
  });

  it("asks for a value when concurrent edits conflict, then shows the resolved secrets", async () => {
    mocked.listSecrets.mockRejectedValueOnce(
      new AppError({ code: "secret_conflict", params: { keys: "KEY" } }),
    );
    const set = {
      environment: "default",
      heads: ["h1", "h2"],
      conflicts: [
        {
          key: "KEY",
          candidates: [
            { value: "alice", deleted: false },
            { value: "bob", deleted: false },
          ],
        },
      ],
    };
    mocked.listConflicts.mockResolvedValueOnce(set);
    mocked.resolveConflicts.mockResolvedValueOnce(undefined);
    await renderDashboard();

    expect(container.textContent).toContain("Choose a value");
    expect(container.textContent).not.toContain("Secrets changed");
    const bob = container.querySelectorAll<HTMLInputElement>('[data-conflict-key="KEY"] input')[1];
    act(() => bob?.click());
    await act(async () => {
      queryButton("Use these values")?.click();
      for (let i = 0; i < 6; i++) await Promise.resolve();
    });

    expect(mocked.resolveConflicts).toHaveBeenCalledWith(
      "default",
      ["h1", "h2"],
      [{ key: "KEY", value: "bob", delete: false }],
    );
    expect(container.textContent).not.toContain("Choose a value");
    expect(container.querySelector('input[aria-label="Value: KEY"]')).not.toBeNull();
  });

  it("asks before overwriting an output file it cannot read, then reports what it kept", async () => {
    mocked.pullSecrets.mockReset();
    mocked.pullSecrets
      .mockRejectedValueOnce(new AppError({ code: "output_unreadable", params: { file: ".env" } }))
      .mockResolvedValueOnce({ output: ".env", count: 1, kept: ["LOCAL"], removed: [] });
    await renderDashboard();
    vi.useFakeTimers();

    await act(async () => {
      queryButton("Pull")?.click();
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(mocked.pullSecrets).toHaveBeenLastCalledWith("default", false);
    expect(container.querySelector('[role="dialog"]')?.textContent).toContain("Overwrite .env?");

    await act(async () => {
      queryButton("Overwrite: Overwrite .env?")?.click();
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(mocked.pullSecrets).toHaveBeenLastCalledWith("default", true);
    expect(container.querySelector('[role="dialog"]')).toBeNull();
    expect(container.textContent).toContain("Kept local variables enbu does not store: LOCAL");
  });

  it("keeps the secret rows mounted while a refresh runs", async () => {
    await renderDashboard();
    const row = container.querySelector('input[aria-label="Value: KEY"]');
    expect(row).not.toBeNull();

    mocked.pullSecrets.mockResolvedValueOnce({ output: ".env", count: 1, kept: [], removed: [] });
    mocked.listEnvironments.mockClear();
    mocked.listEnvironments.mockImplementationOnce(() => new Promise(() => {}));
    await act(async () => queryButton("Pull")?.click());
    await settle();
    expect(mocked.listEnvironments).toHaveBeenCalledTimes(1);

    expect(container.querySelector('input[aria-label="Value: KEY"]')).toBe(row);
  });
});
