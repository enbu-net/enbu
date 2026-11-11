import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { Session } from "../../lib/session";
import { noRepo, type RepoInfo } from "../../lib/types";
import {
  container,
  labelledInput,
  queryButton,
  root,
  settle,
  setupDom,
  submitForm,
  typeInto,
  withSession,
} from "../../test/dom";
import { Welcome } from "./welcome";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));
vi.mock("../../lib/platform", () => ({
  openURL: vi.fn(),
  onProgress: () => () => {},
}));

setupDom();

const mocked = vi.mocked(backend);

function repoInfo(overrides: Partial<RepoInfo> = {}): RepoInfo {
  return {
    path: "/home/octo/app",
    owner: "octo",
    repo: "app",
    initialized: true,
    has_git: true,
    has_remote: true,
    storage_configured: true,
    ...overrides,
  };
}

async function renderWelcome(session: Partial<Session> = {}) {
  const setRepo = vi.fn();
  await act(async () => {
    root.render(
      <>
        {withSession(<Welcome />, {
          status: { authenticated: false, workspace_configured: false },
          setRepo,
          ...session,
        })}
      </>,
    );
  });
  await settle();
  return setRepo;
}

function steps() {
  return Array.from(container.querySelectorAll("details"));
}

describe("Welcome", () => {
  beforeEach(() => {
    mocked.ListRepositories.mockReset();
    mocked.ListRepositories.mockResolvedValue([]);
    mocked.SelectRepository.mockReset();
    mocked.BrowseRepository.mockReset();
  });

  it("titles the screen with h1 and names each section with h2", async () => {
    await renderWelcome();
    expect(container.querySelector("h1")?.textContent).toBe("enbu");
    const sections = Array.from(container.querySelectorAll("section h2")).map((h) => h.textContent);
    expect(sections).toEqual(["Start", "Recent", "Getting started"]);
    for (const section of container.querySelectorAll("section")) {
      const id = section.getAttribute("aria-labelledby");
      expect(id && section.querySelector(`h2[id="${id}"]`)).toBeTruthy();
    }
  });

  it("opens the folder the picker returns", async () => {
    const chosen = repoInfo();
    mocked.BrowseRepository.mockResolvedValueOnce(chosen);
    const setRepo = await renderWelcome();
    await act(async () => queryButton("Open folder…")?.click());
    await settle();
    expect(setRepo).toHaveBeenCalledWith(chosen);
  });

  it("stays when the folder picker is cancelled", async () => {
    mocked.BrowseRepository.mockResolvedValueOnce(noRepo);
    const setRepo = await renderWelcome();
    await act(async () => queryButton("Open folder…")?.click());
    await settle();
    expect(setRepo).not.toHaveBeenCalled();
  });

  it("shows the path field only when asked, and opens the typed path on Enter", async () => {
    const chosen = repoInfo();
    mocked.SelectRepository.mockResolvedValueOnce(chosen);
    const setRepo = await renderWelcome();
    expect(labelledInput("Repository folder")).toBeNull();

    act(() => queryButton("Enter a path…")?.click());
    const input = labelledInput("Repository folder");
    expect(document.activeElement).toBe(input);
    expect(input?.placeholder).toBe("C:\\Users\\you\\src\\your-repo");
    expect(queryButton("Continue")?.disabled).toBe(true);
    typeInto(input, " /home/octo/app ");
    await act(async () => submitForm(input));
    await settle();

    expect(mocked.SelectRepository).toHaveBeenCalledWith("/home/octo/app");
    expect(setRepo).toHaveBeenCalledWith(chosen);
  });

  it("shows a failed selection as a display error", async () => {
    mocked.SelectRepository.mockRejectedValueOnce(new Error("EACCES /secret/path"));
    await renderWelcome();
    act(() => queryButton("Enter a path…")?.click());
    typeInto(labelledInput("Repository folder"), "/x");
    await act(async () => queryButton("Continue")?.click());
    await settle();
    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("EACCES");
  });

  it("lists the repositories opened before and opens one", async () => {
    const other = repoInfo({ path: "/home/octo/other", owner: "", repo: "" });
    mocked.ListRepositories.mockResolvedValueOnce([repoInfo(), other]);
    mocked.SelectRepository.mockResolvedValueOnce(other);
    const setRepo = await renderWelcome();

    expect(queryButton("octo/app")?.textContent).toContain("/home/octo/app");
    await act(async () => queryButton("other")?.click());
    await settle();
    expect(mocked.SelectRepository).toHaveBeenCalledWith("/home/octo/other");
    expect(setRepo).toHaveBeenCalledWith(other);
  });

  it("says where opened repositories appear when there are none", async () => {
    await renderWelcome();
    expect(container.textContent).toContain("Repositories you open appear here.");
  });

  it("starts the walkthrough at sign-in and offers it", async () => {
    await renderWelcome();
    expect(steps().map((step) => step.querySelector("summary")?.textContent)).toEqual([
      "Sign in to GitHub",
      "Open your repository",
      "Create or join the workspace",
      "Get approved",
    ]);
    expect(steps().map((step) => step.open)).toEqual([true, false, false, false]);
    expect(queryButton("Connect with GitHub", steps()[0])).toBeTruthy();
  });

  it("marks sign-in done and opens the next step once signed in", async () => {
    await renderWelcome({
      status: { authenticated: true, workspace_configured: false, username: "octo" },
    });
    expect(steps()[0].querySelector("summary")?.textContent).toBe("Sign in to GitHub (done)");
    expect(steps()[0].textContent).toContain("Signed in as octo.");
    expect(queryButton("Connect with GitHub")).toBeNull();
    expect(steps().map((step) => step.open)).toEqual([false, true, false, false]);
  });

  it("tells a joiner to pass the fingerprint over another channel", async () => {
    await renderWelcome();
    expect(steps()[3].textContent).toContain("over another channel");
  });

  it("shows the browser step of the sign-in in place of the welcome", async () => {
    mocked.StartOAuthLogin.mockResolvedValueOnce({
      session_id: "session",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    await renderWelcome();
    await act(async () => queryButton("Connect with GitHub")?.click());
    await settle();
    expect(container.querySelector("h1")?.textContent).toBe("GitHub Login");
  });
});
