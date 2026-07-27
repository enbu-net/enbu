import { describe, expect, it, vi, beforeEach, afterEach } from "vite-plus/test";
import { createRoot } from "react-dom/client";
import { act } from "react-dom/test-utils";
import { I18nProvider } from "../lib/i18n";
import { backend, openURL } from "../lib/backend";
import { AccountMenu, AuthContext, RepositoryContextMenu, Sidebar } from "./__root";
import {
  parseConfigDraft,
  CreateEnvironmentModal,
  EnvironmentSelector,
  HomePage,
  MemberAvatar,
  MemberRow,
  RepositoryOwnerSelect,
  RecipientsPanel,
  resolveWorkspaceEnvironment,
  SecretRow,
  serializeConfigDraft,
} from "./index";

const oauthMocks = vi.hoisted(() => ({
  start: vi.fn(),
  status: vi.fn(),
  cancel: vi.fn(),
  repoStatus: vi.fn(),
}));

vi.mock("../lib/backend", () => ({
  backend: {
    authStatus: vi.fn(async () => ({ authenticated: false })),
    startOAuthLogin: oauthMocks.start,
    oauthStatus: oauthMocks.status,
    cancelOAuthLogin: oauthMocks.cancel,
    logout: vi.fn(),
    repoStatus: oauthMocks.repoStatus,
    browseRepository: vi.fn(),
    selectRepository: vi.fn(),
    initialize: vi.fn(),
    listEnvironments: vi.fn(async () => []),
    listSecrets: vi.fn(async () => ({ environment: "default", secrets: [] })),
    addSecret: vi.fn(),
    editSecret: vi.fn(),
    deleteSecret: vi.fn(),
    pullSecrets: vi.fn(),
    exportSecrets: vi.fn(),
    syncSecrets: vi.fn(),
    listRepositories: vi.fn(async () => []),
    removeRepository: vi.fn(),
    listRecipients: vi.fn(async () => []),
    readConfig: vi.fn(async () => ""),
    writeConfig: vi.fn(),
    appVersion: vi.fn(async () => ""),
  },
  openURL: vi.fn(),
}));

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let clipboardWrite: ReturnType<typeof vi.fn>;

beforeEach(() => {
  localStorage.clear();
  class ResizeObserverMock {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Object.defineProperty(globalThis, "ResizeObserver", {
    configurable: true,
    value: ResizeObserverMock,
  });
  clipboardWrite = vi.fn(async () => {});
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: clipboardWrite },
  });
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.useRealTimers();
});

function renderUnauthenticatedHome() {
  act(() => {
    root.render(
      <I18nProvider>
        <AuthContext.Provider
          value={{
            status: { authenticated: false },
            loading: false,
            repoPath: "",
            refresh: async () => {},
          }}
        >
          <HomePage />
        </AuthContext.Provider>
      </I18nProvider>,
    );
  });
}

function renderAuthenticatedHome() {
  act(() => {
    root.render(
      <I18nProvider>
        <AuthContext.Provider
          value={{
            status: { authenticated: true, username: "u" },
            loading: false,
            repoPath: "",
            refresh: async () => {},
          }}
        >
          <HomePage />
        </AuthContext.Provider>
      </I18nProvider>,
    );
  });
}

function renderSecretRow(props: {
  secretKey: string;
  secretValue: string;
  onEdit?: (val: string) => Promise<void>;
  onDelete?: () => Promise<void>;
  deleteLabel?: string;
}) {
  act(() => {
    root.render(
      <I18nProvider>
        <SecretRow
          secretKey={props.secretKey}
          secretValue={props.secretValue}
          onEdit={props.onEdit ?? (async () => {})}
          onDelete={props.onDelete ?? (async () => {})}
          deleteLabel={props.deleteLabel ?? "Delete"}
        />
      </I18nProvider>,
    );
  });
}

function queryInput(value: string): HTMLInputElement | null {
  return (
    Array.from(container.querySelectorAll<HTMLInputElement>("input")).find(
      (el) => el.value === value || el.defaultValue === value,
    ) ?? null
  );
}

function queryButton(label: string): HTMLButtonElement | null {
  return (
    Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
      (b) => b.textContent?.includes(label) || b.getAttribute("aria-label") === label,
    ) ?? null
  );
}

describe("OAuth login", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    oauthMocks.start.mockReset();
    oauthMocks.status.mockReset();
    oauthMocks.cancel.mockReset();
    oauthMocks.repoStatus.mockReset();
    oauthMocks.start.mockResolvedValue({
      session_id: "session",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    oauthMocks.cancel.mockResolvedValue(undefined);
    oauthMocks.repoStatus.mockResolvedValue({ selected: false });
  });

  it("shows the login action and language selector without a redundant heading", () => {
    renderUnauthenticatedHome();

    expect(queryButton("Connect with GitHub")).toBeTruthy();
    expect(container.textContent).not.toContain("Sign in to GitHub");
    expect(container.querySelector("select")?.value).toBe("en");
  });

  it("shows the Japanese authentication label after selecting Japanese", () => {
    renderUnauthenticatedHome();

    const language = container.querySelector("select");
    expect(language).toBeTruthy();
    act(() => {
      if (!language) return;
      language.value = "ja";
      language.dispatchEvent(new Event("change", { bubbles: true }));
    });

    expect(queryButton("GitHub認証")).toBeTruthy();
  });

  it("clears the OAuth panel even when repository refresh fails", async () => {
    oauthMocks.status.mockResolvedValue({ state: "success", username: "octo" });
    oauthMocks.repoStatus.mockRejectedValue(new Error("refresh failed"));
    renderUnauthenticatedHome();

    await act(async () => {
      queryButton("Connect with GitHub")?.click();
      await Promise.resolve();
    });
    await act(async () => vi.advanceTimersByTimeAsync(1000));

    expect(oauthMocks.status).toHaveBeenCalledWith("session");
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });

  it("shows a terminal error when OAuth status polling rejects", async () => {
    oauthMocks.status.mockRejectedValue(new Error("poll failed"));
    renderUnauthenticatedHome();

    await act(async () => {
      queryButton("Connect with GitHub")?.click();
      await Promise.resolve();
    });
    await act(async () => vi.advanceTimersByTimeAsync(1000));

    expect(container.textContent).toContain("poll failed");
    expect(queryButton("Try again")).toBeTruthy();
  });

  it("cancels and resets a pending OAuth login", async () => {
    oauthMocks.status.mockResolvedValue({ state: "pending" });
    renderUnauthenticatedHome();

    await act(async () => {
      queryButton("Connect with GitHub")?.click();
      await Promise.resolve();
    });
    await act(async () => {
      queryButton("Cancel")?.click();
      await Promise.resolve();
    });

    expect(oauthMocks.cancel).toHaveBeenCalledWith("session");
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });
});

describe("AccountMenu", () => {
  it("does not show another GitHub connect action when signed out", async () => {
    act(() => {
      root.render(
        <I18nProvider>
          <AccountMenu status={{ authenticated: false }} loading={false} />
        </I18nProvider>,
      );
    });

    await act(async () => queryButton("Account menu")?.click());

    expect(document.body.textContent).toContain("Language");
    expect(document.body.textContent).not.toContain("Connect GitHub");
  });
});

describe("SecretRow", () => {
  it("renders value input as password by default", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    expect(queryInput("super-secret")?.type).toBe("password");
  });

  it("toggles to text type on eye button click", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    act(() => {
      queryButton("Show value")?.click();
    });
    expect(queryInput("super-secret")?.type).toBe("text");
    expect(queryButton("Hide value")).toBeTruthy();
  });

  it("toggles back to password on second click", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    act(() => {
      queryButton("Show value")?.click();
    });
    act(() => {
      queryButton("Hide value")?.click();
    });
    expect(queryInput("super-secret")?.type).toBe("password");
  });

  it("asks for confirmation before deleting", async () => {
    const onDelete = vi.fn(async () => {});
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret", onDelete });
    act(() => {
      queryButton("Delete")?.click();
    });
    expect(onDelete).not.toHaveBeenCalled();
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain("Delete API_KEY?");
    await act(async () => {
      dialog?.querySelector<HTMLButtonElement>('button[aria-label^="Delete:"]')?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("copies the secret key and value independently", async () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    await act(async () => {
      queryButton("Copy key")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("API_KEY");
    expect(queryButton("Key copied")).toBeTruthy();

    await act(async () => {
      queryButton("Copy value")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("super-secret");
    expect(queryButton("Value copied")).toBeTruthy();
  });

  it("renders the secret key as a monospace label", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    expect(container.textContent).toContain("API_KEY");
  });

  it("renders the value input at all viewport sizes (not hidden)", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    const valueInput = queryInput("super-secret");
    expect(valueInput).toBeTruthy();
    // The input must not carry display:none — it was previously hidden on mobile
    expect(valueInput?.style.display).not.toBe("none");
  });

  it("value input has correct aria-label linking it to its key", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    const valueInput = container.querySelector<HTMLInputElement>(
      'input[aria-label="Value: API_KEY"]',
    );
    expect(valueInput).toBeTruthy();
  });
});

describe("RepositoryContextMenu", () => {
  it("removes a repository from the right-click menu", () => {
    const onRemove = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <RepositoryContextMenu x={20} y={30} removing={false} onRemove={onRemove} />
        </I18nProvider>,
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
    let repositories = [{ path: "C:\\repo", owner: "enbu-net", repo: "test", initialized: true }];
    const backendMock = vi.mocked(backend);
    backendMock.listRepositories.mockImplementation(async () => repositories);
    backendMock.removeRepository.mockImplementation(async () => {
      repositories = [];
    });
    await act(async () => {
      root.render(
        <I18nProvider>
          <Sidebar activePath="C:\\repo" />
        </I18nProvider>,
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

describe("enbu config editor", () => {
  it("hydrates missing environment output defaults for the GUI", () => {
    expect(
      parseConfigDraft('version = "v1alpha1"\ndefault_env = "development"\n', [
        { name: "development", current: true },
        { name: "production", current: false },
      ]),
    ).toEqual({
      version: "v1alpha1",
      default_env: "development",
      env: {
        development: { output: ".env.development" },
        production: { output: ".env.production" },
      },
    });
  });

  it("serializes GUI edits as valid canonical TOML", () => {
    const text = serializeConfigDraft({
      version: "v1alpha1",
      default_env: "staging",
      env: { staging: { output: ".env.staging" } },
    });
    expect(text).toBe(
      'version = "v1alpha1"\ndefault_env = "staging"\n\n[env.staging]\noutput = ".env.staging"\n',
    );
    expect(text).not.toContain("[env]\n");
    expect(parseConfigDraft(text, [])).toMatchObject({ default_env: "staging" });
  });

  it("rejects invalid TOML before entering the GUI", () => {
    expect(() => parseConfigDraft('version = "v1alpha1', [])).toThrow();
  });
});

describe("MemberAvatar", () => {
  it("uses the GitHub avatar and keeps initials as a fallback", () => {
    act(() => {
      root.render(<MemberAvatar username="octo cat" />);
    });
    const image = container.querySelector("img");
    expect(image?.src).toContain("avatars.githubusercontent.com/octo%20cat?size=76");
    expect(container.textContent).toContain("OC");
    act(() => {
      image?.dispatchEvent(new Event("error"));
    });
    expect(image?.style.display).toBe("none");
  });
});

describe("MemberRow", () => {
  it("opens the member's GitHub profile", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <MemberRow
            recipient={{ username: "octo cat", fingerprint: "fingerprint", public_key: "age1" }}
          />
        </I18nProvider>,
      );
    });
    act(() => {
      container.querySelector("button")?.click();
    });
    expect(vi.mocked(openURL)).toHaveBeenCalledWith("https://github.com/octo%20cat");
  });
});

describe("repository setup", () => {
  it("renders personal and organization owners and reports the selection", async () => {
    const onChange = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <RepositoryOwnerSelect
            owners={[
              { login: "octo", organization: false },
              { login: "octo-org", organization: true },
            ]}
            value="octo"
            loading={false}
            onChange={onChange}
          />
        </I18nProvider>,
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

  it("falls back to the new repository's current environment", () => {
    expect(
      resolveWorkspaceEnvironment("dev", [
        { name: "staging", current: true },
        { name: "production", current: false },
      ]),
    ).toBe("staging");
    expect(
      resolveWorkspaceEnvironment("production", [
        { name: "staging", current: true },
        { name: "production", current: false },
      ]),
    ).toBe("production");
  });
});

describe("accessibility: form labels", () => {
  it("repo path input has aria-label", async () => {
    oauthMocks.repoStatus.mockResolvedValue({ selected: false });
    renderAuthenticatedHome();
    await act(async () => Promise.resolve());
    expect(container.querySelector("input[aria-label]")?.getAttribute("aria-label")).toBe(
      "C:\\Users\\you\\src\\your-repo",
    );
  });
});

describe("accessibility: landmark labels and heading levels", () => {
  it("repository selection title is h1", async () => {
    oauthMocks.repoStatus.mockResolvedValue({ selected: false });
    renderAuthenticatedHome();
    await act(async () => Promise.resolve());
    expect(container.querySelector("h1")?.textContent).toContain("Select repository");
  });
});

describe("accessibility: sidebar keyboard", () => {
  it("sidebar repo items have role=button and tabIndex", async () => {
    vi.spyOn(backend, "listRepositories").mockResolvedValue([
      { path: "/a", owner: "acme", repo: "app" },
    ]);
    act(() => {
      root.render(
        <I18nProvider>
          <AuthContext.Provider
            value={{
              status: { authenticated: true, username: "u" },
              loading: false,
              repoPath: "/b",
              refresh: async () => {},
            }}
          >
            <Sidebar activePath="/b" />
          </AuthContext.Provider>
        </I18nProvider>,
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

describe("environment selector", () => {
  it("switches environments and exposes environment creation as the last action", async () => {
    const onSelect = vi.fn();
    const onAdd = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <EnvironmentSelector
            environments={[
              { name: "default", current: true },
              { name: "staging", current: false },
            ]}
            value="default"
            onSelect={onSelect}
            onAdd={onAdd}
          />
        </I18nProvider>,
      );
    });

    const trigger = document.querySelector<HTMLButtonElement>(
      'button[aria-label="Current environment"]',
    );
    await act(async () => {
      trigger?.click();
      await Promise.resolve();
    });
    const menuButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"));
    const staging = menuButtons.find((button) => button.textContent?.includes("staging"));
    expect(menuButtons.at(-1)?.textContent).toContain("Add environment");
    await act(async () => {
      staging?.click();
      await Promise.resolve();
    });
    expect(onSelect).toHaveBeenCalledWith("staging");

    await act(async () => {
      trigger?.click();
      await Promise.resolve();
    });
    const reopenedAdd = Array.from(document.querySelectorAll<HTMLButtonElement>("button")).find(
      (button) => button.textContent?.includes("Add environment"),
    );
    await act(async () => {
      reopenedAdd?.click();
      await Promise.resolve();
    });
    expect(onAdd).toHaveBeenCalledTimes(1);
  });

  it("creates an environment from the modal", () => {
    const onCreate = vi.fn();
    const onClose = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <CreateEnvironmentModal
            open
            value="staging"
            loading={false}
            onValueChange={() => {}}
            onClose={onClose}
            onCreate={onCreate}
          />
        </I18nProvider>,
      );
    });
    expect(document.querySelector('[role="dialog"]')).toBeTruthy();
    act(() => {
      queryButton("Create")?.click();
    });
    expect(onCreate).toHaveBeenCalledTimes(1);
  });
});

describe("accessibility: CreateEnvironmentModal focus", () => {
  it("dialog has aria-modal and aria-labelledby", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <CreateEnvironmentModal
            open={true}
            value=""
            loading={false}
            onValueChange={() => {}}
            onClose={() => {}}
            onCreate={() => {}}
          />
        </I18nProvider>,
      );
    });
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.getAttribute("aria-modal")).toBe("true");
    expect(dialog?.getAttribute("aria-labelledby")).toBeTruthy();
    const titleId = dialog?.getAttribute("aria-labelledby");
    expect(container.querySelector(`[id="${titleId ?? ""}"]`)).toBeTruthy();
  });
});

describe("accessibility: live regions", () => {
  it("loading state has role=status", async () => {
    vi.spyOn(backend, "listRecipients").mockImplementation(
      () => new Promise(() => {}), // never resolves
    );
    act(() => {
      root.render(
        <I18nProvider>
          <RecipientsPanel
            recipients={[]}
            loading={true}
            error=""
            onSync={() => {}}
            onErrorDismiss={() => {}}
          />
        </I18nProvider>,
      );
    });
    const status = container.querySelector('[role="status"]');
    expect(status).toBeTruthy();
  });
});

describe("dashboard review regressions", () => {
  const backendMock = vi.mocked(backend);
  const initializedRepo = (path: string) => ({
    selected: true,
    repo: {
      path,
      owner: "acme",
      repo: path.slice(1),
      initialized: true,
      has_git: true,
      has_remote: true,
    },
  });

  beforeEach(() => {
    oauthMocks.repoStatus.mockReset();
    oauthMocks.repoStatus.mockResolvedValue(initializedRepo("/a"));
    backendMock.listEnvironments.mockResolvedValue([{ name: "default", current: true }]);
    backendMock.listSecrets.mockResolvedValue({
      environment: "default",
      secrets: [{ key: "KEY", value: "value" }],
    });
    backendMock.listRecipients.mockReset();
    backendMock.listRecipients.mockResolvedValue([]);
    backendMock.pullSecrets.mockReset();
    backendMock.pullSecrets.mockResolvedValue();
    backendMock.exportSecrets.mockReset();
    backendMock.exportSecrets.mockResolvedValue();
  });

  it("prompts for pull when the environment has no local cache", async () => {
    backendMock.listSecrets.mockResolvedValue({
      environment: "default",
      cached: false,
      secrets: [],
    });

    renderAuthenticatedHome();
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(container.textContent).toContain(
      "No cached secrets. Pull to download this environment.",
    );
  });

  it("exports the current environment and blocks pull until export finishes", async () => {
    vi.useFakeTimers();
    let resolveExport!: () => void;
    backendMock.exportSecrets.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          resolveExport = resolve;
        }),
    );

    renderAuthenticatedHome();
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    await act(async () => {
      queryButton("Export")?.click();
      await Promise.resolve();
    });

    expect(backendMock.exportSecrets.mock.calls).toEqual([["default"]]);
    expect(queryButton("Pull")?.disabled).toBe(true);
    act(() => queryButton("Pull")?.click());
    expect(backendMock.pullSecrets.mock.calls).toHaveLength(0);

    await act(async () => {
      resolveExport();
      await Promise.resolve();
    });
    await act(async () => {
      vi.advanceTimersByTime(1200);
      await Promise.resolve();
    });
    expect(queryButton("Pull")?.disabled).toBe(false);
  });

  it("clears export loading and displays an export error", async () => {
    vi.useFakeTimers();
    backendMock.exportSecrets.mockRejectedValueOnce(new Error("export failed"));

    renderAuthenticatedHome();
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    await act(async () => {
      queryButton("Export")?.click();
      await Promise.resolve();
    });
    expect(queryButton("Export")?.disabled).toBe(true);

    await act(async () => {
      vi.advanceTimersByTime(2200);
      await Promise.resolve();
    });

    expect(container.textContent).toContain("export failed");
    expect(queryButton("Export")?.disabled).toBe(false);
  });

  it("trims duplicate keys before validation and does not call the backend", async () => {
    backendMock.addSecret.mockClear();
    renderAuthenticatedHome();
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    const keyInput = container.querySelector<HTMLInputElement>('input[aria-label="Key"]');
    act(() => {
      if (!keyInput) return;
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(
        keyInput,
        " KEY ",
      );
      keyInput.dispatchEvent(new Event("input", { bubbles: true }));
    });
    act(() => queryButton("Add")?.click());

    expect(backendMock.addSecret).not.toHaveBeenCalled();
    expect(container.textContent).toContain('Key "KEY" already exists');
  });

  it("reloads recipients by repository path and ignores stale completions", async () => {
    let resolveA!: (
      value: Array<{ username: string; fingerprint: string; public_key: string }>,
    ) => void;
    let resolveB!: (
      value: Array<{ username: string; fingerprint: string; public_key: string }>,
    ) => void;
    const recipientsA = new Promise<
      Array<{ username: string; fingerprint: string; public_key: string }>
    >((resolve) => {
      resolveA = resolve;
    });
    const recipientsB = new Promise<
      Array<{ username: string; fingerprint: string; public_key: string }>
    >((resolve) => {
      resolveB = resolve;
    });
    oauthMocks.repoStatus
      .mockResolvedValueOnce(initializedRepo("/a"))
      .mockResolvedValue(initializedRepo("/b"));
    backendMock.listRecipients.mockReset();
    backendMock.listRecipients
      .mockImplementationOnce(() => recipientsA)
      .mockImplementationOnce(() => recipientsB);

    renderAuthenticatedHome();
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(backendMock.listRecipients).toHaveBeenCalledTimes(1);

    await act(async () => {
      window.dispatchEvent(new Event("enbu-auth-changed"));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(backendMock.listRecipients).toHaveBeenCalledTimes(2);

    await act(async () => {
      resolveB([{ username: "new-repo-user", fingerprint: "b", public_key: "age1b" }]);
      await Promise.resolve();
    });
    await act(async () => {
      queryButton("Members")?.click();
      await Promise.resolve();
    });
    expect(container.textContent).toContain("new-repo-user");

    await act(async () => {
      resolveA([{ username: "stale-user", fingerprint: "a", public_key: "age1a" }]);
      await Promise.resolve();
    });
    expect(container.textContent).toContain("new-repo-user");
    expect(container.textContent).not.toContain("stale-user");
  });

  it("delegates recipient sync and error dismissal", async () => {
    const onSync = vi.fn();
    const onErrorDismiss = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <RecipientsPanel
            recipients={[]}
            loading={false}
            error="failed"
            onSync={onSync}
            onErrorDismiss={onErrorDismiss}
          />
        </I18nProvider>,
      );
    });
    act(() => queryButton("Sync")?.click());
    expect(onSync).toHaveBeenCalledTimes(1);
    act(() => container.querySelector<HTMLButtonElement>('button[aria-label="Close"]')?.click());
    expect(onErrorDismiss).toHaveBeenCalledTimes(1);
  });
});
