import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { backend } from "./backend";

declare global {
  interface Window {
    calls?: unknown[][];
  }
}

beforeEach(() => {
  window.calls = [];
  window.go = {
    main: {
      DesktopService: {
        GetAuthStatus: vi.fn(),
        StartOAuthLogin: vi.fn(),
        GetOAuthLoginStatus: vi.fn(),
        CancelOAuthLogin: vi.fn(),
        Logout: vi.fn(),
        BrowseRepository: vi.fn(),
        SelectRepository: vi.fn(),
        GetRepoStatus: vi.fn(),
        Initialize: vi.fn(async () => ({
          public_key: "age1test",
          username: "octo",
          environment: "default",
        })),
        ListEnvironments: vi.fn(async () => [{ name: "default", current: true }]),
        CreateEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["create", name]);
        }),
        SwitchEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["switch", name]);
        }),
        RenameEnvironment: vi.fn(async (name: string, newName: string) => {
          window.calls?.push(["rename", name, newName]);
        }),
        DeleteEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["deleteEnv", name]);
        }),
        ListSecrets: vi.fn(async (env: string) => ({
          environment: env,
          secrets: [{ key: "TOKEN", value: "secret" }],
        })),
        AddSecret: vi.fn(async (env: string, key: string, value: string) => {
          window.calls?.push(["add", env, key, value]);
        }),
        EditSecret: vi.fn(async (env: string, key: string, value: string) => {
          window.calls?.push(["edit", env, key, value]);
        }),
        DeleteSecret: vi.fn(async (env: string, key: string) => {
          window.calls?.push(["delete", env, key]);
        }),
        PullSecrets: vi.fn(async (env: string) => {
          window.calls?.push(["pull", env]);
        }),
        ExportSecrets: vi.fn(async (env: string) => {
          window.calls?.push(["export", env]);
        }),
        SyncSecrets: vi.fn(async (env: string) => {
          window.calls?.push(["sync", env]);
        }),
        ListRepositories: vi.fn(async () => []),
        RemoveRepository: vi.fn(async () => {}),
        ListRecipients: vi.fn(async () => []),
        ReadConfig: vi.fn(async () => ""),
        WriteConfig: vi.fn(async () => {}),
        GitInit: vi.fn(async (path: string) => ({
          path,
          owner: "",
          repo: "",
          initialized: false,
          has_git: true,
          has_remote: false,
        })),
        ListRepositoryOwners: vi.fn(async () => [
          { login: "octo", organization: false },
          { login: "octo-org", organization: true },
        ]),
        GitCreateRemote: vi.fn(
          async (path: string, owner: string, repo: string, privateRepository: boolean) => {
            window.calls?.push(["createRemote", path, owner, repo, privateRepository]);
            return {
              path,
              owner,
              repo,
              initialized: false,
              has_git: true,
              has_remote: true,
            };
          },
        ),
        GetAppVersion: vi.fn(async () => "v0.7.5"),
      },
    },
  };
});

describe("backend desktop adapter", () => {
  it("delegates initialization and workspace reads to Wails", async () => {
    await expect(backend.initialize()).resolves.toMatchObject({
      environment: "default",
      username: "octo",
    });
    await expect(backend.listEnvironments()).resolves.toEqual([{ name: "default", current: true }]);
    await expect(backend.listSecrets("default")).resolves.toEqual({
      environment: "default",
      secrets: [{ key: "TOKEN", value: "secret" }],
    });
  });

  it("passes environment and secret operations to Wails with desktop argument order", async () => {
    await backend.createEnvironment("staging");
    await backend.switchEnvironment("staging");
    await backend.renameEnvironment("staging", "prod");
    await backend.deleteEnvironment("prod");
    await backend.addSecret("TOKEN", "secret", "default");
    await backend.editSecret("TOKEN", "new", "default");
    await backend.deleteSecret("TOKEN", "default");
    await backend.pullSecrets("default");
    await backend.exportSecrets("default");
    await backend.syncSecrets("default");

    expect(window.calls).toEqual([
      ["create", "staging"],
      ["switch", "staging"],
      ["rename", "staging", "prod"],
      ["deleteEnv", "prod"],
      ["add", "default", "TOKEN", "secret"],
      ["edit", "default", "TOKEN", "new"],
      ["delete", "default", "TOKEN"],
      ["pull", "default"],
      ["export", "default"],
      ["sync", "default"],
    ]);
  });

  it("delegates repository setup to the desktop service", async () => {
    await expect(backend.gitInit("C:/repo")).resolves.toMatchObject({
      repo: { has_git: true, has_remote: false },
    });
    await expect(backend.listRepositoryOwners()).resolves.toEqual([
      { login: "octo", organization: false },
      { login: "octo-org", organization: true },
    ]);
    await expect(
      backend.gitCreateRemote("C:/repo", "octo-org", "example", true),
    ).resolves.toMatchObject({
      repo: { owner: "octo-org", repo: "example", has_remote: true },
    });
    expect(window.calls).toContainEqual(["createRemote", "C:/repo", "octo-org", "example", true]);
  });
});
