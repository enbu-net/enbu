import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { backend } from "./backend";

declare global {
  interface Window {
    calls?: unknown[][];
  }
}

const ok = <T>(data: T) => ({ data });

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
        Initialize: vi.fn(async () =>
          ok({
            public_key: "age1test",
            username: "octo",
            environment: "default",
          }),
        ),
        ListEnvironments: vi.fn(async () => ok([{ name: "default", current: true }])),
        CreateEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["create", name]);
          return ok(undefined);
        }),
        SwitchEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["switch", name]);
          return ok(undefined);
        }),
        RenameEnvironment: vi.fn(async (name: string, newName: string) => {
          window.calls?.push(["rename", name, newName]);
          return ok(undefined);
        }),
        DeleteEnvironment: vi.fn(async (name: string) => {
          window.calls?.push(["deleteEnv", name]);
          return ok(undefined);
        }),
        ListSecrets: vi.fn(async (env: string) =>
          ok({
            environment: env,
            secrets: [{ key: "TOKEN", value: "secret" }],
          }),
        ),
        AddSecret: vi.fn(async (env: string, key: string, value: string) => {
          window.calls?.push(["add", env, key, value]);
          return ok(undefined);
        }),
        EditSecret: vi.fn(async (env: string, key: string, value: string) => {
          window.calls?.push(["edit", env, key, value]);
          return ok(undefined);
        }),
        DeleteSecret: vi.fn(async (env: string, key: string) => {
          window.calls?.push(["delete", env, key]);
          return ok(undefined);
        }),
        PullSecrets: vi.fn(async (env: string) => {
          window.calls?.push(["pull", env]);
          return ok(undefined);
        }),
        SyncSecrets: vi.fn(async (env: string) => {
          window.calls?.push(["sync", env]);
          return ok(undefined);
        }),
        ListConflicts: vi.fn(async (env: string) =>
          // Wails hands back null for empty Go slices.
          ok({
            environment: env,
            heads: ["h1", "h2"],
            conflicts: [
              {
                key: "KEY",
                candidates: [
                  { value: "a", deleted: false },
                  { value: "", deleted: true },
                ],
              },
              { key: "OTHER", candidates: null },
            ],
          } as never),
        ),
        ResolveConflicts: vi.fn(async (env: string, heads: string[], choices: unknown[]) => {
          window.calls?.push(["resolve", env, heads, choices]);
          return ok(undefined);
        }),
        ListRepositories: vi.fn(async () => ok([])),
        RemoveRepository: vi.fn(async () => ok(undefined)),
        ListMembers: vi.fn(async () =>
          // Wails can hand back null entries; the adapter must drop them.
          ok([
            { device_id: "d1", fingerprint: "aaaa", algorithm: "p256", admin: true, self: true },
            null,
          ] as never),
        ),
        ListJoinRequests: vi.fn(async () =>
          ok([{ device_id: "d2", fingerprint: "bbbb", algorithm: "ed25519", requested_at: "t" }]),
        ),
        ApproveMember: vi.fn(async (id: string) => {
          window.calls?.push(["approve", id]);
          return ok(undefined);
        }),
        RemoveMember: vi.fn(async (id: string) => {
          window.calls?.push(["remove", id]);
          return ok(undefined);
        }),
        ListHistory: vi.fn(async () =>
          ok([{ index: 1, timestamp: "t", tag: "a" }] as Array<{
            index: number;
            timestamp: string;
            tag: string;
          }>),
        ),
        DiffHistory: vi.fn(async (env: string, from: number, to: number) => {
          window.calls?.push(["diff", env, from, to]);
          return ok({ added: ["A"], removed: null as unknown as string[], modified: [] });
        }),
        RestoreHistory: vi.fn(async (env: string, index: number) => {
          window.calls?.push(["restore", env, index]);
          return ok(undefined);
        }),
        SetAdmin: vi.fn(async (id: string, admin: boolean) => {
          window.calls?.push(["admin", id, admin]);
          return ok(undefined);
        }),
        UpgradeIdentity: vi.fn(async () =>
          ok({ algorithm: "MLKEM768-X25519", fingerprint: "aaaa", pending: true }),
        ),
        DeleteEnvironmentPurging: vi.fn(async (name: string) => {
          window.calls?.push(["delete-purging", name]);
          return ok(3);
        }),
        PurgeIncarnation: vi.fn(async (incarnation: string) => {
          window.calls?.push(["purge", incarnation]);
          return ok(2);
        }),
        ImportSecrets: vi.fn(async (env: string, dotenv: string, overwrite: boolean) => {
          window.calls?.push(["import", env, dotenv, overwrite]);
          return ok({
            environment: env || "default",
            added: ["A"],
            updated: null as unknown as string[],
            unchanged: [],
          });
        }),
        ReadConfig: vi.fn(async () => ok("")),
        WriteConfig: vi.fn(async () => ok(undefined)),
        GitInit: vi.fn(async (path: string) =>
          ok({
            path,
            owner: "",
            repo: "",
            initialized: false,
            has_git: true,
            has_remote: false,
          }),
        ),
        ListRepositoryOwners: vi.fn(async () =>
          ok([
            { login: "octo", organization: false },
            { login: "octo-org", organization: true },
          ]),
        ),
        GitCreateRemote: vi.fn(
          async (path: string, owner: string, repo: string, privateRepository: boolean) => {
            window.calls?.push(["createRemote", path, owner, repo, privateRepository]);
            return ok({
              path,
              owner,
              repo,
              initialized: false,
              has_git: true,
              has_remote: true,
            });
          },
        ),
        GetAppVersion: vi.fn(async () => ok("v0.7.5")),
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

describe("backend member operations", () => {
  it("maps members and join requests from the desktop service", async () => {
    await expect(backend.listMembers()).resolves.toEqual([
      {
        device_id: "d1",
        fingerprint: "aaaa",
        algorithm: "p256",
        admin: true,
        self: true,
        post_quantum: false,
      },
    ]);
    await expect(backend.listJoinRequests()).resolves.toEqual([
      {
        device_id: "d2",
        fingerprint: "bbbb",
        algorithm: "ed25519",
        requested_at: "t",
        key_update: false,
      },
    ]);
  });

  it("passes the device id to approve and remove", async () => {
    await backend.approveMember("d2");
    await backend.removeMember("d1");
    expect(window.calls).toEqual([
      ["approve", "d2"],
      ["remove", "d1"],
    ]);
  });

  it("passes admin changes and returns the key update", async () => {
    await backend.setAdmin("d2", true);
    await backend.setAdmin("d2", false);
    expect(window.calls).toEqual([
      ["admin", "d2", true],
      ["admin", "d2", false],
    ]);
    await expect(backend.upgradeIdentity()).resolves.toEqual({
      algorithm: "MLKEM768-X25519",
      fingerprint: "aaaa",
      pending: true,
    });
  });

  it("purges environments and incarnations and returns the deleted count", async () => {
    await expect(backend.deleteEnvironmentPurging("old")).resolves.toBe(3);
    await expect(backend.purgeIncarnation("0b8e1f6c-1d3e-4c55-9a51-6f3d2c1b0a99")).resolves.toBe(2);
    expect(window.calls).toEqual([
      ["delete-purging", "old"],
      ["purge", "0b8e1f6c-1d3e-4c55-9a51-6f3d2c1b0a99"],
    ]);
  });

  it("imports a dotenv file and fills missing lists", async () => {
    await expect(backend.importSecrets("A=1\n", true, "prod")).resolves.toEqual({
      environment: "prod",
      added: ["A"],
      updated: [],
      unchanged: [],
    });
    expect(window.calls).toEqual([["import", "prod", "A=1\n", true]]);
  });

  it("lists, compares, and restores history with desktop argument order", async () => {
    await expect(backend.listHistory("prod")).resolves.toEqual([
      { index: 1, timestamp: "t", tag: "a" },
    ]);
    await expect(backend.diffHistory(1, 2, "prod")).resolves.toEqual({
      added: ["A"],
      removed: [],
      modified: [],
    });
    await backend.restoreHistory(1, "prod");
    expect(window.calls).toEqual([
      ["diff", "prod", 1, 2],
      ["restore", "prod", 1],
    ]);
  });

  it("refuses irreversible member and storage changes without the desktop service", async () => {
    window.go = undefined;
    for (const call of [
      () => backend.setAdmin("d2", true),
      () => backend.upgradeIdentity(),
      () => backend.deleteEnvironmentPurging("old"),
      () => backend.purgeIncarnation("x"),
      () => backend.importSecrets("A=1", false),
      () => backend.restoreHistory(1),
    ]) {
      await expect(call()).rejects.toMatchObject({ payload: { code: "unavailable" } });
    }
  });

  it("lists conflicts and passes the decisions with the heads they were made from", async () => {
    await expect(backend.listConflicts("prod")).resolves.toEqual({
      environment: "prod",
      heads: ["h1", "h2"],
      conflicts: [
        {
          key: "KEY",
          candidates: [
            { value: "a", deleted: false },
            { value: "", deleted: true },
          ],
        },
        { key: "OTHER", candidates: [] },
      ],
    });
    await backend.resolveConflicts("prod", ["h1", "h2"], [{ key: "KEY", value: "", delete: true }]);
    expect(window.calls).toEqual([
      ["resolve", "prod", ["h1", "h2"], [{ key: "KEY", value: "", delete: true }]],
    ]);
  });

  it("treats an empty result as no members", async () => {
    window.go!.main!.DesktopService!.ListMembers = vi.fn(async () => ok(null as never));
    window.go!.main!.DesktopService!.ListJoinRequests = vi.fn(async () => ok(null as never));
    await expect(backend.listMembers()).resolves.toEqual([]);
    await expect(backend.listJoinRequests()).resolves.toEqual([]);
  });

  it("fails instead of pretending when the desktop service is missing", async () => {
    window.go = undefined;
    await expect(backend.listMembers()).resolves.toEqual([]);
    await expect(backend.listJoinRequests()).resolves.toEqual([]);
    await expect(backend.approveMember("d2")).rejects.toMatchObject({
      payload: { code: "unavailable" },
    });
    await expect(backend.removeMember("d1")).rejects.toMatchObject({
      payload: { code: "unavailable" },
    });
    await expect(backend.resolveConflicts("", ["h1"], [])).rejects.toMatchObject({
      payload: { code: "unavailable" },
    });
  });

  it("propagates a refusal from the desktop service", async () => {
    window.go!.main!.DesktopService!.ApproveMember = vi.fn(async () => ({
      error: { code: "access_denied", message: "no", params: {} },
    }));
    await expect(backend.approveMember("d2")).rejects.toMatchObject({
      payload: { code: "access_denied" },
    });
  });
});
