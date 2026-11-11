import { vi } from "vite-plus/test";
import type { Backend } from "../lib/backend";

/**
 * A Backend whose every method is a mock with a harmless default. Use it from
 * a vi.mock factory:
 *
 *   vi.mock("../lib/backend", async () => ({
 *     backend: (await import("../test/backend-mock")).createBackendMock(),
 *   }));
 */
export function createBackendMock() {
  return {
    GetAuthStatus: vi.fn(async () => ({ authenticated: false, workspace_configured: false })),
    StartOAuthLogin: vi.fn(),
    GetOAuthLoginStatus: vi.fn(),
    CancelOAuthLogin: vi.fn(async () => {}),
    Logout: vi.fn(async () => {}),
    SwitchAccount: vi.fn(async () => {}),
    GetRepoStatus: vi.fn(async () => ({ selected: false })),
    BrowseRepository: vi.fn(async () => ({ selected: false })),
    SelectRepository: vi.fn(async () => ({ selected: false })),
    ListRepositories: vi.fn(async () => []),
    RemoveRepository: vi.fn(async () => {}),
    Initialize: vi.fn(),
    SuggestStorage: vi.fn(async () => ""),
    ListEnvironments: vi.fn(async () => []),
    CreateEnvironment: vi.fn(async () => {}),
    SwitchEnvironment: vi.fn(async () => {}),
    RenameEnvironment: vi.fn(async () => {}),
    DeleteEnvironment: vi.fn(async () => ({ purged: 0 })),
    PurgeIncarnation: vi.fn(async () => 0),
    ListSecrets: vi.fn(async (env: string = "default") => ({ environment: env, secrets: [] })),
    AddSecret: vi.fn(async () => {}),
    EditSecret: vi.fn(async () => {}),
    DeleteSecret: vi.fn(async () => {}),
    PullSecrets: vi.fn(),
    SyncSecrets: vi.fn(async () => {}),
    ListConflicts: vi.fn(),
    ResolveConflicts: vi.fn(async () => {}),
    ImportSecrets: vi.fn(async () => ({
      environment: "default",
      added: [],
      updated: [],
      unchanged: [],
    })),
    ListHistory: vi.fn(async () => []),
    DiffHistory: vi.fn(async () => ({ added: [], removed: [], modified: [] })),
    RestoreHistory: vi.fn(async () => {}),
    ListMembers: vi.fn(async () => []),
    ListJoinRequests: vi.fn(async () => []),
    ApproveMember: vi.fn(async () => {}),
    RemoveMember: vi.fn(async () => {}),
    SetAdmin: vi.fn(async () => {}),
    GetIdentity: vi.fn(async () => ({
      backend: "keyring",
      algorithm: "MLKEM768-X25519",
      recipient: "age1pq1test",
      device_id: "d",
      fingerprint: "f",
    })),
    DiagnoseIdentity: vi.fn(async () => ({
      backend: "tpm",
      available: false,
      denied: false,
      fallback_available: true,
      keyring_locked: false,
    })),
    ReadConfig: vi.fn(async () => ""),
    WriteConfig: vi.fn(async () => {}),
    GetAppVersion: vi.fn(async () => ""),
    CheckForUpdate: vi.fn(async () => ({ method: "development", current: "", available: false })),
    InstallUpdate: vi.fn(),
    RestartApp: vi.fn(async () => {}),
  } satisfies Record<keyof Backend, unknown>;
}
