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
    authStatus: vi.fn(async () => ({ authenticated: false, workspace_configured: false })),
    startOAuthLogin: vi.fn(),
    oauthStatus: vi.fn(),
    cancelOAuthLogin: vi.fn(async () => {}),
    logout: vi.fn(async () => {}),
    switchAccount: vi.fn(async () => {}),
    repoStatus: vi.fn(async () => ({ selected: false })),
    browseRepository: vi.fn(async () => ({ selected: false })),
    selectRepository: vi.fn(async () => ({ selected: false })),
    listRepositories: vi.fn(async () => []),
    removeRepository: vi.fn(async () => {}),
    initialize: vi.fn(),
    suggestStorage: vi.fn(async () => ""),
    listEnvironments: vi.fn(async () => []),
    createEnvironment: vi.fn(async () => {}),
    switchEnvironment: vi.fn(async () => {}),
    renameEnvironment: vi.fn(async () => {}),
    deleteEnvironment: vi.fn(async () => ({ purged: 0 })),
    purgeIncarnation: vi.fn(async () => 0),
    listSecrets: vi.fn(async (env: string = "default") => ({ environment: env, secrets: [] })),
    addSecret: vi.fn(async () => {}),
    editSecret: vi.fn(async () => {}),
    deleteSecret: vi.fn(async () => {}),
    pullSecrets: vi.fn(),
    syncSecrets: vi.fn(async () => {}),
    listConflicts: vi.fn(),
    resolveConflicts: vi.fn(async () => {}),
    importSecrets: vi.fn(async () => ({
      environment: "default",
      added: [],
      updated: [],
      unchanged: [],
    })),
    listHistory: vi.fn(async () => []),
    diffHistory: vi.fn(async () => ({ added: [], removed: [], modified: [] })),
    restoreHistory: vi.fn(async () => {}),
    listMembers: vi.fn(async () => []),
    listJoinRequests: vi.fn(async () => []),
    approveMember: vi.fn(async () => {}),
    removeMember: vi.fn(async () => {}),
    setAdmin: vi.fn(async () => {}),
    identity: vi.fn(async () => ({
      backend: "keyring",
      algorithm: "MLKEM768-X25519",
      recipient: "age1pq1test",
      device_id: "d",
      fingerprint: "f",
    })),
    diagnoseIdentity: vi.fn(async () => ({
      backend: "tpm",
      available: false,
      denied: false,
      fallback_available: true,
      keyring_locked: false,
    })),
    readConfig: vi.fn(async () => ""),
    writeConfig: vi.fn(async () => {}),
    appVersion: vi.fn(async () => ""),
    checkForUpdate: vi.fn(async () => ({ method: "development", current: "", available: false })),
    installUpdate: vi.fn(),
    restartApp: vi.fn(async () => {}),
  } satisfies Record<keyof Backend, unknown>;
}
