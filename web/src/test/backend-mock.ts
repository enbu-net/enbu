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
    repoStatus: vi.fn(async () => ({ selected: false })),
    browseRepository: vi.fn(async () => ({ selected: false })),
    selectRepository: vi.fn(async () => ({ selected: false })),
    listRepositories: vi.fn(async () => []),
    removeRepository: vi.fn(async () => {}),
    initialize: vi.fn(),
    gitInit: vi.fn(),
    gitCreateRemote: vi.fn(),
    listRepositoryOwners: vi.fn(async () => []),
    listEnvironments: vi.fn(async () => []),
    createEnvironment: vi.fn(async () => {}),
    switchEnvironment: vi.fn(async () => {}),
    renameEnvironment: vi.fn(async () => {}),
    deleteEnvironment: vi.fn(async () => {}),
    listSecrets: vi.fn(async (env: string = "default") => ({ environment: env, secrets: [] })),
    addSecret: vi.fn(async () => {}),
    editSecret: vi.fn(async () => {}),
    deleteSecret: vi.fn(async () => {}),
    pullSecrets: vi.fn(),
    syncSecrets: vi.fn(async () => {}),
    listConflicts: vi.fn(),
    resolveConflicts: vi.fn(async () => {}),
    listMembers: vi.fn(async () => []),
    listJoinRequests: vi.fn(async () => []),
    approveMember: vi.fn(async () => {}),
    removeMember: vi.fn(async () => {}),
    readConfig: vi.fn(async () => ""),
    writeConfig: vi.fn(async () => {}),
    appVersion: vi.fn(async () => ""),
  } satisfies Record<keyof Backend, unknown>;
}
