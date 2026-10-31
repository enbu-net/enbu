import { DesktopService as Desktop } from "../bindings/github.com/enbu-net/enbu/desktop/wails";
import { AppError, createAppError, toDisplayError } from "./app-error";
import { host } from "./host";
import { mockBackend } from "./mock-backend";
import { vscodeBridge, vscodeService } from "./vscode";
import type {
  AuthStatus,
  ConflictChoice,
  ConflictSet,
  Diagnosis,
  Diff,
  Environment,
  EnvironmentDeletion,
  GUIRepoStatus,
  HistoryEntry,
  ImportResult,
  InitResult,
  StorageSettings,
  JoinRequest,
  KeyUpdateResult,
  Member,
  OAuthStart,
  OAuthStatus,
  PublicInfo,
  PullResult,
  RepoInfo,
  SecretsResponse,
} from "./types";

/**
 * Everything the UI asks of enbu. The desktop app implements it with the
 * generated Wails bindings, a VS Code webview with the same service over the
 * extension host (see vscode.ts), and the browser preview with an in-memory
 * mock. A new operation is a method here, one in the mock, and the Go method in
 * desktop/wails/binding.go it calls, also listed in desktop/rpc.Methods.
 */
export interface Backend {
  authStatus(): Promise<AuthStatus>;
  startOAuthLogin(): Promise<OAuthStart>;
  oauthStatus(sessionID: string): Promise<OAuthStatus>;
  cancelOAuthLogin(sessionID: string): Promise<void>;
  logout(): Promise<void>;

  repoStatus(): Promise<GUIRepoStatus>;
  browseRepository(): Promise<GUIRepoStatus>;
  selectRepository(path: string): Promise<GUIRepoStatus>;
  listRepositories(): Promise<RepoInfo[]>;
  removeRepository(path: string): Promise<void>;
  /** Founds a workspace in storage ("" for the suggested one), or joins enbu.toml's. */
  initialize(storage: StorageSettings, acceptNewGenesis: boolean): Promise<InitResult>;
  /** The GHCR repository beside the GitHub origin that founding suggests. */
  suggestStorage(): Promise<string>;

  listEnvironments(): Promise<Environment[]>;
  createEnvironment(name: string): Promise<void>;
  switchEnvironment(name: string): Promise<void>;
  renameEnvironment(name: string, newName: string): Promise<void>;
  /** With purge the stored revisions go too (admin only); without, the result names their incarnation. */
  deleteEnvironment(name: string, purge: boolean): Promise<EnvironmentDeletion>;
  /** Deletes the stored revisions of an environment deleted without purge (admin only). */
  purgeIncarnation(incarnation: string): Promise<number>;

  listSecrets(env?: string): Promise<SecretsResponse>;
  addSecret(key: string, value: string, env?: string): Promise<void>;
  editSecret(key: string, value: string, env?: string): Promise<void>;
  deleteSecret(key: string, env?: string): Promise<void>;
  /** With replace the output file's content is dropped, even when enbu cannot read it. */
  pullSecrets(env?: string, replace?: boolean): Promise<PullResult>;
  syncSecrets(env?: string): Promise<void>;
  listConflicts(env?: string): Promise<ConflictSet>;
  resolveConflicts(env: string, heads: string[], choices: ConflictChoice[]): Promise<void>;
  /** Adds every variable of a dotenv file's content; overwrite replaces ones with another value. */
  importSecrets(dotenv: string, overwrite: boolean, env?: string): Promise<ImportResult>;

  /** The revisions that changed env's secrets, oldest first, numbered from 1. */
  listHistory(env: string): Promise<HistoryEntry[]>;
  diffHistory(env: string, from: number, to: number): Promise<Diff>;
  /** Publishes the content of revision index as a new revision. */
  restoreHistory(env: string, index: number): Promise<void>;

  listMembers(): Promise<Member[]>;
  listJoinRequests(): Promise<JoinRequest[]>;
  approveMember(deviceID: string): Promise<void>;
  removeMember(deviceID: string): Promise<void>;
  setAdmin(deviceID: string, admin: boolean): Promise<void>;
  /** Joins member changes two admins made at the same time. */
  resolveMemberFork(): Promise<void>;

  /** This device's keys in the selected workspace. */
  identity(): Promise<PublicInfo>;
  diagnoseIdentity(): Promise<Diagnosis>;
  /** Switches this device to a post-quantum key; a member's waits for an admin. */
  upgradeIdentity(): Promise<KeyUpdateResult>;

  readConfig(): Promise<string>;
  writeConfig(content: string): Promise<void>;
  appVersion(): Promise<string>;
}

/**
 * A failed call rejects with the error's AppError payload as its cause (see
 * marshalError in desktop/wails). Anything else, such as a binding missing in
 * an outdated build, becomes an internal error; the details go to the console.
 */
export function toAppError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  const cause = (err as { cause?: unknown } | null)?.cause;
  if (
    cause &&
    typeof cause === "object" &&
    typeof (cause as { code?: unknown }).code === "string"
  ) {
    return new AppError(cause as AppError["payload"]);
  }
  console.error("desktop call failed", err);
  return createAppError("internal");
}

async function call<T>(promise: PromiseLike<T>): Promise<T> {
  try {
    return await promise;
  } catch (err) {
    throw toAppError(err);
  }
}

function repoStatusOf(repo: RepoInfo | null | undefined): GUIRepoStatus {
  return repo?.path ? { selected: true, repo } : { selected: false };
}

/** The desktop service's methods, by their Go names. */
export type ServiceMethod = keyof typeof Desktop;

/** A client of the desktop service: the Wails bindings, or the VS Code bridge. */
export type ServiceClient = {
  [K in ServiceMethod]: (
    ...args: Parameters<(typeof Desktop)[K]>
  ) => PromiseLike<Awaited<ReturnType<(typeof Desktop)[K]>>>;
};

export function createServiceBackend(svc: ServiceClient): Backend {
  return {
    authStatus: () => call(svc.GetAuthStatus()),
    startOAuthLogin: () => call(svc.StartOAuthLogin()),
    async oauthStatus(sessionID) {
      const status = await call(svc.GetOAuthLoginStatus(sessionID));
      return {
        state: status.state as OAuthStatus["state"],
        username: status.username,
        error: status.error ? toDisplayError(status.error) : undefined,
      };
    },
    cancelOAuthLogin: (sessionID) => call(svc.CancelOAuthLogin(sessionID)),
    logout: () => call(svc.Logout()),

    repoStatus: async () => repoStatusOf(await call(svc.GetRepoStatus())),
    browseRepository: async () => repoStatusOf(await call(svc.BrowseRepository())),
    selectRepository: async (path) => repoStatusOf(await call(svc.SelectRepository(path))),
    listRepositories: () => call(svc.ListRepositories()),
    removeRepository: (path) => call(svc.RemoveRepository(path)),
    initialize: (storage, acceptNewGenesis) => call(svc.Initialize(storage, acceptNewGenesis)),
    suggestStorage: () => call(svc.SuggestStorage()),

    listEnvironments: () => call(svc.ListEnvironments()),
    createEnvironment: (name) => call(svc.CreateEnvironment(name)),
    switchEnvironment: (name) => call(svc.SwitchEnvironment(name)),
    renameEnvironment: (name, newName) => call(svc.RenameEnvironment(name, newName)),
    deleteEnvironment: (name, purge) => call(svc.DeleteEnvironment(name, purge)),
    purgeIncarnation: (incarnation) => call(svc.PurgeIncarnation(incarnation)),

    listSecrets: (env = "") => call(svc.ListSecrets(env)),
    addSecret: (key, value, env = "") => call(svc.AddSecret(env, key, value)),
    editSecret: (key, value, env = "") => call(svc.EditSecret(env, key, value)),
    deleteSecret: (key, env = "") => call(svc.DeleteSecret(env, key)),
    pullSecrets: (env = "", replace = false) => call(svc.PullSecrets(env, replace)),
    syncSecrets: (env = "") => call(svc.SyncSecrets(env)),
    listConflicts: (env = "") => call(svc.ListConflicts(env)),
    resolveConflicts: (env, heads, choices) => call(svc.ResolveConflicts(env, heads, choices)),
    importSecrets: (dotenv, overwrite, env = "") => call(svc.ImportSecrets(env, dotenv, overwrite)),

    listHistory: (env) => call(svc.ListHistory(env)),
    async diffHistory(env, from, to) {
      const diff = await call(svc.DiffHistory(env, from, to));
      return diff ?? { added: [], removed: [], modified: [] };
    },
    restoreHistory: (env, index) => call(svc.RestoreHistory(env, index)),

    listMembers: () => call(svc.ListMembers()),
    listJoinRequests: () => call(svc.ListJoinRequests()),
    approveMember: (deviceID) => call(svc.ApproveMember(deviceID)),
    removeMember: (deviceID) => call(svc.RemoveMember(deviceID)),
    setAdmin: (deviceID, admin) => call(svc.SetAdmin(deviceID, admin)),
    resolveMemberFork: () => call(svc.ResolveMemberFork()),

    identity: () => call(svc.GetIdentity()),
    diagnoseIdentity: () => call(svc.DiagnoseIdentity()),
    upgradeIdentity: () => call(svc.UpgradeIdentity()),

    readConfig: () => call(svc.ReadConfig()),
    writeConfig: (content) => call(svc.WriteConfig(content)),
    appVersion: () => call(svc.GetAppVersion()),
  };
}

export const desktopBackend: Backend = createServiceBackend(Desktop);

export const backend: Backend =
  host === "vscode" && vscodeBridge
    ? createServiceBackend(vscodeService(vscodeBridge))
    : host === "preview"
      ? mockBackend
      : desktopBackend;
