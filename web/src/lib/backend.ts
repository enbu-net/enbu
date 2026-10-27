import { DesktopService as Desktop } from "../bindings/github.com/enbu-net/enbu/desktop/wails";
import { AppError, createAppError, toDisplayError } from "./app-error";
import { mockBackend } from "./mock-backend";
import { isPreview } from "./preview";
import type {
  AuthStatus,
  ConflictChoice,
  ConflictSet,
  Environment,
  GUIRepoStatus,
  InitResult,
  JoinRequest,
  Member,
  OAuthStart,
  OAuthStatus,
  PullResult,
  RepoInfo,
  RepositoryOwner,
  SecretsResponse,
} from "./types";

/**
 * Everything the UI asks of enbu. The desktop app implements it with the
 * generated Wails bindings; the browser preview with an in-memory mock. A new
 * operation is a method here, one in each implementation, and the Go method
 * in desktop/wails/binding.go it calls.
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
  initialize(): Promise<InitResult>;
  gitInit(path: string): Promise<GUIRepoStatus>;
  gitCreateRemote(
    path: string,
    owner: string,
    repoName: string,
    privateRepository: boolean,
  ): Promise<GUIRepoStatus>;
  listRepositoryOwners(): Promise<RepositoryOwner[]>;

  listEnvironments(): Promise<Environment[]>;
  createEnvironment(name: string): Promise<void>;
  switchEnvironment(name: string): Promise<void>;
  renameEnvironment(name: string, newName: string): Promise<void>;
  deleteEnvironment(name: string): Promise<void>;

  listSecrets(env?: string): Promise<SecretsResponse>;
  addSecret(key: string, value: string, env?: string): Promise<void>;
  editSecret(key: string, value: string, env?: string): Promise<void>;
  deleteSecret(key: string, env?: string): Promise<void>;
  /** With replace the output file's content is dropped, even when enbu cannot read it. */
  pullSecrets(env?: string, replace?: boolean): Promise<PullResult>;
  syncSecrets(env?: string): Promise<void>;
  listConflicts(env?: string): Promise<ConflictSet>;
  resolveConflicts(env: string, heads: string[], choices: ConflictChoice[]): Promise<void>;

  listMembers(): Promise<Member[]>;
  listJoinRequests(): Promise<JoinRequest[]>;
  approveMember(deviceID: string): Promise<void>;
  removeMember(deviceID: string): Promise<void>;

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

export const desktopBackend: Backend = {
  authStatus: () => call(Desktop.GetAuthStatus()),
  startOAuthLogin: () => call(Desktop.StartOAuthLogin()),
  async oauthStatus(sessionID) {
    const status = await call(Desktop.GetOAuthLoginStatus(sessionID));
    return {
      state: status.state as OAuthStatus["state"],
      username: status.username,
      error: status.error ? toDisplayError(status.error) : undefined,
    };
  },
  cancelOAuthLogin: (sessionID) => call(Desktop.CancelOAuthLogin(sessionID)),
  logout: () => call(Desktop.Logout()),

  repoStatus: async () => repoStatusOf(await call(Desktop.GetRepoStatus())),
  browseRepository: async () => repoStatusOf(await call(Desktop.BrowseRepository())),
  selectRepository: async (path) => repoStatusOf(await call(Desktop.SelectRepository(path))),
  listRepositories: () => call(Desktop.ListRepositories()),
  removeRepository: (path) => call(Desktop.RemoveRepository(path)),
  initialize: () => call(Desktop.Initialize()),
  gitInit: async (path) => repoStatusOf(await call(Desktop.GitInit(path))),
  gitCreateRemote: async (path, owner, repoName, privateRepository) =>
    repoStatusOf(await call(Desktop.GitCreateRemote(path, owner, repoName, privateRepository))),
  listRepositoryOwners: () => call(Desktop.ListRepositoryOwners()),

  listEnvironments: () => call(Desktop.ListEnvironments()),
  createEnvironment: (name) => call(Desktop.CreateEnvironment(name)),
  switchEnvironment: (name) => call(Desktop.SwitchEnvironment(name)),
  renameEnvironment: (name, newName) => call(Desktop.RenameEnvironment(name, newName)),
  deleteEnvironment: (name) => call(Desktop.DeleteEnvironment(name)),

  listSecrets: (env = "") => call(Desktop.ListSecrets(env)),
  addSecret: (key, value, env = "") => call(Desktop.AddSecret(env, key, value)),
  editSecret: (key, value, env = "") => call(Desktop.EditSecret(env, key, value)),
  deleteSecret: (key, env = "") => call(Desktop.DeleteSecret(env, key)),
  pullSecrets: (env = "", replace = false) => call(Desktop.PullSecrets(env, replace)),
  syncSecrets: (env = "") => call(Desktop.SyncSecrets(env)),
  listConflicts: (env = "") => call(Desktop.ListConflicts(env)),
  resolveConflicts: (env, heads, choices) => call(Desktop.ResolveConflicts(env, heads, choices)),

  listMembers: () => call(Desktop.ListMembers()),
  listJoinRequests: () => call(Desktop.ListJoinRequests()),
  approveMember: (deviceID) => call(Desktop.ApproveMember(deviceID)),
  removeMember: (deviceID) => call(Desktop.RemoveMember(deviceID)),

  readConfig: () => call(Desktop.ReadConfig()),
  writeConfig: (content) => call(Desktop.WriteConfig(content)),
  appVersion: () => call(Desktop.GetAppVersion()),
};

export const backend: Backend = isPreview ? mockBackend : desktopBackend;
