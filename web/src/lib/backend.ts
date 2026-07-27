import {
  api,
  type AuthStatus,
  type Environment,
  type GUIRepoStatus,
  type InitResult,
  type Recipient,
  type SecretsResponse,
} from "./api";
import { mockBackend } from "./mock-backend";

const isMock =
  (typeof window !== "undefined" && new URLSearchParams(window.location.search).has("mock")) ||
  import.meta.env.BASE_URL.includes("/enbu/");

export interface OAuthStart {
  session_id: string;
  expires_at: string;
}

export interface OAuthStatus {
  state: "pending" | "success" | "expired" | "denied" | "error";
  message?: string;
  username?: string;
}

export interface RepositoryOwner {
  login: string;
  organization: boolean;
}

type DesktopService = {
  GetAuthStatus: () => Promise<DesktopAuthStatus>;
  StartOAuthLogin: () => Promise<OAuthStart>;
  GetOAuthLoginStatus: (sessionID: string) => Promise<OAuthStatus>;
  CancelOAuthLogin: (sessionID: string) => Promise<void>;
  Logout: () => Promise<void>;
  BrowseRepository: () => Promise<GUIRepoStatus["repo"]>;
  SelectRepository: (path: string) => Promise<GUIRepoStatus["repo"]>;
  GetRepoStatus: () => Promise<GUIRepoStatus["repo"]>;
  Initialize: () => Promise<InitResult>;
  ListEnvironments: () => Promise<Environment[]>;
  CreateEnvironment: (name: string) => Promise<void>;
  SwitchEnvironment: (name: string) => Promise<void>;
  RenameEnvironment: (name: string, newName: string) => Promise<void>;
  DeleteEnvironment: (name: string) => Promise<void>;
  ListSecrets: (env: string) => Promise<SecretsResponse>;
  AddSecret: (env: string, key: string, value: string) => Promise<void>;
  EditSecret: (env: string, key: string, value: string) => Promise<void>;
  DeleteSecret: (env: string, key: string) => Promise<void>;
  PullSecrets: (env: string) => Promise<void>;
  ExportSecrets: (env: string) => Promise<void>;
  SyncSecrets: (env: string) => Promise<void>;
  ListRepositories: () => Promise<
    Array<{ path: string; owner: string; repo: string; initialized: boolean }>
  >;
  RemoveRepository: (path: string) => Promise<void>;
  ListRecipients: () => Promise<
    Array<{ username: string; fingerprint: string; public_key: string }>
  >;
  ReadConfig: () => Promise<string>;
  WriteConfig: (content: string) => Promise<void>;
  GitInit: (path: string) => Promise<GUIRepoStatus["repo"]>;
  ListRepositoryOwners: () => Promise<RepositoryOwner[]>;
  GitCreateRemote: (
    path: string,
    owner: string,
    repoName: string,
    privateRepository: boolean,
  ) => Promise<GUIRepoStatus["repo"]>;
  GetAppVersion: () => Promise<string>;
};

type DesktopAuthStatus = Omit<AuthStatus, "repo"> & {
  repo?: AuthStatus["repo"] & {
    repo?: string;
  };
};

declare global {
  interface Window {
    go?: {
      main?: {
        DesktopService?: DesktopService;
      };
      desktop?: {
        Service?: DesktopService;
      };
    };
  }
}

function service(): DesktopService | undefined {
  return window.go?.main?.DesktopService ?? window.go?.desktop?.Service;
}

const realBackend = {
  async authStatus(): Promise<AuthStatus> {
    const svc = service();
    if (!svc) {
      return api.auth.status();
    }
    return normalizeAuthStatus(await svc.GetAuthStatus());
  },
  async startOAuthLogin(): Promise<OAuthStart> {
    const svc = service();
    if (!svc) {
      throw new Error("Desktop authentication is not available");
    }
    return svc.StartOAuthLogin();
  },
  async oauthStatus(sessionID: string): Promise<OAuthStatus> {
    const svc = service();
    if (!svc) {
      throw new Error("Desktop authentication is not available");
    }
    return svc.GetOAuthLoginStatus(sessionID);
  },
  async cancelOAuthLogin(sessionID: string): Promise<void> {
    await service()?.CancelOAuthLogin(sessionID);
  },
  async logout(): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.auth.logout();
      return;
    }
    await svc.Logout();
  },
  async repoStatus(): Promise<GUIRepoStatus> {
    const svc = service();
    if (!svc) {
      return api.gui.repo();
    }
    const repo = await svc.GetRepoStatus();
    return { selected: Boolean(repo?.path), repo };
  },
  async browseRepository(): Promise<GUIRepoStatus> {
    const svc = service();
    if (!svc) {
      throw new Error("Native repository picker is not available");
    }
    const repo = await svc.BrowseRepository();
    return { selected: Boolean(repo?.path), repo };
  },
  async selectRepository(path: string): Promise<GUIRepoStatus> {
    const svc = service();
    if (!svc) {
      return api.gui.selectRepo(path);
    }
    const repo = await svc.SelectRepository(path);
    return { selected: Boolean(repo?.path), repo };
  },
  async initialize(): Promise<InitResult> {
    const svc = service();
    if (!svc) {
      return api.init();
    }
    return svc.Initialize();
  },
  async gitInit(path: string): Promise<GUIRepoStatus> {
    const svc = service();
    if (!svc) {
      throw new Error("Desktop Git initialization is not available");
    }
    const repo = await svc.GitInit(path);
    return { selected: Boolean(repo?.path), repo };
  },
  async gitCreateRemote(
    path: string,
    owner: string,
    repoName: string,
    privateRepository: boolean,
  ): Promise<GUIRepoStatus> {
    const svc = service();
    if (!svc) {
      throw new Error("Desktop GitHub repository creation is not available");
    }
    const repo = await svc.GitCreateRemote(path, owner, repoName, privateRepository);
    return { selected: Boolean(repo?.path), repo };
  },
  async listRepositoryOwners(): Promise<RepositoryOwner[]> {
    const svc = service();
    if (!svc) {
      throw new Error("Desktop GitHub account selection is not available");
    }
    return svc.ListRepositoryOwners();
  },
  async listEnvironments(): Promise<Environment[]> {
    const svc = service();
    if (!svc) {
      return (await api.environments.list()).environments;
    }
    return svc.ListEnvironments();
  },
  async createEnvironment(name: string): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.environments.create(name);
      return;
    }
    await svc.CreateEnvironment(name);
  },
  async switchEnvironment(name: string): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.environments.switch(name);
      return;
    }
    await svc.SwitchEnvironment(name);
  },
  async renameEnvironment(name: string, newName: string): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.environments.rename(name, newName);
      return;
    }
    await svc.RenameEnvironment(name, newName);
  },
  async deleteEnvironment(name: string): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.environments.delete(name);
      return;
    }
    await svc.DeleteEnvironment(name);
  },
  async listSecrets(env = ""): Promise<SecretsResponse> {
    return service()?.ListSecrets(env) ?? api.secrets.list(env || undefined);
  },
  async addSecret(key: string, value: string, env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.add(key, value, env || undefined);
      return;
    }
    await svc.AddSecret(env, key, value);
  },
  async editSecret(key: string, value: string, env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.edit(key, value, env || undefined);
      return;
    }
    await svc.EditSecret(env, key, value);
  },
  async deleteSecret(key: string, env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.delete(key, env || undefined);
      return;
    }
    await svc.DeleteSecret(env, key);
  },
  async pullSecrets(env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.pull(env || undefined);
      return;
    }
    await svc.PullSecrets(env);
  },
  async exportSecrets(env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.export(env || undefined);
      return;
    }
    await svc.ExportSecrets(env);
  },
  async syncSecrets(env = ""): Promise<void> {
    const svc = service();
    if (!svc) {
      await api.secrets.sync(env || undefined);
      return;
    }
    await svc.SyncSecrets(env);
  },
  async listRepositories(): Promise<GUIRepoStatus["repo"][]> {
    const svc = service();
    if (!svc) return [];
    const items = await svc.ListRepositories();
    return items.map((r) => ({
      path: r.path,
      owner: r.owner,
      repo: r.repo,
      initialized: r.initialized,
    }));
  },
  async removeRepository(path: string): Promise<void> {
    await service()?.RemoveRepository(path);
  },
  async listRecipients(): Promise<Recipient[]> {
    const svc = service();
    if (!svc) return [];
    const items = await svc.ListRecipients();
    return items.map((r) => ({
      username: r.username,
      fingerprint: r.fingerprint,
      public_key: r.public_key,
    }));
  },
  async readConfig(): Promise<string> {
    const svc = service();
    if (!svc) throw new Error("Not available");
    return svc.ReadConfig();
  },
  async writeConfig(content: string): Promise<void> {
    await service()?.WriteConfig(content);
  },
  async appVersion(): Promise<string> {
    return (await service()?.GetAppVersion()) ?? "";
  },
};

export const backend = isMock ? mockBackend : realBackend;

export function openURL(url: string): void {
  // Wails injects window.runtime at startup; use it to open in OS browser
  // instead of spawning a new app window via window.open
  const wailsRuntime = (window as unknown as { runtime?: { BrowserOpenURL?: (u: string) => void } })
    .runtime;
  if (wailsRuntime?.BrowserOpenURL) {
    wailsRuntime.BrowserOpenURL(url);
  } else {
    window.open(url, "_blank");
  }
}

function normalizeAuthStatus(status: DesktopAuthStatus): AuthStatus {
  if (!status.repo) {
    return status;
  }
  return {
    ...status,
    repo: {
      owner: status.repo.owner,
      name: status.repo.name ?? status.repo.repo ?? "",
    },
  };
}
