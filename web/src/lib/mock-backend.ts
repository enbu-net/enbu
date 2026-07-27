import type {
  AuthStatus,
  Environment,
  GUIRepoStatus,
  InitResult,
  Recipient,
  SecretsResponse,
} from "./api";
import type { OAuthStart, OAuthStatus } from "./backend";

const previewUsername = "yashikota";

let mockEnvs: Environment[] = [
  { name: "development", current: true },
  { name: "production", current: false },
  { name: "staging", current: false },
];

let mockSecretsByEnv: Record<string, { key: string; value: string }[]> = {
  development: [
    { key: "API_KEY", value: "sk-demo-abc123" },
    { key: "DATABASE_URL", value: "postgres://localhost:5432/enbu" },
    { key: "SECRET_TOKEN", value: "tok-enbu-xyz789" },
  ],
  production: [
    { key: "API_KEY", value: "sk-prod-abc123" },
    { key: "DATABASE_URL", value: "postgres://prod.example.com:5432/enbu" },
    { key: "SECRET_TOKEN", value: "tok-prod-xyz789" },
  ],
  staging: [
    { key: "API_KEY", value: "sk-stg-abc123" },
    { key: "DATABASE_URL", value: "postgres://staging.example.com:5432/enbu" },
  ],
};

const mockRecipients: Recipient[] = [
  {
    username: previewUsername,
    fingerprint: "aabbccdd",
    public_key: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysqqp",
  },
  {
    username: "collaborator",
    fingerprint: "11223344",
    public_key: "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysqqa",
  },
];

const mockRepoHistory: NonNullable<GUIRepoStatus["repo"]>[] = [
  { path: "/demo/enbu", owner: "enbu-net", repo: "enbu", initialized: true },
];
let mockSelectedRepoPath = mockRepoHistory[0]?.path ?? "";

let mockConfig = `version = "v1alpha1"\ndefault_env = "default"\n`;

function currentEnvName(): string {
  return mockEnvs.find((e) => e.current)?.name ?? "development";
}

function secretsForEnv(env: string): { key: string; value: string }[] {
  const name = env || currentEnvName();
  return (mockSecretsByEnv[name] ??= []);
}

export const mockBackend = {
  async authStatus(): Promise<AuthStatus> {
    return {
      authenticated: true,
      username: previewUsername,
      repo: { owner: "enbu-net", name: "enbu" },
    };
  },

  async startOAuthLogin(): Promise<OAuthStart> {
    throw new Error("Mock mode: auth is pre-configured");
  },

  async oauthStatus(_sessionID: string): Promise<OAuthStatus> {
    throw new Error("Mock mode: auth is pre-configured");
  },

  async cancelOAuthLogin(_sessionID: string): Promise<void> {
    // no-op
  },

  async logout(): Promise<void> {
    // no-op
  },

  async repoStatus(): Promise<GUIRepoStatus> {
    const selected = mockRepoHistory.find((repo) => repo.path === mockSelectedRepoPath);
    if (!selected) return { selected: false };
    return {
      selected: true,
      repo: {
        ...selected,
        has_git: true,
        has_remote: true,
      },
    };
  },

  async browseRepository(): Promise<GUIRepoStatus> {
    return mockBackend.repoStatus();
  },

  async selectRepository(path: string): Promise<GUIRepoStatus> {
    mockSelectedRepoPath = path;
    return mockBackend.repoStatus();
  },

  async initialize(): Promise<InitResult> {
    return { public_key: "age1demo...", username: previewUsername, environment: "development" };
  },

  async gitInit(_path: string): Promise<GUIRepoStatus> {
    return mockBackend.repoStatus();
  },

  async gitCreateRemote(
    _path: string,
    _owner: string,
    _repoName: string,
    _privateRepository: boolean,
  ): Promise<GUIRepoStatus> {
    return mockBackend.repoStatus();
  },

  async listRepositoryOwners() {
    return [
      { login: previewUsername, organization: false },
      { login: "enbu-net", organization: true },
    ];
  },

  async listEnvironments(): Promise<Environment[]> {
    return [...mockEnvs];
  },

  async createEnvironment(name: string): Promise<void> {
    if (!mockEnvs.find((e) => e.name === name)) {
      mockEnvs.push({ name, current: false });
      mockSecretsByEnv[name] = [];
    }
  },

  async switchEnvironment(name: string): Promise<void> {
    mockEnvs = mockEnvs.map((e) => ({ ...e, current: e.name === name }));
  },

  async renameEnvironment(name: string, newName: string): Promise<void> {
    mockEnvs = mockEnvs.map((e) => (e.name === name ? { ...e, name: newName } : e));
    if (mockSecretsByEnv[name]) {
      mockSecretsByEnv[newName] = mockSecretsByEnv[name];
      delete mockSecretsByEnv[name];
    }
  },

  async deleteEnvironment(name: string): Promise<void> {
    mockEnvs = mockEnvs.filter((e) => e.name !== name);
    delete mockSecretsByEnv[name];
  },

  async listSecrets(env = ""): Promise<SecretsResponse> {
    const name = env || currentEnvName();
    return { environment: name, secrets: [...secretsForEnv(name)] };
  },

  async addSecret(key: string, value: string, env = ""): Promise<void> {
    const secrets = secretsForEnv(env);
    const idx = secrets.findIndex((s) => s.key === key);
    if (idx >= 0) {
      secrets[idx].value = value;
    } else {
      secrets.push({ key, value });
      secrets.sort((a, b) => a.key.localeCompare(b.key));
    }
  },

  async editSecret(key: string, value: string, env = ""): Promise<void> {
    const secrets = secretsForEnv(env);
    const s = secrets.find((s) => s.key === key);
    if (s) s.value = value;
  },

  async deleteSecret(key: string, env = ""): Promise<void> {
    const name = env || currentEnvName();
    mockSecretsByEnv[name] = secretsForEnv(env).filter((s) => s.key !== key);
  },

  async pullSecrets(_env = ""): Promise<void> {
    // no-op in mock
  },

  async exportSecrets(_env = ""): Promise<void> {
    // no-op in mock
  },

  async syncSecrets(_env = ""): Promise<void> {
    // no-op in mock
  },
  async listRepositories(): Promise<NonNullable<GUIRepoStatus["repo"]>[]> {
    return [...mockRepoHistory];
  },
  async removeRepository(path: string): Promise<void> {
    const idx = mockRepoHistory.findIndex((r) => r.path === path);
    if (idx >= 0) mockRepoHistory.splice(idx, 1);
    if (mockSelectedRepoPath === path) mockSelectedRepoPath = "";
  },
  async listRecipients(): Promise<Recipient[]> {
    return [...mockRecipients];
  },
  async readConfig(): Promise<string> {
    return mockConfig;
  },
  async writeConfig(content: string): Promise<void> {
    mockConfig = content;
  },
  async appVersion(): Promise<string> {
    return "";
  },
};
