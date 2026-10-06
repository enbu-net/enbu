import type {
  AuthStatus,
  Environment,
  GUIRepoStatus,
  InitResult,
  JoinRequest,
  Member,
  Recipient,
  SecretsResponse,
} from "./api";
import { createAppError } from "./app-error";
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

let mockMembers: Member[] = [
  {
    device_id: "aabbccdd".repeat(8),
    fingerprint: "aabb-ccdd-aabb-ccdd-aabb",
    algorithm: "p256",
    admin: true,
    self: true,
  },
  {
    device_id: "11223344".repeat(8),
    fingerprint: "1122-3344-1122-3344-1122",
    algorithm: "ed25519",
    admin: false,
    self: false,
  },
];

let mockJoinRequests: JoinRequest[] = [
  {
    device_id: "55667788".repeat(8),
    fingerprint: "5566-7788-5566-7788-5566",
    algorithm: "p256",
    requested_at: "2026-10-06T09:30:00Z",
  },
];

const mockRepoHistory: NonNullable<GUIRepoStatus["repo"]>[] = [
  { path: "/demo/enbu", owner: "enbu-net", repo: "enbu", initialized: true },
];
let mockSelectedRepoPath = mockRepoHistory[0]?.path ?? "";

let mockConfig = `version = "v1alpha2"\ndefault_env = "default"\n`;

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
  async listMembers(): Promise<Member[]> {
    return [...mockMembers];
  },
  async listJoinRequests(): Promise<JoinRequest[]> {
    return [...mockJoinRequests];
  },
  async approveMember(deviceID: string): Promise<void> {
    const request = mockJoinRequests.find((r) => r.device_id === deviceID);
    if (!request) throw createAppError("invalid_argument");
    mockJoinRequests = mockJoinRequests.filter((r) => r.device_id !== deviceID);
    mockMembers = [
      ...mockMembers,
      {
        device_id: request.device_id,
        fingerprint: request.fingerprint,
        algorithm: request.algorithm,
        admin: false,
        self: false,
      },
    ];
  },
  async removeMember(deviceID: string): Promise<void> {
    if (!mockMembers.some((m) => m.device_id === deviceID))
      throw createAppError("invalid_argument");
    mockMembers = mockMembers.filter((m) => m.device_id !== deviceID);
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
