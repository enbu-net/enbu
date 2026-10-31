import type {
  AuthStatus,
  ConflictChoice,
  ConflictSet,
  Diff,
  Environment,
  EnvironmentDeletion,
  GUIRepoStatus,
  Diagnosis,
  HistoryEntry,
  ImportResult,
  InitResult,
  KeyUpdateResult,
  PublicInfo,
  JoinRequest,
  Member,
  OAuthStart,
  OAuthStatus,
  PullResult,
  RepoInfo,
  SecretsResponse,
} from "./types";
import { createAppError } from "./app-error";
import type { Backend } from "./backend";

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

// Staging shows what two people editing one secret at the same time looks like.
let mockConflictsByEnv: Record<string, ConflictSet> = {
  staging: {
    environment: "staging",
    heads: ["mock-head-a", "mock-head-b"],
    conflicts: [
      {
        key: "API_KEY",
        candidates: [
          { value: "sk-stg-abc123", deleted: false },
          { value: "sk-stg-rotated", deleted: false },
        ],
      },
    ],
  },
};

// Each environment's past contents, oldest first; the last is the current one.
const mockHistoryByEnv: Record<string, { timestamp: string; secrets: Record<string, string> }[]> = {
  development: [
    {
      timestamp: "2026-10-01T09:00:00Z",
      secrets: { API_KEY: "sk-demo-old", DATABASE_URL: "postgres://localhost:5432/enbu" },
    },
    {
      timestamp: "2026-10-05T14:20:00Z",
      secrets: {
        API_KEY: "sk-demo-abc123",
        DATABASE_URL: "postgres://localhost:5432/enbu",
        SECRET_TOKEN: "tok-enbu-xyz789",
      },
    },
  ],
};

function diffSecrets(from: Record<string, string>, to: Record<string, string>): Diff {
  const keys = (record: Record<string, string>) => Object.keys(record).sort();
  return {
    added: keys(to).filter((key) => !(key in from)),
    removed: keys(from).filter((key) => !(key in to)),
    modified: keys(to).filter((key) => key in from && from[key] !== to[key]),
  };
}

let mockMembers: Member[] = [
  {
    device_id: "aabbccdd".repeat(8),
    fingerprint: "aabb-ccdd-aabb-ccdd-aabb",
    algorithm: "p256",
    admin: true,
    self: true,
    post_quantum: false,
  },
  {
    device_id: "11223344".repeat(8),
    fingerprint: "1122-3344-1122-3344-1122",
    algorithm: "ed25519",
    admin: false,
    self: false,
    post_quantum: true,
  },
];

let mockJoinRequests: JoinRequest[] = [
  {
    device_id: "55667788".repeat(8),
    fingerprint: "5566-7788-5566-7788-5566",
    algorithm: "p256",
    requested_at: "2026-10-06T09:30:00Z",
    key_update: false,
  },
];

const mockRepoHistory: RepoInfo[] = [
  {
    path: "/demo/enbu",
    owner: "enbu-net",
    repo: "enbu",
    initialized: true,
    has_git: true,
    has_remote: true,
    storage_configured: true,
  },
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

export const mockBackend: Backend = {
  async authStatus(): Promise<AuthStatus> {
    return {
      authenticated: true,
      username: previewUsername,
      workspace_configured: true,
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
    return { selected: true, repo: Object.assign({}, selected) };
  },

  async browseRepository(): Promise<GUIRepoStatus> {
    return mockBackend.repoStatus();
  },

  async selectRepository(path: string): Promise<GUIRepoStatus> {
    mockSelectedRepoPath = path;
    return mockBackend.repoStatus();
  },

  async initialize(): Promise<InitResult> {
    return {
      public_key: "age1demo...",
      username: previewUsername,
      environment: "development",
      device_id: mockMembers[0].device_id,
      fingerprint: mockMembers[0].fingerprint,
      pending: false,
    };
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
    mockEnvs = mockEnvs.map((e) => ({ name: e.name, current: e.name === name }));
  },

  async renameEnvironment(name: string, newName: string): Promise<void> {
    mockEnvs = mockEnvs.map((e) => (e.name === name ? { name: newName, current: e.current } : e));
    if (mockSecretsByEnv[name]) {
      mockSecretsByEnv[newName] = mockSecretsByEnv[name];
      delete mockSecretsByEnv[name];
    }
  },

  async deleteEnvironment(name: string, purge: boolean): Promise<EnvironmentDeletion> {
    if (currentEnvName() === name) throw createAppError("invalid_argument", { name });
    mockEnvs = mockEnvs.filter((e) => e.name !== name);
    delete mockSecretsByEnv[name];
    return purge
      ? { purged: mockHistoryByEnv[name]?.length ?? 0 }
      : { purged: 0, incarnation: "0b6f2c1e-6a4d-4c47-9d1e-3f2a7c5b8e90" };
  },

  async purgeIncarnation(_incarnation: string): Promise<number> {
    return 1;
  },

  async listSecrets(env = ""): Promise<SecretsResponse> {
    const name = env || currentEnvName();
    const conflicted = mockConflictsByEnv[name]?.conflicts.map((c) => c.key) ?? [];
    if (conflicted.length > 0)
      throw createAppError("secret_conflict", { keys: conflicted.join(", ") });
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

  async pullSecrets(env = "", _replace = false): Promise<PullResult> {
    return { output: ".env", count: secretsForEnv(env).length, kept: [], removed: [] };
  },

  async syncSecrets(_env = ""): Promise<void> {
    // no-op in mock
  },
  async listConflicts(env = ""): Promise<ConflictSet> {
    const name = env || currentEnvName();
    return mockConflictsByEnv[name] ?? { environment: name, heads: [], conflicts: [] };
  },
  async resolveConflicts(env: string, heads: string[], choices: ConflictChoice[]): Promise<void> {
    const name = env || currentEnvName();
    const set = mockConflictsByEnv[name];
    if (!set || set.heads.join() !== heads.join()) throw createAppError("conflict");
    if (set.conflicts.some((c) => !choices.some((choice) => choice.key === c.key))) {
      throw createAppError("secret_conflict", { keys: set.conflicts.map((c) => c.key).join(", ") });
    }
    const secrets = secretsForEnv(name).filter((s) => !choices.some((c) => c.key === s.key));
    for (const choice of choices) {
      if (!choice.delete) secrets.push({ key: choice.key, value: choice.value });
    }
    mockSecretsByEnv[name] = secrets.sort((a, b) => a.key.localeCompare(b.key));
    const { [name]: _resolved, ...rest } = mockConflictsByEnv;
    mockConflictsByEnv = rest;
  },
  async listHistory(env: string): Promise<HistoryEntry[]> {
    return (mockHistoryByEnv[env || currentEnvName()] ?? []).map((entry, i) => ({
      index: i + 1,
      timestamp: entry.timestamp,
      tag: `mock-revision-${i + 1}`,
    }));
  },
  async diffHistory(env: string, from: number, to: number): Promise<Diff> {
    const history = mockHistoryByEnv[env || currentEnvName()] ?? [];
    const at = (index: number) => {
      const entry = history[index - 1];
      if (!entry) throw createAppError("invalid_argument", { index: String(index) });
      return entry.secrets;
    };
    return diffSecrets(at(from), at(to));
  },
  async restoreHistory(env: string, index: number): Promise<void> {
    const name = env || currentEnvName();
    const history = (mockHistoryByEnv[name] ??= []);
    const entry = history[index - 1];
    if (!entry) throw createAppError("invalid_argument", { index: String(index) });
    history.push({ timestamp: new Date().toISOString(), secrets: { ...entry.secrets } });
    mockSecretsByEnv[name] = Object.entries(entry.secrets)
      .map(([key, value]) => ({ key, value }))
      .sort((a, b) => a.key.localeCompare(b.key));
  },
  async importSecrets(dotenv: string, overwrite: boolean, env = ""): Promise<ImportResult> {
    const name = env || currentEnvName();
    const secrets = secretsForEnv(name);
    const result: ImportResult = { environment: name, added: [], updated: [], unchanged: [] };
    const incoming = dotenv
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => {
        const at = line.indexOf("=");
        return { key: line.slice(0, at).trim(), value: line.slice(at + 1).replace(/^"|"$/g, "") };
      });
    if (incoming.length === 0) throw createAppError("invalid_argument");
    const changed = incoming.filter((item) =>
      secrets.some((s) => s.key === item.key && s.value !== item.value),
    );
    if (changed.length > 0 && !overwrite) {
      throw createAppError("secret_already_exists", {
        keys: changed.map((item) => item.key).join(","),
      });
    }
    for (const item of incoming) {
      const existing = secrets.find((s) => s.key === item.key);
      if (!existing) result.added.push(item.key);
      else if (existing.value === item.value) result.unchanged.push(item.key);
      else result.updated.push(item.key);
      await mockBackend.addSecret(item.key, item.value, name);
    }
    return result;
  },
  async listRepositories(): Promise<RepoInfo[]> {
    return [...mockRepoHistory];
  },
  async removeRepository(path: string): Promise<void> {
    const idx = mockRepoHistory.findIndex((r) => r.path === path);
    if (idx >= 0) mockRepoHistory.splice(idx, 1);
    if (mockSelectedRepoPath === path) mockSelectedRepoPath = "";
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
        post_quantum: true,
      },
    ];
  },
  async removeMember(deviceID: string): Promise<void> {
    if (!mockMembers.some((m) => m.device_id === deviceID))
      throw createAppError("invalid_argument");
    mockMembers = mockMembers.filter((m) => m.device_id !== deviceID);
  },
  async setAdmin(deviceID: string, admin: boolean): Promise<void> {
    if (!mockMembers.some((m) => m.device_id === deviceID))
      throw createAppError("invalid_argument");
    mockMembers = mockMembers.map((m) =>
      m.device_id === deviceID ? Object.assign({}, m, { admin }) : m,
    );
  },
  async resolveMemberFork(): Promise<void> {
    throw createAppError("invalid_argument");
  },
  async identity(): Promise<PublicInfo> {
    const self = mockMembers[0];
    return {
      backend: "keyring",
      algorithm: self.post_quantum ? "ML-KEM-768+X25519" : "X25519",
      recipient: self.post_quantum ? "age1pq1demo..." : "age1demo...",
      device_id: self.device_id,
      fingerprint: self.fingerprint,
    };
  },
  async diagnoseIdentity(): Promise<Diagnosis> {
    return {
      backend: "tpm",
      available: false,
      fallback_available: true,
    };
  },
  async upgradeIdentity(): Promise<KeyUpdateResult> {
    mockMembers = mockMembers.map((m) =>
      m.self ? Object.assign({}, m, { post_quantum: true }) : m,
    );
    const self = mockMembers[0];
    return {
      backend: "keyring",
      algorithm: "ML-KEM-768+X25519",
      recipient: "age1pq1demo...",
      device_id: self.device_id,
      fingerprint: self.fingerprint,
      pending: false,
    };
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
