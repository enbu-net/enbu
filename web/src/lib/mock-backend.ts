import type {
  UpdateMethod,
  UpdateStatus,
  AuthStatus,
  ConflictSet,
  Diff,
  EnvInfo,
  EnvironmentDeletion,
  HistoryEntry,
  IdentityDiagnosis,
  ImportResult,
  InitResult,
  JoinRequestInfo,
  MemberInfo,
  OAuthStart,
  OAuthStatus,
  PublicInfo,
  RepoInfo,
  SecretChoice,
  SecretsResponse,
  StorageConfig,
  WrittenFile,
} from "./types";
import { noRepo } from "./types";
import { createAppError } from "./app-error";
import type { Backend } from "./backend";

const previewUsername = "yashikota";

let mockEnvs: EnvInfo[] = [
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
    id: "mock-conflict",
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

let mockMembers: MemberInfo[] = [
  {
    device_id: "aabbccdd".repeat(8),
    fingerprint: "aabb-ccdd-aabb-ccdd-aabb",
    recipient: "age1pq1demo-self",
    algorithm: "p256",
    admin: true,
    self: true,
  },
  {
    device_id: "11223344".repeat(8),
    fingerprint: "1122-3344-1122-3344-1122",
    recipient: "age1pq1demo-peer",
    algorithm: "ed25519",
    admin: false,
    self: false,
  },
];

let mockJoinRequests: JoinRequestInfo[] = [
  {
    device_id: "55667788".repeat(8),
    fingerprint: "5566-7788-5566-7788-5566",
    recipient: "age1pq1demo-request",
    algorithm: "p256",
    requested_at: "2026-10-06T09:30:00Z",
  },
];

const mockRepoHistory: RepoInfo[] = [
  {
    path: "/demo/enbu",
    owner: "enbu-net",
    repo: "enbu",
    initialized: true,
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

// Two signed-in accounts, so the preview shows switching and signing out.
let mockAccounts = ["octocat", previewUsername];
let mockCurrentAccount = previewUsername;

export const mockBackend: Backend = {
  async GetAuthStatus(): Promise<AuthStatus> {
    return {
      authenticated: mockCurrentAccount !== "",
      username: mockCurrentAccount,
      accounts: [...mockAccounts],
      workspace_configured: true,
    };
  },

  async StartOAuthLogin(): Promise<OAuthStart> {
    throw new Error("Mock mode: auth is pre-configured");
  },

  async GetOAuthLoginStatus(_sessionID: string): Promise<OAuthStatus> {
    throw new Error("Mock mode: auth is pre-configured");
  },

  async CancelOAuthLogin(_sessionID: string): Promise<void> {
    // no-op
  },

  async Logout(login: string): Promise<void> {
    const gone = login || mockCurrentAccount;
    mockAccounts = mockAccounts.filter((account) => account !== gone);
    if (gone === mockCurrentAccount) mockCurrentAccount = mockAccounts.at(-1) ?? "";
  },

  async SwitchAccount(login: string): Promise<void> {
    if (!mockAccounts.includes(login)) throw createAppError("invalid_argument");
    mockCurrentAccount = login;
  },

  async GetRepoStatus(): Promise<RepoInfo> {
    const selected = mockRepoHistory.find((repo) => repo.path === mockSelectedRepoPath);
    return selected ? Object.assign({}, selected) : Object.assign({}, noRepo);
  },

  async BrowseRepository(): Promise<RepoInfo> {
    return mockBackend.GetRepoStatus();
  },

  async SelectRepository(path: string): Promise<RepoInfo> {
    mockSelectedRepoPath = path;
    return mockBackend.GetRepoStatus();
  },

  async Initialize(storage: StorageConfig): Promise<InitResult> {
    return {
      public_key: "age1demo...",
      username: previewUsername,
      environment: "development",
      workspace_id: "3f2b8c1e-9a4d-4e6b-8c2f-1a5d7e9b0c3d",
      control_genesis: "",
      key_created: true,
      mode: "initialize",
      has_secrets: false,
      can_decrypt: null,
      device_id: mockMembers[0].device_id,
      fingerprint: mockMembers[0].fingerprint,
      pending: false,
      storage: storage.url || "oci://ghcr.io/enbu-net/enbu-enbu",
      founded: true,
    };
  },

  async SuggestStorage(): Promise<string> {
    return "oci://ghcr.io/enbu-net/enbu-enbu";
  },

  async ListEnvironments(): Promise<EnvInfo[]> {
    return [...mockEnvs];
  },

  async CreateEnvironment(name: string): Promise<void> {
    if (!mockEnvs.find((e) => e.name === name)) {
      mockEnvs.push({ name, current: false });
      mockSecretsByEnv[name] = [];
    }
  },

  async SwitchEnvironment(name: string): Promise<void> {
    mockEnvs = mockEnvs.map((e) => ({ name: e.name, current: e.name === name }));
  },

  async RenameEnvironment(name: string, newName: string): Promise<void> {
    mockEnvs = mockEnvs.map((e) => (e.name === name ? { name: newName, current: e.current } : e));
    if (mockSecretsByEnv[name]) {
      mockSecretsByEnv[newName] = mockSecretsByEnv[name];
      delete mockSecretsByEnv[name];
    }
  },

  async DeleteEnvironment(name: string, purge: boolean): Promise<EnvironmentDeletion> {
    if (currentEnvName() === name) throw createAppError("invalid_argument", { name });
    mockEnvs = mockEnvs.filter((e) => e.name !== name);
    delete mockSecretsByEnv[name];
    return purge
      ? { purged: mockHistoryByEnv[name]?.length ?? 0 }
      : { purged: 0, incarnation: "0b6f2c1e-6a4d-4c47-9d1e-3f2a7c5b8e90" };
  },

  async PurgeIncarnation(_incarnation: string): Promise<number> {
    return 1;
  },

  async ListSecrets(env: string): Promise<SecretsResponse> {
    const name = env || currentEnvName();
    const conflicted = mockConflictsByEnv[name]?.conflicts.map((c) => c.key) ?? [];
    if (conflicted.length > 0)
      throw createAppError("secret_conflict", { keys: conflicted.join(", ") });
    return { environment: name, secrets: [...secretsForEnv(name)] };
  },

  async AddSecret(env: string, key: string, value: string): Promise<void> {
    const secrets = secretsForEnv(env);
    const idx = secrets.findIndex((s) => s.key === key);
    if (idx >= 0) {
      secrets[idx].value = value;
    } else {
      secrets.push({ key, value });
      secrets.sort((a, b) => a.key.localeCompare(b.key));
    }
  },

  async EditSecret(env: string, key: string, value: string): Promise<void> {
    const secrets = secretsForEnv(env);
    const s = secrets.find((s) => s.key === key);
    if (s) s.value = value;
  },

  async DeleteSecret(env: string, key: string): Promise<void> {
    const name = env || currentEnvName();
    mockSecretsByEnv[name] = secretsForEnv(env).filter((s) => s.key !== key);
  },

  async PullSecrets(env: string, _replace: boolean): Promise<WrittenFile> {
    return { output: ".env", count: secretsForEnv(env).length, kept: [], removed: [] };
  },

  async SyncSecrets(_env: string): Promise<void> {
    // no-op in mock
  },
  async ListConflicts(env: string): Promise<ConflictSet> {
    const name = env || currentEnvName();
    return mockConflictsByEnv[name] ?? { environment: name, id: "", heads: [], conflicts: [] };
  },
  async ResolveConflicts(env: string, heads: string[], choices: SecretChoice[]): Promise<void> {
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
  async ListHistory(env: string): Promise<HistoryEntry[]> {
    return (mockHistoryByEnv[env || currentEnvName()] ?? []).map((entry, i) => ({
      index: i + 1,
      timestamp: entry.timestamp,
      tag: `mock-revision-${i + 1}`,
    }));
  },
  async DiffHistory(env: string, from: number, to: number): Promise<Diff> {
    const history = mockHistoryByEnv[env || currentEnvName()] ?? [];
    const at = (index: number) => {
      const entry = history[index - 1];
      if (!entry) throw createAppError("invalid_argument", { index: String(index) });
      return entry.secrets;
    };
    return diffSecrets(at(from), at(to));
  },
  async RestoreHistory(env: string, index: number): Promise<void> {
    const name = env || currentEnvName();
    const history = (mockHistoryByEnv[name] ??= []);
    const entry = history[index - 1];
    if (!entry) throw createAppError("invalid_argument", { index: String(index) });
    history.push({ timestamp: new Date().toISOString(), secrets: { ...entry.secrets } });
    mockSecretsByEnv[name] = Object.entries(entry.secrets)
      .map(([key, value]) => ({ key, value }))
      .sort((a, b) => a.key.localeCompare(b.key));
  },
  async ImportSecrets(env: string, dotenv: string, overwrite: boolean): Promise<ImportResult> {
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
      await mockBackend.AddSecret(name, item.key, item.value);
    }
    return result;
  },
  async ListRepositories(): Promise<RepoInfo[]> {
    return [...mockRepoHistory];
  },
  async RemoveRepository(path: string): Promise<void> {
    const idx = mockRepoHistory.findIndex((r) => r.path === path);
    if (idx >= 0) mockRepoHistory.splice(idx, 1);
    if (mockSelectedRepoPath === path) mockSelectedRepoPath = "";
  },
  async ListMembers(): Promise<MemberInfo[]> {
    return [...mockMembers];
  },
  async ListJoinRequests(): Promise<JoinRequestInfo[]> {
    return [...mockJoinRequests];
  },
  async ApproveMember(deviceID: string): Promise<void> {
    const request = mockJoinRequests.find((r) => r.device_id === deviceID);
    if (!request) throw createAppError("invalid_argument");
    mockJoinRequests = mockJoinRequests.filter((r) => r.device_id !== deviceID);
    mockMembers = [
      ...mockMembers,
      {
        device_id: request.device_id,
        fingerprint: request.fingerprint,
        recipient: request.recipient,
        algorithm: request.algorithm,
        admin: false,
        self: false,
      },
    ];
  },
  async RemoveMember(deviceID: string): Promise<void> {
    if (!mockMembers.some((m) => m.device_id === deviceID))
      throw createAppError("invalid_argument");
    mockMembers = mockMembers.filter((m) => m.device_id !== deviceID);
  },
  async SetAdmin(deviceID: string, admin: boolean): Promise<void> {
    if (!mockMembers.some((m) => m.device_id === deviceID))
      throw createAppError("invalid_argument");
    mockMembers = mockMembers.map((m) =>
      m.device_id === deviceID ? Object.assign({}, m, { admin }) : m,
    );
  },
  async GetIdentity(): Promise<PublicInfo> {
    const self = mockMembers[0];
    return {
      backend: "keyring",
      algorithm: "MLKEM768-X25519",
      recipient: "age1pq1demo...",
      device_id: self.device_id,
      fingerprint: self.fingerprint,
    };
  },
  async DiagnoseIdentity(): Promise<IdentityDiagnosis> {
    return {
      backend: "tpm",
      available: false,
      denied: false,
      fallback_available: true,
      keyring_locked: false,
    };
  },
  async ReadConfig(): Promise<string> {
    return mockConfig;
  },
  async WriteConfig(content: string): Promise<void> {
    mockConfig = content;
  },
  async GetAppVersion(): Promise<string> {
    return "";
  },
  // The preview is not a release; it has nothing to update.
  async CheckForUpdate(): Promise<UpdateStatus> {
    return { method: "development" as UpdateMethod, current: "", available: false };
  },
  async InstallUpdate(): Promise<UpdateStatus> {
    throw createAppError("invalid_argument");
  },
  async RestartApp(): Promise<void> {
    throw createAppError("invalid_argument");
  },
};
