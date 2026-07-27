function getCsrfToken(): string {
  const match = document.cookie.match(/(?:^|; )enbu_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-ENBU-Token": getCsrfToken(),
  };

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    let errorMessage = "";
    try {
      const errJson = JSON.parse(text) as { error?: { message?: string } };
      errorMessage = errJson.error?.message ?? "";
    } catch {
      // ignore JSON parse errors
    }
    if (errorMessage) {
      throw new Error(errorMessage);
    }
    throw new Error(text || `HTTP ${res.status}`);
  }

  const json = (await res.json()) as { data: T; error?: { message: string } };
  if (json.error) {
    throw new Error(json.error.message);
  }
  return json.data;
}

export const api = {
  gui: {
    repo: () => request<GUIRepoStatus>("GET", "/api/gui/repo"),
    selectRepo: (path: string) => request<GUIRepoStatus>("POST", "/api/gui/repo", { path }),
  },
  auth: {
    status: () => request<AuthStatus>("GET", "/api/auth/status"),
    login: () => request<{ redirect_url: string }>("GET", "/api/auth/login"),
    logout: () => request<{ status: string }>("POST", "/api/auth/logout"),
  },
  repo: {
    status: () => request<RepoStatus>("GET", "/api/repo"),
  },
  init: () => request<InitResult>("POST", "/api/init"),
  environments: {
    list: () => request<{ environments: Environment[] }>("GET", "/api/environments"),
    create: (name: string) => request<{ name: string }>("POST", "/api/environments", { name }),
    switch: (name: string) =>
      request<{ current: string }>("PUT", `/api/environments/${name}/switch`),
    rename: (name: string, newName: string) =>
      request<{ name: string }>("PUT", `/api/environments/${name}`, { new_name: newName }),
    delete: (name: string) => request<{ deleted: string }>("DELETE", `/api/environments/${name}`),
  },
  secrets: {
    list: (env?: string) =>
      request<SecretsResponse>("GET", `/api/secrets${env ? `?env=${env}` : ""}`),
    add: (key: string, value: string, env?: string) =>
      request<{ key: string }>("POST", "/api/secrets", { key, value, env }),
    edit: (key: string, value: string, env?: string) =>
      request<{ key: string }>("PUT", `/api/secrets/${key}`, { value, env }),
    delete: (key: string, env?: string) =>
      request<{ deleted: string }>("DELETE", `/api/secrets/${key}${env ? `?env=${env}` : ""}`),
    pull: (env?: string) => request<{ status: string }>("POST", "/api/secrets/pull", { env }),
    export: (env?: string) => request<{ status: string }>("POST", "/api/secrets/export", { env }),
    sync: (env?: string) => request<{ status: string }>("POST", "/api/secrets/sync", { env }),
  },
  history: {
    list: (env?: string) =>
      request<{ entries: HistoryEntry[] }>("GET", `/api/history${env ? `?env=${env}` : ""}`),
    diff: (from: number, to: number, env?: string) =>
      request<DiffResult>(
        "GET",
        `/api/history/diff?from=${from}&to=${to}${env ? `&env=${env}` : ""}`,
      ),
    restore: (index: number, env?: string) =>
      request<{ status: string }>(
        "POST",
        `/api/history/${index}/restore${env ? `?env=${env}` : ""}`,
      ),
  },
};

export interface AuthStatus {
  authenticated: boolean;
  username?: string;
  repo?: { owner: string; name: string };
}

export interface Recipient {
  username: string;
  fingerprint: string;
  public_key: string;
}

export interface GUIRepoStatus {
  selected: boolean;
  repo?: {
    path: string;
    owner: string;
    repo: string;
    initialized?: boolean;
    has_git?: boolean;
    has_remote?: boolean;
  };
}

export interface RepoStatus {
  owner: string;
  repo: string;
  initialized: boolean;
}

export interface InitResult {
  public_key: string;
  username: string;
  environment: string;
}

export interface Environment {
  name: string;
  current: boolean;
}

export interface SecretsResponse {
  environment: string;
  cached?: boolean;
  secrets: { key: string; value: string }[];
}

export interface HistoryEntry {
  index: number;
  timestamp: string;
  tag: string;
}

export interface DiffResult {
  added: string[];
  removed: string[];
  modified: string[];
}
