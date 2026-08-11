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
