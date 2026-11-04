// The data the desktop backend exchanges with the UI. Most types come from the
// Go structs through the generated bindings, so a field changed in Go is a
// type error here; only the shapes the UI builds itself are declared below.
export type {
  AuthStatus,
  ConflictCandidate,
  ConflictChoice,
  ConflictRetry,
  ConflictSet,
  Environment,
  EnvironmentDeletion,
  HistoryEntry,
  InitResult,
  JoinRequest,
  Member,
  OAuthStart,
  PullResult,
  RepoInfo,
  SecretConflict,
  SecretItem,
  SecretsResponse,
} from "../bindings/github.com/enbu-net/enbu/desktop/models";
export type {
  Diff,
  ImportResult,
  KeyUpdateResult,
  ProgressStep,
} from "../bindings/github.com/enbu-net/enbu/app/models";
export type { PublicInfo } from "../bindings/github.com/enbu-net/enbu/pkg/identity/models";

import type { RepoInfo } from "../bindings/github.com/enbu-net/enbu/desktop/models";
export type { IdentityDiagnosis as Diagnosis } from "../bindings/github.com/enbu-net/enbu/desktop/models";
import type { DisplayError } from "./app-error";

/** The repository the app works on; repo is unset until one is selected. */
export interface GUIRepoStatus {
  selected: boolean;
  repo?: RepoInfo;
}

export interface OAuthStatus {
  state: "pending" | "success" | "expired" | "denied" | "error";
  error?: DisplayError;
  username?: string;
}

/** Where Initialize founds a workspace: the storage and `enbu init`'s flags for it. */
export interface StorageSettings {
  url: string;
  region: string;
  endpoint: string;
  path_style: boolean;
  plain_http: boolean;
}
