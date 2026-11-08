// The data the desktop backend exchanges with the UI. The types come from the
// Go structs through the generated bindings, so a field changed in Go is a
// type error here.
export type {
  AuthStatus,
  ConflictRetry,
  IdentityDiagnosis,
  OAuthStart,
  OAuthStatus,
  RepoInfo,
  SecretItem,
  SecretsResponse,
} from "../bindings/github.com/enbu-net/enbu/desktop/models";
export type {
  ConflictCandidate,
  ConflictSet,
  Diff,
  EnvInfo,
  EnvironmentDeletion,
  HistoryEntry,
  ImportResult,
  InitResult,
  JoinRequestInfo,
  MemberInfo,
  ProgressStep,
  SecretChoice,
  SecretConflict,
  WrittenFile,
} from "../bindings/github.com/enbu-net/enbu/app/models";
export type { PublicInfo } from "../bindings/github.com/enbu-net/enbu/pkg/identity/models";

import type { RepoInfo } from "../bindings/github.com/enbu-net/enbu/desktop/models";
import type { StorageConfig as StorageConfigModel } from "../bindings/github.com/enbu-net/enbu/pkg/config/models";

/** Where Initialize founds a workspace. The UI builds it, so it is a plain object. */
export type StorageConfig = Pick<StorageConfigModel, keyof StorageConfigModel>;

/** What the backend reports when no repository is selected: no path. */
export const noRepo: RepoInfo = {
  initialized: false,
  has_git: false,
  has_remote: false,
  storage_configured: false,
};
