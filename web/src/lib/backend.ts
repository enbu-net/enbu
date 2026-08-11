import { createAppError, type BindingResult, unwrapBindingResult } from "./app-error";
import { mockBackend } from "./mock-backend";
import type {
  CommitPage,
  OpenWorkspaceResult,
  OperationSnapshot,
  ResourcePage,
  WorkspaceSnapshot,
} from "./types";

const isMock =
  (typeof window !== "undefined" && new URLSearchParams(window.location.search).has("mock")) ||
  import.meta.env.BASE_URL.includes("/enbu/");

type DesktopService = {
  BrowseWorkspace: () => Promise<BindingResult<OpenWorkspaceResult>>;
  StartImportFile: (
    sessionID: string,
    name: string,
    format: string,
    mediaType: string,
  ) => Promise<BindingResult<string>>;
  StartMaterialize: (
    sessionID: string,
    commitID: string,
    resourceID: string,
    payload: string,
    format: string,
  ) => Promise<BindingResult<string>>;
  Snapshot: (sessionID: string) => Promise<BindingResult<WorkspaceSnapshot>>;
  ListResources: (
    sessionID: string,
    commitID: string,
    cursor: string,
  ) => Promise<BindingResult<ResourcePage>>;
  ListCommits: (
    sessionID: string,
    frontier: string[],
    cursor: string,
  ) => Promise<BindingResult<CommitPage>>;
  PollOperation: (
    sessionID: string,
    operationID: string,
    cursor: number,
  ) => Promise<BindingResult<OperationSnapshot>>;
  CancelOperation: (sessionID: string, operationID: string) => Promise<BindingResult<null>>;
  CloseWorkspace: (sessionID: string) => Promise<BindingResult<null>>;
  GetAppVersion: () => Promise<BindingResult<string>>;
};

declare global {
  interface Window {
    go?: { main?: { DesktopService?: DesktopService } };
  }
}

function service(): DesktopService {
  const value = window.go?.main?.DesktopService;
  if (!value) throw createAppError("unavailable");
  return value;
}

const nativeBackend = {
  async browseWorkspace() {
    return unwrapBindingResult(await service().BrowseWorkspace());
  },
  async snapshot(sessionID: string) {
    return unwrapBindingResult(await service().Snapshot(sessionID));
  },
  async listResources(sessionID: string, commitID: string, cursor = "") {
    return unwrapBindingResult(await service().ListResources(sessionID, commitID, cursor));
  },
  async closeWorkspace(sessionID: string) {
    unwrapBindingResult(await service().CloseWorkspace(sessionID));
  },
};

export const backend = isMock ? mockBackend : nativeBackend;
