export type WorkspaceSnapshot = {
  frontier: string[];
  config_revision: string;
  resource_count: number;
  commit_count: number;
};

export type ResourceMetadata = {
  kind: string;
  uid: string;
  schema: { group: string; version: string; kind: string } | string;
  metadata: {
    name?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  sealed: { revision: string; material: string; grant: string };
};

export type ResourcePage = { resources: ResourceMetadata[]; next?: string };
export type CommitPage = { commits: Array<Record<string, unknown>>; next?: string };
export type OperationSnapshot = {
  operation_id: string;
  kind: string;
  state: "queued" | "running" | "succeeded" | "conflicted" | "failed" | "canceled";
  next_cursor: number;
  events?: Array<{ sequence: number; phase: string; completed: number; total: number }>;
};

export type OpenWorkspaceResult = { session_id: string; snapshot: WorkspaceSnapshot };
export type InitializeWorkspaceResult = { session_id: string; operation_id: string };
