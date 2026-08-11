import type { OpenWorkspaceResult, ResourcePage, WorkspaceSnapshot } from "./types";

const snapshot: WorkspaceSnapshot = {
  frontier: ["sha256:5c86f16f4c4c7a9a0748291a70ef5f41fab646ff27f6cb03ea65c89b6d67b82a"],
  config_revision: "sha256:b1ee3d4fcb26f99a3dc89101edaba1b777b681f680ba81af310a20fc2a76fd8c",
  resource_count: 3,
  commit_count: 2,
};

export const mockBackend = {
  async browseWorkspace(): Promise<OpenWorkspaceResult> {
    return { session_id: "11111111-1111-4111-8111-111111111111", snapshot };
  },
  async snapshot(): Promise<WorkspaceSnapshot> {
    return snapshot;
  },
  async listResources(): Promise<ResourcePage> {
    return {
      resources: [
        {
          kind: "Collection",
          uid: "22222222-2222-4222-8222-222222222222",
          schema: "schemas.enbu.net/v1alpha1/Workspace",
          metadata: { name: "workspace", labels: { environment: "development" } },
          sealed: {
            revision: snapshot.frontier[0],
            material: snapshot.frontier[0],
            grant: snapshot.frontier[0],
          },
        },
        {
          kind: "Resource",
          uid: "33333333-3333-4333-8333-333333333333",
          schema: "schemas.enbu.net/v1alpha1/SecretMap",
          metadata: { name: "application-secrets" },
          sealed: {
            revision: snapshot.frontier[0],
            material: snapshot.frontier[0],
            grant: snapshot.frontier[0],
          },
        },
      ],
    };
  },
  async closeWorkspace(): Promise<void> {},
};
