import { useCallback, useEffect, useRef, useState } from "react";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { ConflictSet, EnvInfo, SecretsResponse } from "../../lib/types";

export function resolveWorkspaceEnvironment(requested: string, environments: EnvInfo[]) {
  if (requested && environments.some((environment) => environment.name === requested)) {
    return requested;
  }
  return (
    environments.find((environment) => environment.current)?.name ?? environments[0]?.name ?? ""
  );
}

export type Workspace = {
  workspaceID: string;
  environments: EnvInfo[];
  currentEnvironment: string;
  secrets: SecretsResponse | null;
  /** Set while concurrent edits stop reading until someone chooses a value. */
  conflicts: ConflictSet | null;
  loading: boolean;
  error: DisplayError | null;
  setError: (error: DisplayError | null) => void;
  /** Reloads the selected environment and its secrets from the same snapshot. */
  refresh: () => Promise<void>;
};

/** The environments and secrets of the selected repository. */
export function useWorkspace(repoPath: string): Workspace {
  const [data, setData] = useState<
    Pick<Workspace, "workspaceID" | "environments" | "currentEnvironment" | "secrets" | "conflicts">
  >({ workspaceID: "", environments: [], currentEnvironment: "", secrets: null, conflicts: null });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  const request = useRef(0);
  const active = useRef(false);

  const refresh = useCallback(async () => {
    if (!active.current) return;
    // A newer refresh, for example after switching repositories, wins.
    const id = ++request.current;
    setLoading(true);
    setError(null);
    try {
      const snapshot = await backend.GetWorkspace(repoPath);
      if (id !== request.current) return;
      setData({
        workspaceID: snapshot.workspace_id,
        environments: [...snapshot.environments].sort((a, b) => a.name.localeCompare(b.name)),
        currentEnvironment: snapshot.secrets.environment,
        secrets: snapshot.secrets,
        conflicts: snapshot.conflicts,
      });
    } catch (err) {
      if (id === request.current) setError(toDisplayError(err));
    } finally {
      if (id === request.current) setLoading(false);
    }
  }, [repoPath]);

  // The dashboard is keyed by the repository, so a new repository starts empty.
  useEffect(() => {
    active.current = true;
    if (repoPath) void refresh();
    return () => {
      active.current = false;
      request.current++;
    };
  }, [repoPath, refresh]);

  return {
    ...data,
    loading,
    error,
    setError,
    refresh,
  };
}
