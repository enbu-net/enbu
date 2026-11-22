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
    Pick<Workspace, "environments" | "currentEnvironment" | "secrets" | "conflicts">
  >({ environments: [], currentEnvironment: "", secrets: null, conflicts: null });
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
      const envs = await backend.ListEnvironments();
      if (id !== request.current) return;
      const nextEnv = resolveWorkspaceEnvironment("", envs);
      let nextSecrets: SecretsResponse;
      let nextConflicts: ConflictSet | null = null;
      try {
        nextSecrets = await backend.ListSecrets(nextEnv);
      } catch (err) {
        if (toDisplayError(err).code !== "secret_conflict") throw err;
        nextSecrets = { environment: nextEnv, secrets: [] };
        nextConflicts = await backend.ListConflicts(nextEnv);
      }
      if (id !== request.current) return;
      setData({
        environments: [...envs].sort((a, b) => a.name.localeCompare(b.name)),
        currentEnvironment: nextEnv,
        secrets: nextSecrets,
        conflicts: nextConflicts,
      });
    } catch (err) {
      if (id === request.current) setError(toDisplayError(err));
    } finally {
      if (id === request.current) setLoading(false);
    }
  }, []);

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
