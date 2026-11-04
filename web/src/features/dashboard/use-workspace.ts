import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { ConflictSet, Environment, SecretsResponse } from "../../lib/types";

export function resolveWorkspaceEnvironment(requested: string, environments: Environment[]) {
  if (requested && environments.some((environment) => environment.name === requested)) {
    return requested;
  }
  return (
    environments.find((environment) => environment.current)?.name ?? environments[0]?.name ?? ""
  );
}

export type Workspace = {
  environments: Environment[];
  currentEnvironment: string;
  secrets: SecretsResponse | null;
  /** Set while concurrent edits stop reading until someone chooses a value. */
  conflicts: ConflictSet | null;
  loading: boolean;
  error: DisplayError | null;
  setError: (error: DisplayError | null) => void;
  /** Reloads the environments and the secrets of env, or of the current one. */
  refresh: (env?: string) => Promise<void>;
};

/** The environments and secrets of the selected repository. */
export function useWorkspace(repoPath: string): Workspace {
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [secrets, setSecrets] = useState<SecretsResponse | null>(null);
  const [conflicts, setConflicts] = useState<ConflictSet | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  const request = useRef(0);

  const currentEnvironment = useMemo(
    () => environments.find((env) => env.current)?.name ?? secrets?.environment ?? "",
    [environments, secrets?.environment],
  );
  const currentRef = useRef(currentEnvironment);
  useEffect(() => {
    currentRef.current = currentEnvironment;
  }, [currentEnvironment]);

  const refresh = useCallback(async (env?: string) => {
    // A newer refresh, for example after switching repositories, wins.
    const id = ++request.current;
    setLoading(true);
    setError(null);
    try {
      const envs = await backend.listEnvironments();
      const nextEnv = resolveWorkspaceEnvironment(env ?? currentRef.current, envs);
      let nextSecrets: SecretsResponse;
      let nextConflicts: ConflictSet | null = null;
      try {
        nextSecrets = await backend.listSecrets(nextEnv);
      } catch (err) {
        if (toDisplayError(err).code !== "secret_conflict") throw err;
        nextSecrets = { environment: nextEnv, secrets: [] };
        nextConflicts = await backend.listConflicts(nextEnv);
      }
      if (id !== request.current) return;
      setEnvironments([...envs].sort((a, b) => a.name.localeCompare(b.name)));
      setSecrets(nextSecrets);
      setConflicts(nextConflicts);
    } catch (err) {
      if (id === request.current) setError(toDisplayError(err));
    } finally {
      if (id === request.current) setLoading(false);
    }
  }, []);

  // The dashboard is keyed by the repository, so a new repository starts empty.
  useEffect(() => {
    if (repoPath) void refresh("");
  }, [repoPath, refresh]);

  return {
    environments,
    currentEnvironment,
    secrets,
    conflicts,
    loading,
    error,
    setError,
    refresh,
  };
}
