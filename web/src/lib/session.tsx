import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { backend } from "./backend";
import { createAuthRefresher, type AuthRefreshOptions } from "./auth-refresh";
import type { AuthStatus, GUIRepoStatus } from "./types";

/**
 * What every screen needs to know: who is signed in and which repository the
 * app works on. Screens change the repository through setRepo, so the sidebar,
 * the setup flow and the dashboard never disagree about it.
 */
export type Session = {
  status: AuthStatus | null;
  loading: boolean;
  /** The selected repository; null until it has been loaded. */
  repo: GUIRepoStatus | null;
  refresh: (options?: AuthRefreshOptions) => Promise<void> | undefined;
  /** Shows a repository the backend just selected or set up. */
  setRepo: (repo: GUIRepoStatus) => void;
  reloadRepo: () => Promise<void>;
};

export const SessionContext = createContext<Session>({
  status: null,
  loading: true,
  repo: null,
  refresh: async () => {},
  setRepo: () => {},
  reloadRepo: async () => {},
});

export function useSession() {
  return useContext(SessionContext);
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [repo, setRepoState] = useState<GUIRepoStatus | null>(null);

  const refresher = useRef(
    createAuthRefresher({
      fetchStatus: () => backend.authStatus(),
      setStatus,
    }),
  );
  const refresh = useCallback(
    (options?: AuthRefreshOptions) => refresher.current.refresh(options),
    [],
  );

  const reloadRepo = useCallback(async () => {
    try {
      setRepoState(await backend.repoStatus());
    } catch (err) {
      console.error("loading the selected repository failed", err);
      setRepoState({ selected: false });
    }
  }, []);

  // Whether a workspace is configured depends on the repository.
  const setRepo = useCallback(
    (next: GUIRepoStatus) => {
      setRepoState(next);
      void refresh({ force: true });
    },
    [refresh],
  );

  useEffect(() => {
    void Promise.all([reloadRepo(), refresh({ force: true })]).finally(() => setLoading(false));
    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refresh, reloadRepo]);

  const session = useMemo(
    () => ({ status, loading, repo, refresh, setRepo, reloadRepo }),
    [status, loading, repo, refresh, setRepo, reloadRepo],
  );
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}
