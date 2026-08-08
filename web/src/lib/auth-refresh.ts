import type { AuthStatus } from "./types";

export type AuthRefreshOptions = {
  force?: boolean;
};

type AuthRefresherOptions = {
  fetchStatus: () => Promise<AuthStatus>;
  setStatus: (status: AuthStatus | null) => void;
  minIntervalMs?: number;
  now?: () => number;
};

export function createAuthRefresher({
  fetchStatus,
  setStatus,
  minIntervalMs = 5000,
  now = Date.now,
}: AuthRefresherOptions) {
  let lastStartedAt = 0;
  let inFlight: Promise<void> | null = null;

  async function refresh(options: AuthRefreshOptions = {}) {
    if (inFlight) {
      return inFlight;
    }

    const current = now();
    if (!options.force && lastStartedAt > 0 && current - lastStartedAt < minIntervalMs) {
      return;
    }

    lastStartedAt = current;
    const run = fetchStatus()
      .then((status) => setStatus(status))
      .catch(() => setStatus(null))
      .finally(() => {
        if (inFlight === run) {
          inFlight = null;
        }
      });
    inFlight = run;
    return run;
  }

  return { refresh };
}
