import type { AuthStatus } from "./types";

export type AuthRefreshOptions = {
  force?: boolean;
  /**
   * What the status depends on, such as the selected repository, has changed,
   * so a request already running may answer for the old state: fetch again
   * once it finishes. Such calls made meanwhile share that one fetch.
   */
  invalidate?: boolean;
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
  let followUp: Promise<void> | null = null;

  async function refresh(options: AuthRefreshOptions = {}): Promise<void> {
    if (inFlight && options.invalidate) {
      followUp ??= inFlight.then(() => {
        followUp = null;
        return refresh({ force: true });
      });
      return followUp;
    }
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
