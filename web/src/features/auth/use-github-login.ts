import { useCallback, useEffect, useRef, useState } from "react";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { OAuthStart } from "../../lib/types";
import type { LoginStatus } from "./oauth-login-panel";

/** Seconds left until a sign-in started at start expires, ticking while it is pending. */
function useSecondsLeft(start: OAuthStart | null, pending: boolean) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!start || !pending) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [start, pending]);
  if (!start) return 0;
  return Math.max(0, Math.ceil((new Date(start.expires_at).getTime() - now) / 1000));
}

/**
 * Signs in with GitHub: the browser completes the authorization while this
 * polls for the result, then calls onSuccess. Signing in with another account
 * adds it beside the ones already signed in and makes it the one in use.
 */
export function useGitHubLogin(onSuccess: () => Promise<unknown>) {
  const active = useRef<OAuthStart | null>(null);
  const mounted = useRef(false);
  const [start, setStart] = useState<OAuthStart | null>(null);
  const [status, setStatus] = useState<LoginStatus | null>(null);
  const [error, setError] = useState<DisplayError | null>(null);
  const [starting, setStarting] = useState(false);
  const pending = status?.state === "pending";
  const expiresIn = useSecondsLeft(start, pending);

  useEffect(() => {
    if (!start || !pending) return;
    const poll = window.setInterval(async () => {
      try {
        const next = await backend.GetOAuthLoginStatus(start.session_id);
        if (!mounted.current || active.current?.session_id !== start.session_id) return;
        if (next.state !== "success") {
          setStatus({
            state: next.state as LoginStatus["state"],
            error: next.error ? toDisplayError(next.error) : undefined,
          });
          return;
        }
        window.clearInterval(poll);
        active.current = null;
        setStart(null);
        setStatus(null);
        await onSuccess();
      } catch (err) {
        setStatus({ state: "error", error: toDisplayError(err) });
      }
    }, 1000);
    return () => window.clearInterval(poll);
  }, [start, pending, onSuccess]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (active.current)
        void backend
          .CancelOAuthLogin(active.current.session_id)
          .catch((err: unknown) => console.error("cancelling sign-in failed", err));
    };
  }, []);

  function reset() {
    active.current = null;
    setStart(null);
    setStatus(null);
    setError(null);
  }

  const begin = useCallback(async () => {
    setStarting(true);
    setError(null);
    try {
      const next = await backend.StartOAuthLogin();
      if (!mounted.current) {
        await backend.CancelOAuthLogin(next.session_id);
        return;
      }
      active.current = next;
      setStart(next);
      setStatus({ state: "pending" });
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setStarting(false);
    }
  }, []);

  async function cancel() {
    const current = active.current;
    active.current = null;
    if (current) await backend.CancelOAuthLogin(current.session_id);
    reset();
  }

  return {
    start,
    status,
    error,
    starting,
    expiresIn,
    begin,
    cancel,
    reset,
    clearError: () => setError(null),
  };
}
