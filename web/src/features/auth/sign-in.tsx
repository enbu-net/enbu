import { useEffect, useState } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { VStack } from "styled-system/jsx";
import { Button } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { LanguageSelector } from "../../components/language-selector";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import { useSession } from "../../lib/session";
import type { OAuthStart, OAuthStatus } from "../../lib/types";
import { OAuthLoginPanel } from "./oauth-login-panel";

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
 * Signs in with GitHub: the browser completes the authorization while the app
 * polls for the result.
 */
export function SignIn() {
  const { t } = useI18n();
  const { refresh, reloadRepo } = useSession();
  const [start, setStart] = useState<OAuthStart | null>(null);
  const [status, setStatus] = useState<OAuthStatus | null>(null);
  const [error, setError] = useState<DisplayError | null>(null);
  const [starting, setStarting] = useState(false);
  const pending = status?.state === "pending";
  const expiresIn = useSecondsLeft(start, pending);

  useEffect(() => {
    if (!start || !pending) return;
    const poll = window.setInterval(async () => {
      try {
        const next = await backend.oauthStatus(start.session_id);
        if (next.state !== "success") {
          setStatus(next);
          return;
        }
        window.clearInterval(poll);
        setStart(null);
        setStatus(null);
        await Promise.all([refresh({ force: true }), reloadRepo()]);
      } catch (err) {
        setStatus({ state: "error", error: toDisplayError(err) });
      }
    }, 1000);
    return () => window.clearInterval(poll);
  }, [start, pending, refresh, reloadRepo]);

  function reset() {
    setStart(null);
    setStatus(null);
    setError(null);
  }

  if (start) {
    return (
      <PageCenter>
        <OAuthLoginPanel
          status={status}
          expiresIn={expiresIn}
          onCancel={async () => {
            await backend.cancelOAuthLogin(start.session_id);
            reset();
          }}
          onRetry={reset}
        />
      </PageCenter>
    );
  }

  return (
    <PageCenter>
      <VStack gap={5} w="full" maxW="480px" textAlign="center">
        {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}
        <Button
          w="full"
          bg="accent.default"
          color="accent.fg"
          fontWeight="semibold"
          loading={starting}
          onClick={async () => {
            setStarting(true);
            setError(null);
            try {
              setStart(await backend.startOAuthLogin());
              setStatus({ state: "pending" });
            } catch (err) {
              setError(toDisplayError(err));
            } finally {
              setStarting(false);
            }
          }}
        >
          <SiGithub size={16} aria-hidden="true" />
          {t("auth.connect")}
        </Button>
        <LanguageSelector w="full" justifyContent="flex-end" pt="3" />
      </VStack>
    </PageCenter>
  );
}
