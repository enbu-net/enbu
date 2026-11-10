import { useCallback } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { VStack } from "styled-system/jsx";
import { Button } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { useSession } from "../../lib/session";
import { OAuthLoginPanel } from "./oauth-login-panel";
import { useGitHubLogin } from "./use-github-login";
import { m } from "../../paraglide/messages";

/**
 * Signs in with GitHub: the browser completes the authorization while the app
 * polls for the result.
 */
export function SignIn() {
  const { refresh, reloadRepo } = useSession();
  const onSuccess = useCallback(
    () => Promise.all([refresh({ force: true, invalidate: true }), reloadRepo()]),
    [refresh, reloadRepo],
  );
  const { start, status, error, starting, expiresIn, begin, cancel, reset, clearError } =
    useGitHubLogin(onSuccess);

  if (start) {
    return (
      <PageCenter>
        <OAuthLoginPanel status={status} expiresIn={expiresIn} onCancel={cancel} onRetry={reset} />
      </PageCenter>
    );
  }

  return (
    <PageCenter>
      <VStack gap={5} w="full" maxW="480px" textAlign="center">
        {error && <ErrorAlert error={error} onDismiss={clearError} />}
        <Button
          w="full"
          bg="accent.default"
          color="accent.fg"
          fontWeight="semibold"
          loading={starting}
          onClick={begin}
        >
          <SiGithub size={16} aria-hidden="true" />
          {m.auth_connect()}
        </Button>
      </VStack>
    </PageCenter>
  );
}
