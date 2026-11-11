import { useCallback } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { VStack } from "styled-system/jsx";
import { Button, Heading, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { useSession } from "../../lib/session";
import { OAuthLoginPanel } from "./oauth-login-panel";
import { useGitHubLogin } from "./use-github-login";
import { m } from "../../paraglide/messages";

/**
 * Signs in with the GitHub Device Flow: the user enters the shown code on
 * GitHub while the app polls for the result.
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
        <OAuthLoginPanel
          userCode={start.user_code}
          verificationURI={start.verification_uri}
          status={status}
          expiresIn={expiresIn}
          onCancel={cancel}
          onRetry={reset}
        />
      </PageCenter>
    );
  }

  return (
    <PageCenter>
      <VStack gap={5} w="full" maxW="480px" textAlign="center">
        <VStack gap={2}>
          <Heading as="h1" size="2xl" fontWeight="extrabold">
            {m.auth_signInTitle()}
          </Heading>
          <Text color="fg.muted">{m.auth_signInDescription()}</Text>
        </VStack>
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
