import { useCallback, useEffect } from "react";
import { VStack } from "styled-system/jsx";
import { PageCenter } from "../../components/layout";
import { Button, Heading, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { useSession } from "../../lib/session";
import { m } from "../../paraglide/messages";
import { OAuthLoginPanel } from "./oauth-login-panel";
import { useGitHubLogin } from "./use-github-login";

export function AddAccount({ onDone }: { onDone: () => void }) {
  const { refresh, reloadRepo } = useSession();
  const onSuccess = useCallback(async () => {
    await Promise.all([refresh({ force: true, invalidate: true }), reloadRepo()]);
    onDone();
  }, [refresh, reloadRepo, onDone]);
  const login = useGitHubLogin(onSuccess);
  const { begin } = login;
  useEffect(() => {
    void begin();
  }, [begin]);
  async function cancel() {
    await login.cancel();
    onDone();
  }
  return (
    <PageCenter>
      {login.start ? (
        <OAuthLoginPanel
          userCode={login.start.user_code}
          verificationURI={login.start.verification_uri}
          status={login.status}
          expiresIn={login.expiresIn}
          onCancel={cancel}
          onRetry={login.reset}
        />
      ) : (
        <VStack gap="4" alignItems="stretch" w="full" maxW="480px">
          <Heading as="h1" size="2xl">
            {m.settings_addAccount()}
          </Heading>
          <Text>{m.auth_addAccountHint()}</Text>
          {login.error && <ErrorAlert error={login.error} onDismiss={login.clearError} />}
          <Button loading={login.starting} onClick={begin}>
            {m.auth_connect()}
          </Button>
          <Button variant="ghost" onClick={onDone}>
            {m.auth_cancel()}
          </Button>
        </VStack>
      )}
    </PageCenter>
  );
}
