import { useCallback, useState } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { Box, Flex, VStack, styled } from "styled-system/jsx";
import { Badge, Button, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import { OAuthLoginPanel } from "../auth/oauth-login-panel";
import { useGitHubLogin } from "../auth/use-github-login";
import { m } from "../../paraglide/messages";

function Avatar({ login }: { login: string }) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return (
      <Box
        w="32px"
        h="32px"
        flexShrink="0"
        borderRadius="full"
        bg="accent.default"
        color="accent.fg"
        fontSize="sm"
        fontWeight="extrabold"
        display="grid"
        placeItems="center"
        aria-hidden="true"
      >
        {login.slice(0, 1).toUpperCase()}
      </Box>
    );
  }
  return (
    <img
      src={`https://avatars.githubusercontent.com/${login}?size=64`}
      width={32}
      height={32}
      alt=""
      style={{ borderRadius: "50%", flexShrink: 0 }}
      onError={() => setFailed(true)}
    />
  );
}

/**
 * The GitHub accounts signed in on this device: the one in use, switching to
 * another, signing one out, and signing in with another account.
 */
export function AccountList() {
  const { status, refresh, reloadRepo } = useSession();
  const [busy, setBusy] = useState("");
  const [error, setError] = useState<DisplayError | null>(null);
  const reload = useCallback(
    () => Promise.all([refresh({ force: true, invalidate: true }), reloadRepo()]),
    [refresh, reloadRepo],
  );
  const login = useGitHubLogin(reload);

  const current = status?.authenticated ? (status.username ?? "") : "";
  const accounts = status?.accounts ?? [];
  // GITHUB_TOKEN signs in without an account entry; show it without actions.
  const fromEnvironment = current !== "" && !accounts.includes(current);

  async function act(account: string, run: () => Promise<void>) {
    setBusy(account);
    setError(null);
    try {
      await run();
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setBusy("");
      await reload();
    }
  }

  if (login.start) {
    return (
      <Flex justify="center" py="4">
        <OAuthLoginPanel
          status={login.status}
          expiresIn={login.expiresIn}
          onCancel={login.cancel}
          onRetry={login.reset}
        />
      </Flex>
    );
  }

  // The account in use first, then the others from the latest sign-in back.
  const others = accounts.filter((account) => account !== current).reverse();
  const rows = current ? [current, ...others] : others;
  return (
    <VStack alignItems="stretch" gap="3">
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}
      {login.error && <ErrorAlert error={login.error} onDismiss={login.clearError} />}
      {rows.length === 0 && (
        <Text fontSize="sm" color="fg.muted">
          {m.settings_noAccounts()}
        </Text>
      )}
      {rows.length > 0 && (
        <styled.ul
          aria-label={m.settings_accounts()}
          listStyle="none"
          m="0"
          p="0"
          borderWidth="1px"
          borderColor="border.default"
          borderRadius="lg"
          bg="bg.surface"
        >
          {rows.map((account, index) => {
            const inUse = account === current;
            const envToken = fromEnvironment && index === 0;
            return (
              <Flex
                as="li"
                key={`${account}-${index}`}
                data-account={account}
                align="center"
                gap="3"
                px="3.5"
                py="3"
                borderTopWidth={index === 0 ? "0" : "1px"}
                borderColor="border.default"
              >
                <Avatar login={account} />
                <Flex flex="1" minW="0" align="center" gap="2" flexWrap="wrap">
                  <styled.a
                    href={`https://github.com/${account}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    fontSize="sm"
                    fontWeight="semibold"
                    color="fg.default"
                    truncate
                    _hover={{ textDecoration: "underline", color: "accent.default" }}
                  >
                    {account}
                  </styled.a>
                  {inUse && <Badge size="sm">{m.settings_inUse()}</Badge>}
                  {envToken && (
                    <Text fontSize="xs" color="fg.muted">
                      {m.settings_envToken()}
                    </Text>
                  )}
                </Flex>
                {!envToken && !inUse && (
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={`${m.settings_use()}: ${account}`}
                    disabled={busy !== ""}
                    loading={busy === account}
                    onClick={() => void act(account, () => backend.switchAccount(account))}
                  >
                    {m.settings_use()}
                  </Button>
                )}
                {!envToken && (
                  <Button
                    size="sm"
                    variant="outline"
                    aria-label={`${m.auth_logout()}: ${account}`}
                    disabled={busy !== ""}
                    onClick={() => void act(account, () => backend.logout(account))}
                  >
                    {m.auth_logout()}
                  </Button>
                )}
              </Flex>
            );
          })}
        </styled.ul>
      )}
      <Box>
        <Button size="sm" variant="outline" loading={login.starting} onClick={login.begin}>
          <SiGithub size={14} aria-hidden="true" />
          {m.settings_addAccount()}
        </Button>
      </Box>
    </VStack>
  );
}
