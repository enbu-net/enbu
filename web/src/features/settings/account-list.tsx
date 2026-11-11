import { useCallback, useState } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { Plus } from "lucide-react";
import { Box, Flex, VStack, styled } from "styled-system/jsx";
import { Button, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import { OAuthLoginPanel } from "../auth/oauth-login-panel";
import { useGitHubLogin } from "../auth/use-github-login";
import { Section } from "./section";
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
 * Which sign-in provider an account belongs to. Every account is a GitHub
 * account today; other OpenID Connect providers will add their own label.
 */
function ProviderLabel() {
  return (
    <styled.span display="inline-flex" alignItems="center" gap="1" data-provider="github">
      <SiGithub size={12} title="" aria-hidden="true" />
      GitHub
    </styled.span>
  );
}

/**
 * The accounts signed in on this device: the one in use, switching to
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
      <Section title={m.settings_accounts()}>
        <Flex justify="center" py="4">
          <OAuthLoginPanel
            userCode={login.start.user_code}
            verificationURI={login.start.verification_uri}
            status={login.status}
            expiresIn={login.expiresIn}
            onCancel={login.cancel}
            onRetry={login.reset}
          />
        </Flex>
      </Section>
    );
  }

  // The account in use first, then the others from the latest sign-in back.
  const others = accounts.filter((account) => account !== current).reverse();
  const rows = current ? [current, ...others] : others;
  const addAccount = (
    <Button size="sm" variant="outline" loading={login.starting} onClick={login.begin}>
      <Plus size={14} aria-hidden="true" />
      {m.settings_addAccount()}
    </Button>
  );
  return (
    <Section title={m.settings_accounts()} action={addAccount}>
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
            overflow="hidden"
          >
            {rows.map((account, index) => {
              const inUse = account === current;
              const envToken = fromEnvironment && index === 0;
              return (
                <Flex
                  as="li"
                  key={`${account}-${index}`}
                  data-account={account}
                  data-in-use={inUse ? "true" : undefined}
                  aria-current={inUse ? "true" : undefined}
                  align="center"
                  gap="3"
                  px="3.5"
                  py="3"
                  borderTopWidth={index === 0 ? "0" : "1px"}
                  borderColor="border.default"
                  // The account in use stands out: tinted, with an accent bar.
                  bg={inUse ? "accent.subtle" : undefined}
                  boxShadow={inUse ? "inset 3px 0 0 {colors.accent.default}" : undefined}
                >
                  <Avatar login={account} />
                  <Box flex="1" minW="0">
                    <Flex align="center" gap="2" flexWrap="wrap">
                      <styled.a
                        href={`https://github.com/${account}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        fontSize="sm"
                        fontWeight="semibold"
                        color="fg.default"
                        truncate
                        _hover={{ textDecoration: "underline", color: "accent.text" }}
                      >
                        {account}
                      </styled.a>
                    </Flex>
                    <Flex align="center" gap="1.5" mt="0.5" fontSize="xs" color="fg.muted">
                      <ProviderLabel />
                      {envToken && <span>· {m.settings_envToken()}</span>}
                    </Flex>
                  </Box>
                  {!envToken && !inUse && (
                    <Button
                      size="sm"
                      variant="outline"
                      aria-label={`${m.settings_use()}: ${account}`}
                      disabled={busy !== ""}
                      loading={busy === account}
                      onClick={() => void act(account, () => backend.SwitchAccount(account))}
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
                      onClick={() => void act(account, () => backend.Logout(account))}
                    >
                      {m.auth_logout()}
                    </Button>
                  )}
                </Flex>
              );
            })}
          </styled.ul>
        )}
      </VStack>
    </Section>
  );
}
