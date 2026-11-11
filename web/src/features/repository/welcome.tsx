import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { Circle, CircleCheck, FolderOpen, TextCursorInput } from "lucide-react";
import { Box, Grid, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Heading, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import type { RepoInfo } from "../../lib/types";
import { OAuthLoginPanel } from "../auth/oauth-login-panel";
import { useGitHubLogin } from "../auth/use-github-login";
import { m } from "../../paraglide/messages";

/** How many of the repositories opened before the welcome screen lists, in the sidebar's order. */
const recentLimit = 8;

/**
 * The first screen, while no repository is open: ways to open one, the
 * repositories opened before, and the steps from sign-in to reading the team's
 * secrets, as VS Code's welcome page shows its start actions and walkthroughs.
 */
export function Welcome() {
  const { status, refresh, reloadRepo, setRepo } = useSession();
  const [error, setError] = useState<DisplayError | null>(null);
  const [opening, setOpening] = useState(false);

  const onSignedIn = useCallback(
    () => Promise.all([refresh({ force: true, invalidate: true }), reloadRepo()]),
    [refresh, reloadRepo],
  );
  const login = useGitHubLogin(onSignedIn);

  async function open(choose: () => Promise<RepoInfo>) {
    setOpening(true);
    setError(null);
    try {
      const next = await choose();
      // A cancelled folder picker selects nothing.
      if (next.path) setRepo(next);
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setOpening(false);
    }
  }
  const browse = () => open(() => backend.BrowseRepository());

  if (login.start) {
    return (
      <PageCenter>
        <OAuthLoginPanel
          userCode={login.start.user_code}
          verificationURI={login.start.verification_uri}
          status={login.status}
          expiresIn={login.expiresIn}
          onCancel={login.cancel}
          onRetry={login.reset}
        />
      </PageCenter>
    );
  }

  return (
    <Box maxW="5xl" mx="auto" px={{ base: "4", md: "10" }} py={{ base: "8", md: "14" }}>
      <Box mb="10">
        <Heading as="h1" size="3xl" fontWeight="extrabold">
          enbu
        </Heading>
        <Text color="fg.muted" mt="1">
          {m.welcome_tagline()}
        </Text>
      </Box>
      {(error || login.error) && (
        <Box mb="6">
          <ErrorAlert
            error={(error ?? login.error)!}
            onDismiss={() => {
              setError(null);
              login.clearError();
            }}
          />
        </Box>
      )}
      <Grid columns={{ base: 1, md: 2 }} gap={{ base: "10", md: "14" }} alignItems="start">
        <VStack gap="10" alignItems="stretch">
          <Start
            opening={opening}
            onBrowse={browse}
            onOpenPath={(path) => open(() => backend.SelectRepository(path))}
          />
          <Recent
            onOpen={(path) => open(() => backend.SelectRepository(path))}
            disabled={opening}
          />
        </VStack>
        <Walkthrough
          signedIn={status?.authenticated ?? false}
          username={status?.username ?? ""}
          signingIn={login.starting}
          opening={opening}
          onSignIn={login.begin}
          onBrowse={browse}
        />
      </Grid>
    </Box>
  );
}

function WelcomeSection({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <styled.section aria-labelledby={id}>
      <Heading as="h2" id={id} size="md" fontWeight="semibold" mb="3">
        {title}
      </Heading>
      {children}
    </styled.section>
  );
}

/** A start action: an icon and a label in the accent color, like VS Code's. */
function StartAction({
  icon,
  children,
  disabled,
  onClick,
}: {
  icon: ReactNode;
  children: ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <styled.button
      type="button"
      display="inline-flex"
      alignItems="center"
      gap="2"
      py="1"
      color="accent.text"
      cursor="pointer"
      textAlign="start"
      _hover={{ textDecoration: "underline" }}
      _disabled={{ opacity: 0.5, cursor: "not-allowed" }}
      disabled={disabled}
      onClick={onClick}
    >
      {icon}
      {children}
    </styled.button>
  );
}

function Start({
  opening,
  onBrowse,
  onOpenPath,
}: {
  opening: boolean;
  onBrowse: () => void;
  onOpenPath: (path: string) => Promise<void>;
}) {
  const [typing, setTyping] = useState(false);
  const [path, setPath] = useState("");
  const pathId = useId();
  const pathRef = useRef<HTMLInputElement>(null);

  // The field appears because the person asked to type a path: take them there.
  useEffect(() => {
    if (typing) pathRef.current?.focus();
  }, [typing]);

  return (
    <WelcomeSection title={m.welcome_start()}>
      <VStack gap="1" alignItems="start">
        <StartAction
          icon={<FolderOpen size={18} aria-hidden="true" />}
          disabled={opening}
          onClick={onBrowse}
        >
          {m.welcome_openFolder()}
        </StartAction>
        <StartAction
          icon={<TextCursorInput size={18} aria-hidden="true" />}
          onClick={() => setTyping((open) => !open)}
        >
          {m.welcome_enterPath()}
        </StartAction>
      </VStack>
      {typing && (
        // A form, so Enter submits natively, which an IME's confirming Enter does not.
        <styled.form
          mt="3"
          display="flex"
          flexDirection="column"
          gap="2"
          onSubmit={(event) => {
            event.preventDefault();
            if (path.trim()) void onOpenPath(path.trim());
          }}
        >
          <styled.label htmlFor={pathId} fontSize="sm" fontWeight="semibold">
            {m.repo_pathLabel()}
          </styled.label>
          <HStack>
            <Input
              id={pathId}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder={m.repo_pathPlaceholder()}
              autoComplete="off"
              spellCheck={false}
              ref={pathRef}
              borderColor="border.strong"
              borderRadius="md"
            />
            <Button
              type="submit"
              bg="accent.default"
              color="accent.fg"
              fontWeight="semibold"
              flexShrink={0}
              loading={opening}
              disabled={!path.trim()}
            >
              {m.repo_continue()}
            </Button>
          </HStack>
        </styled.form>
      )}
    </WelcomeSection>
  );
}

function Recent({ onOpen, disabled }: { onOpen: (path: string) => void; disabled: boolean }) {
  const [repos, setRepos] = useState<RepoInfo[] | null>(null);

  useEffect(() => {
    backend
      .ListRepositories()
      .then((list) => setRepos(list.filter((repo) => repo.path).slice(0, recentLimit)))
      // The list is a shortcut; without it the start actions still work.
      .catch(() => setRepos([]));
  }, []);

  if (repos === null) return null;
  return (
    <WelcomeSection title={m.welcome_recent()}>
      {repos.length === 0 ? (
        <Text fontSize="sm" color="fg.muted">
          {m.welcome_noRecent()}
        </Text>
      ) : (
        <styled.ul display="flex" flexDirection="column" gap="1">
          {repos.map((repo) => (
            <li key={repo.path}>
              <styled.button
                type="button"
                display="flex"
                gap="3"
                alignItems="baseline"
                w="full"
                py="1"
                textAlign="start"
                cursor="pointer"
                disabled={disabled}
                onClick={() => onOpen(repo.path ?? "")}
                _disabled={{ opacity: 0.5, cursor: "not-allowed" }}
                _hover={{ "& > span:first-child": { textDecoration: "underline" } }}
              >
                <styled.span color="accent.text" flexShrink={0}>
                  {repo.owner && repo.repo
                    ? `${repo.owner}/${repo.repo}`
                    : baseName(repo.path ?? "")}
                </styled.span>
                <styled.span fontSize="sm" color="fg.muted" truncate minW="0">
                  {repo.path}
                </styled.span>
              </styled.button>
            </li>
          ))}
        </styled.ul>
      )}
    </WelcomeSection>
  );
}

function baseName(path: string) {
  return (
    path
      .replace(/[\\/]+$/, "")
      .split(/[\\/]/)
      .pop() ?? path
  );
}

type Step = {
  title: string;
  body: string;
  done: boolean;
  action?: ReactNode;
};

/**
 * The way from sign-in to reading the team's secrets. Each step opens to tell
 * what it is for; the first one not done yet starts open.
 */
function Walkthrough({
  signedIn,
  username,
  signingIn,
  opening,
  onSignIn,
  onBrowse,
}: {
  signedIn: boolean;
  username: string;
  signingIn: boolean;
  opening: boolean;
  onSignIn: () => void;
  onBrowse: () => void;
}) {
  const steps: Step[] = [
    {
      title: m.welcome_stepSignIn(),
      body:
        signedIn && username ? m.welcome_stepSignInDone({ username }) : m.welcome_stepSignInBody(),
      done: signedIn,
      action: signedIn ? undefined : (
        <Button
          size="sm"
          variant="outline"
          borderColor="border.strong"
          loading={signingIn}
          onClick={onSignIn}
        >
          <SiGithub size={14} aria-hidden="true" />
          {m.auth_connect()}
        </Button>
      ),
    },
    {
      title: m.welcome_stepOpen(),
      body: m.welcome_stepOpenBody(),
      done: false,
      action: (
        <Button
          size="sm"
          bg="accent.default"
          color="accent.fg"
          disabled={opening}
          onClick={onBrowse}
        >
          <FolderOpen size={14} aria-hidden="true" />
          {m.welcome_openFolder()}
        </Button>
      ),
    },
    { title: m.welcome_stepWorkspace(), body: m.welcome_stepWorkspaceBody(), done: false },
    { title: m.welcome_stepApprove(), body: m.welcome_stepApproveBody(), done: false },
  ];
  const firstOpen = steps.findIndex((step) => !step.done);
  const name = useId();

  return (
    <WelcomeSection title={m.welcome_walkthrough()}>
      <styled.ol
        display="flex"
        flexDirection="column"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="lg"
        bg="bg.surface"
        overflow="hidden"
      >
        {steps.map((step, index) => (
          <styled.li
            key={step.title}
            borderTopWidth={index ? "1px" : "0"}
            borderColor="border.default"
          >
            {/* details with a shared name open one at a time where supported, and independently elsewhere. */}
            <styled.details
              name={name}
              open={index === firstOpen}
              css={{ "&[open] > summary": { fontWeight: "semibold" } }}
            >
              <styled.summary
                display="flex"
                alignItems="center"
                gap="3"
                px="4"
                py="3"
                cursor="pointer"
                listStyle="none"
                _hover={{ bg: "bg.muted" }}
                css={{ "&::-webkit-details-marker": { display: "none" } }}
              >
                {step.done ? (
                  <CircleCheck size={18} color="var(--colors-status-success)" aria-hidden="true" />
                ) : (
                  <Circle size={18} color="var(--colors-fg-muted)" aria-hidden="true" />
                )}
                <span>
                  {step.title}
                  {step.done && <styled.span srOnly>{` (${m.welcome_done()})`}</styled.span>}
                </span>
              </styled.summary>
              <VStack alignItems="start" gap="3" px="4" pb="4" ps="11">
                <Text fontSize="sm" color="fg.subtle">
                  {step.body}
                </Text>
                {step.action}
              </VStack>
            </styled.details>
          </styled.li>
        ))}
      </styled.ol>
    </WelcomeSection>
  );
}
