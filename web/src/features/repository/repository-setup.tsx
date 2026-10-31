import { useState, type ReactNode } from "react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Heading, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import type { RepoInfo } from "../../lib/types";
import { m } from "../../paraglide/messages";

/** The step a selected folder still needs before enbu can manage it, if any. */
export type SetupStep = "git" | "remote" | "enbu";

export function setupStep(repo: RepoInfo): SetupStep | null {
  if (!repo.storage_configured && !repo.has_git) return "git";
  if (!repo.storage_configured && !repo.has_remote) return "remote";
  if (!repo.initialized) return "enbu";
  return null;
}

/**
 * Runs one setup action at a time and keeps its error, which every setup
 * screen shows the same way.
 */
function useAction() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  async function run(action: () => Promise<void>) {
    setLoading(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setLoading(false);
    }
  }
  return { loading, error, setError, run };
}

function SetupScreen({
  title,
  description,
  error,
  onDismissError,
  children,
}: {
  title: string;
  description?: string;
  error: DisplayError | null;
  onDismissError: () => void;
  children: ReactNode;
}) {
  return (
    <PageCenter>
      <VStack gap={5} w="full" maxW="540px" alignItems="stretch">
        <Box>
          <Heading as="h1" size="2xl" fontWeight="extrabold" mb={description ? 2 : 0}>
            {title}
          </Heading>
          {description && <Text color="fg.muted">{description}</Text>}
        </Box>
        {error && <ErrorAlert error={error} onDismiss={onDismissError} />}
        {children}
      </VStack>
    </PageCenter>
  );
}

const primaryButton = {
  bg: "accent.default",
  color: "accent.fg",
  fontWeight: "semibold",
  _disabled: { opacity: 0.5, cursor: "not-allowed" },
} as const;

/** Chooses the local repository enbu should manage. */
export function RepositorySelect() {
  const { setRepo } = useSession();
  const [path, setPath] = useState("");
  const action = useAction();

  return (
    <SetupScreen
      title={m.repo_selectTitle()}
      description={m.repo_selectDescription()}
      error={action.error}
      onDismissError={() => action.setError(null)}
    >
      <HStack>
        <Input
          aria-label={m.repo_pathPlaceholder()}
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && path.trim()) {
              void action.run(async () => setRepo(await backend.selectRepository(path.trim())));
            }
          }}
          placeholder={m.repo_pathPlaceholder()}
          h="38px"
          borderColor="border.default"
          borderRadius="md"
        />
        <Button
          variant="outline"
          h="38px"
          borderColor="border.default"
          color="fg.default"
          fontWeight="semibold"
          flexShrink={0}
          onClick={() =>
            action.run(async () => {
              const next = await backend.browseRepository();
              if (next.selected) setRepo(next);
            })
          }
        >
          {m.repo_browse()}
        </Button>
      </HStack>
      <Button
        {...primaryButton}
        loading={action.loading}
        disabled={!path.trim()}
        onClick={() => action.run(async () => setRepo(await backend.selectRepository(path.trim())))}
      >
        {m.repo_continue()}
      </Button>
    </SetupScreen>
  );
}

/**
 * Sets up enbu in a selected folder. A folder without Git or a GitHub remote
 * gets the commands to run, as enbu leaves Git and GitHub to their own tools.
 */
export function RepositorySetup({ step }: { step: SetupStep }) {
  const { reloadRepo } = useSession();
  const action = useAction();
  const dismiss = () => action.setError(null);

  if (step === "git" || step === "remote") {
    return (
      <SetupScreen
        title={step === "git" ? m.init_gitTitle() : m.init_remoteTitle()}
        description={step === "git" ? m.init_gitDescription() : m.init_remoteDescription()}
        error={action.error}
        onDismissError={dismiss}
      >
        <styled.pre
          p="3"
          bg="bg.muted"
          borderRadius="md"
          fontFamily="mono"
          fontSize="sm"
          overflowX="auto"
        >
          {step === "git" ? "git init" : "git remote add origin https://github.com/OWNER/REPO.git"}
        </styled.pre>
        <Button {...primaryButton} loading={action.loading} onClick={() => action.run(reloadRepo)}>
          {m.init_checkAgain()}
        </Button>
      </SetupScreen>
    );
  }

  return (
    <SetupScreen
      title={m.init_title()}
      description={m.init_description()}
      error={action.error}
      onDismissError={dismiss}
    >
      <Button
        {...primaryButton}
        loading={action.loading}
        onClick={() =>
          action.run(async () => {
            await backend.initialize();
            await reloadRepo();
          })
        }
      >
        {m.init_action()}
      </Button>
    </SetupScreen>
  );
}
