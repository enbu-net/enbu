import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Heading, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import type { InitResult, RepoInfo } from "../../lib/types";
import { m } from "../../paraglide/messages";

/**
 * The step a selected folder still needs before enbu can manage it, if any:
 * Git, then founding a workspace, or joining the one enbu.toml names.
 */
export type SetupStep = "git" | "found" | "join";

export function setupStep(repo: RepoInfo): SetupStep | null {
  if (repo.initialized) return null;
  if (repo.storage_configured) return "join";
  return repo.has_git ? "found" : "git";
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
 * Sets up enbu in a selected folder, as `enbu init` does. A folder without Git
 * gets the command to run, as enbu leaves Git and GitHub to their own tools.
 */
export function RepositorySetup({ step }: { step: SetupStep }) {
  const { reloadRepo } = useSession();
  const action = useAction();
  const dismiss = () => action.setError(null);
  const [done, setDone] = useState<InitResult | null>(null);

  if (step === "git") {
    return (
      <SetupScreen
        title={m.init_gitTitle()}
        description={m.init_gitDescription()}
        error={action.error}
        onDismissError={dismiss}
      >
        <Command>git init</Command>
        <Button {...primaryButton} loading={action.loading} onClick={() => action.run(reloadRepo)}>
          {m.init_checkAgain()}
        </Button>
      </SetupScreen>
    );
  }
  if (done) return <InitDone result={done} onContinue={reloadRepo} />;

  async function initialize(storage: string, acceptNewGenesis: boolean) {
    const result = await backend.initialize(storage, acceptNewGenesis);
    // Founding or waiting for approval leaves the person something to do first.
    if (result.founded || result.pending || result.replaced_genesis) setDone(result);
    else await reloadRepo();
  }

  return step === "found" ? (
    <FoundWorkspace action={action} onFound={(storage) => initialize(storage, false)} />
  ) : (
    <SetupScreen
      title={m.init_title()}
      description={m.init_joinDescription()}
      error={action.error}
      onDismissError={dismiss}
    >
      <Button
        {...primaryButton}
        loading={action.loading}
        onClick={() => action.run(() => initialize("", false))}
      >
        {m.init_action()}
      </Button>
      {action.error?.code === "trust_root_changed" && (
        <VStack alignItems="stretch" gap="2">
          <Button
            variant="outline"
            borderColor="status.danger"
            color="status.danger"
            loading={action.loading}
            onClick={() => action.run(() => initialize("", true))}
          >
            {m.init_acceptNewGenesis()}
          </Button>
          <Text fontSize="sm" color="fg.muted">
            {m.init_acceptNewGenesisHint()}
          </Text>
        </VStack>
      )}
    </SetupScreen>
  );
}

/** Founds a workspace in a storage the person may change from the suggested one. */
function FoundWorkspace({
  action,
  onFound,
}: {
  action: ReturnType<typeof useAction>;
  onFound: (storage: string) => Promise<void>;
}) {
  const { reloadRepo } = useSession();
  const [storage, setStorage] = useState("");
  // null while asking, "" when there is no suggestion (no GitHub origin).
  const [suggested, setSuggested] = useState<string | null>(null);

  const suggest = useCallback(async () => {
    const value = await backend.suggestStorage().catch(() => "");
    setSuggested(value);
    setStorage((current) => current || value);
  }, []);

  useEffect(() => {
    void suggest();
  }, [suggest]);

  return (
    <SetupScreen
      title={m.init_title()}
      description={m.init_foundDescription()}
      error={action.error}
      onDismissError={() => action.setError(null)}
    >
      <VStack alignItems="stretch" gap="1">
        <styled.label htmlFor="init-storage" fontSize="sm" fontWeight="semibold">
          {m.init_storage()}
        </styled.label>
        <Input
          id="init-storage"
          value={storage}
          onChange={(e) => setStorage(e.target.value)}
          placeholder="oci://ghcr.io/OWNER/REPO-enbu"
          fontFamily="mono"
          h="38px"
          borderColor="border.default"
          borderRadius="md"
        />
        <Text fontSize="sm" color="fg.muted">
          {m.init_storageHint()}
        </Text>
      </VStack>
      {suggested === "" && (
        <VStack alignItems="stretch" gap="2">
          <Text fontSize="sm">{m.init_noSuggestion()}</Text>
          <Command>git remote add origin https://github.com/OWNER/REPO.git</Command>
          <Button
            variant="outline"
            loading={action.loading}
            onClick={() =>
              action.run(async () => {
                await reloadRepo();
                await suggest();
              })
            }
          >
            {m.init_checkAgain()}
          </Button>
        </VStack>
      )}
      <Button
        {...primaryButton}
        loading={action.loading}
        disabled={!storage.trim()}
        onClick={() => action.run(() => onFound(storage.trim()))}
      >
        {m.init_found()}
      </Button>
    </SetupScreen>
  );
}

/** What the person does next after founding, joining or replacing the trust root. */
function InitDone({ result, onContinue }: { result: InitResult; onContinue: () => Promise<void> }) {
  const ghcr = result.storage.startsWith("oci://ghcr.io/")
    ? result.storage.slice("oci://ghcr.io/".length).split("/")
    : null;
  return (
    <SetupScreen
      title={result.pending ? m.init_pendingTitle() : m.init_foundedTitle()}
      error={null}
      onDismissError={() => {}}
    >
      {result.replaced_genesis && (
        <Text fontSize="sm">{m.init_replacedGenesis({ was: result.replaced_genesis })}</Text>
      )}
      {result.founded && (
        <Text>
          {ghcr && ghcr.length >= 2
            ? m.init_ghcrHint({ owner: ghcr[0], pkg: ghcr.slice(1).join("/") })
            : m.init_commitHint()}
        </Text>
      )}
      {result.pending && <Text>{m.init_pendingHint({ fingerprint: result.fingerprint })}</Text>}
      <Button {...primaryButton} onClick={() => void onContinue()}>
        {m.init_continue()}
      </Button>
    </SetupScreen>
  );
}

function Command({ children }: { children: string }) {
  return (
    <styled.pre
      p="3"
      bg="bg.muted"
      borderRadius="md"
      fontFamily="mono"
      fontSize="sm"
      overflowX="auto"
    >
      {children}
    </styled.pre>
  );
}
