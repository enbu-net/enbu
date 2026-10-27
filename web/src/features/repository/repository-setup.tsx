import { useEffect, useState, type ReactNode } from "react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Heading, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import { useSession } from "../../lib/session";
import { folderName } from "../../lib/paths";
import type { RepoInfo, RepositoryOwner } from "../../lib/types";
import { RepositoryOwnerSelect } from "./repository-owner-select";

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
  const { t } = useI18n();
  const { setRepo } = useSession();
  const [path, setPath] = useState("");
  const action = useAction();

  return (
    <SetupScreen
      title={t("repo.selectTitle")}
      description={t("repo.selectDescription")}
      error={action.error}
      onDismissError={() => action.setError(null)}
    >
      <HStack>
        <Input
          aria-label={t("repo.pathPlaceholder")}
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && path.trim()) {
              void action.run(async () => setRepo(await backend.selectRepository(path.trim())));
            }
          }}
          placeholder={t("repo.pathPlaceholder")}
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
          {t("repo.browse")}
        </Button>
      </HStack>
      <Button
        {...primaryButton}
        loading={action.loading}
        disabled={!path.trim()}
        onClick={() => action.run(async () => setRepo(await backend.selectRepository(path.trim())))}
      >
        {t("repo.continue")}
      </Button>
    </SetupScreen>
  );
}

/** Takes a selected folder through Git, a GitHub remote, and enbu setup. */
export function RepositorySetup({ repo, step }: { repo: RepoInfo; step: SetupStep }) {
  const { t } = useI18n();
  const { setRepo, reloadRepo } = useSession();
  const action = useAction();
  const dismiss = () => action.setError(null);

  if (step === "git") {
    return (
      <SetupScreen
        title={t("init.gitTitle")}
        description={t("init.gitDescription")}
        error={action.error}
        onDismissError={dismiss}
      >
        <Button
          {...primaryButton}
          loading={action.loading}
          onClick={() => action.run(async () => setRepo(await backend.gitInit(repo.path ?? "")))}
        >
          {t("init.gitAction")}
        </Button>
      </SetupScreen>
    );
  }

  if (step === "remote") {
    return <CreateRemote repo={repo} />;
  }

  return (
    <SetupScreen
      title={t("init.title")}
      description={t("init.description")}
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
        {t("init.action")}
      </Button>
    </SetupScreen>
  );
}

function CreateRemote({ repo }: { repo: RepoInfo }) {
  const { t } = useI18n();
  const { status, setRepo } = useSession();
  const action = useAction();
  const [name, setName] = useState(() => folderName(repo.path));
  const [owners, setOwners] = useState<RepositoryOwner[]>([]);
  const [owner, setOwner] = useState("");
  const [ownersLoading, setOwnersLoading] = useState(true);
  const [privateRepository, setPrivateRepository] = useState(true);
  const { setError } = action;

  useEffect(() => {
    let cancelled = false;
    setOwnersLoading(true);
    backend
      .listRepositoryOwners()
      .then((list) => {
        if (cancelled) return;
        setOwners(list);
        setOwner(
          (current) =>
            list.find((item) => item.login === current)?.login ??
            list.find((item) => item.login === status?.username)?.login ??
            list[0]?.login ??
            "",
        );
      })
      .catch((err) => {
        if (!cancelled) setError(toDisplayError(err));
      })
      .finally(() => {
        if (!cancelled) setOwnersLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [status?.username, setError]);

  return (
    <SetupScreen
      title={t("init.remoteTitle")}
      error={action.error}
      onDismissError={() => setError(null)}
    >
      <RepositoryOwnerSelect
        owners={owners}
        value={owner}
        loading={ownersLoading}
        onChange={setOwner}
      />
      <Input
        aria-label={t("init.repositoryName")}
        value={name}
        onChange={(event) => setName(event.target.value)}
        placeholder={t("init.repositoryName")}
        h="38px"
        borderColor="border.default"
        borderRadius="md"
      />
      <HStack>
        <input
          id="private-repository"
          type="checkbox"
          checked={privateRepository}
          onChange={(event) => setPrivateRepository(event.target.checked)}
        />
        <styled.label htmlFor="private-repository" fontSize="sm">
          {t("init.privateRepository")}
        </styled.label>
      </HStack>
      <Button
        {...primaryButton}
        loading={action.loading}
        disabled={!name.trim() || !owner}
        onClick={() =>
          action.run(async () =>
            setRepo(
              await backend.gitCreateRemote(repo.path ?? "", owner, name.trim(), privateRepository),
            ),
          )
        }
      >
        {t("init.createRemote")}
      </Button>
    </SetupScreen>
  );
}
