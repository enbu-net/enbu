import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Box, VStack, styled } from "styled-system/jsx";
import { hstack } from "styled-system/patterns";
import { Button, Heading, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { PageCenter } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { openURL } from "../../lib/platform";
import { useSession } from "../../lib/session";
import type { InitResult, RepoInfo, StorageConfig } from "../../lib/types";
import { m } from "../../paraglide/messages";
import { getLocale } from "../../paraglide/runtime";

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

/** No storage: Initialize suggests one, or joins the one enbu.toml names. */
const noStorage: StorageConfig = {
  url: "",
  region: "",
  endpoint: "",
  path_style: false,
  plain_http: false,
};

const primaryButton = {
  bg: "accent.default",
  color: "accent.fg",
  fontWeight: "semibold",
  _disabled: { opacity: 0.5, cursor: "not-allowed" },
} as const;

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
        <PublishGuide hasGit={false} />
        <Button {...primaryButton} loading={action.loading} onClick={() => action.run(reloadRepo)}>
          {m.init_checkAgain()}
        </Button>
      </SetupScreen>
    );
  }
  if (done) return <InitDone result={done} onContinue={reloadRepo} />;

  async function initialize(storage: StorageConfig, acceptNewGenesis: boolean) {
    const result = await backend.Initialize(storage, acceptNewGenesis);
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
        onClick={() => action.run(() => initialize(noStorage, false))}
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
            onClick={() => action.run(() => initialize(noStorage, true))}
          >
            {m.init_acceptNewGenesis()}
          </Button>
          <Text fontSize="sm">{m.init_newGenesis()}</Text>
          <Command>{action.error.params.configured ?? ""}</Command>
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
  onFound: (storage: StorageConfig) => Promise<void>;
}) {
  const { repo, reloadRepo } = useSession();
  const [storage, setStorage] = useState<StorageConfig>(noStorage);
  // null while asking, "" when there is none: no GitHub origin, or one whose
  // name GHCR does not accept.
  const [suggested, setSuggested] = useState<string | null>(null);
  const hasRemote = repo?.has_remote ?? false;
  const set = (change: Partial<StorageConfig>) =>
    setStorage((current) => ({ ...current, ...change }));

  const suggest = useCallback(async () => {
    const value = await backend.SuggestStorage().catch(() => "");
    setSuggested(value);
    setStorage((current) => (current.url ? current : { ...current, url: value }));
  }, []);

  useEffect(() => {
    void suggest();
  }, [suggest]);

  const url = storage.url.trim();
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
          value={storage.url}
          onChange={(e) => set({ url: e.target.value })}
          placeholder="oci://ghcr.io/OWNER/REPO-enbu"
          fontFamily="mono"
          h="auto"
          minH="38px"
          borderColor="border.default"
          borderRadius="md"
        />
        <Text fontSize="sm" color="fg.muted">
          {m.init_storageHint()}
        </Text>
      </VStack>
      {url.startsWith("s3://") && (
        <VStack alignItems="stretch" gap="2">
          <Input
            aria-label={m.init_region()}
            placeholder={m.init_region()}
            value={storage.region}
            onChange={(e) => set({ region: e.target.value })}
            h="auto"
            minH="38px"
            borderColor="border.default"
            borderRadius="md"
          />
          <Input
            aria-label={m.init_endpoint()}
            placeholder={m.init_endpoint()}
            value={storage.endpoint}
            onChange={(e) => set({ endpoint: e.target.value })}
            h="auto"
            minH="38px"
            borderColor="border.default"
            borderRadius="md"
          />
          <Option
            label={m.init_pathStyle()}
            checked={storage.path_style}
            onChange={(path_style) => set({ path_style })}
          />
        </VStack>
      )}
      {url.startsWith("oci://") && (
        <Option
          label={m.init_plainHttp()}
          checked={storage.plain_http}
          onChange={(plain_http) => set({ plain_http })}
        />
      )}
      {suggested === "" && hasRemote && <Text fontSize="sm">{m.init_noGhcrName()}</Text>}
      {suggested === "" && !hasRemote && (
        <VStack alignItems="stretch" gap="2">
          <Text fontSize="sm">{m.init_noSuggestion()}</Text>
          <PublishGuide hasGit />
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
        disabled={!url}
        onClick={() => action.run(() => onFound({ ...storage, url }))}
      >
        {m.init_found()}
      </Button>
    </SetupScreen>
  );
}

function Option({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={hstack({ gap: "2", fontSize: "sm" })}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

/** What the person does next after founding, joining or replacing the trust root. */
function InitDone({ result, onContinue }: { result: InitResult; onContinue: () => Promise<void> }) {
  const ghcr = result.storage.startsWith("oci://ghcr.io/")
    ? result.storage.slice("oci://ghcr.io/".length).split("/")
    : null;
  return (
    <SetupScreen
      title={
        result.pending
          ? m.init_pendingTitle()
          : result.founded
            ? m.init_foundedTitle()
            : m.init_title()
      }
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

/** The guide on enbu's website to putting a folder on GitHub, in the app's language. */
export function publishGuideURL() {
  const prefix = getLocale() === "ja" ? "/ja" : "";
  return `https://enbu.net${prefix}/docs/put-your-project-on-github/`;
}

/**
 * How to put the folder on GitHub with the tools a beginner already has,
 * GitHub Desktop or VS Code, with the commands kept for terminal users. enbu
 * leaves Git and GitHub to those tools.
 */
function PublishGuide({ hasGit }: { hasGit: boolean }) {
  const ways = [
    { name: "GitHub Desktop", how: hasGit ? m.publish_desktopRemote() : m.publish_desktopInit() },
    { name: "VS Code", how: hasGit ? m.publish_vscodeRemote() : m.publish_vscodeInit() },
  ];
  return (
    <VStack alignItems="stretch" gap="3">
      <styled.ul display="flex" flexDirection="column" gap="2">
        {ways.map((way) => (
          <styled.li
            key={way.name}
            p="3"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="md"
            bg="bg.surface"
          >
            <Text fontWeight="semibold">{way.name}</Text>
            <Text fontSize="sm" color="fg.subtle">
              {way.how}
            </Text>
          </styled.li>
        ))}
      </styled.ul>
      <Text fontSize="sm" color="status.danger">
        {m.publish_secretsWarning()}
      </Text>
      <styled.details fontSize="sm">
        <styled.summary cursor="pointer" color="fg.subtle">
          {m.publish_terminal()}
        </styled.summary>
        <Box mt="2">
          <Text color="fg.subtle" mb="2">
            {m.publish_terminalNote()}
          </Text>
          <Command>
            {hasGit
              ? "git remote add origin https://github.com/OWNER/REPO.git"
              : "git init\ngit remote add origin https://github.com/OWNER/REPO.git"}
          </Command>
        </Box>
      </styled.details>
      <Button
        variant="outline"
        borderColor="border.strong"
        onClick={() => openURL(publishGuideURL())}
      >
        {m.publish_openGuide()}
      </Button>
    </VStack>
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
