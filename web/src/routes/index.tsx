import { createFileRoute } from "@tanstack/react-router";
import { type RefObject, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Box, Flex, HStack, VStack, styled } from "styled-system/jsx";
import { Alert, Button, Heading, Input, Popover, Spinner, Tabs, Text } from "../components/ui";
import {
  Building2,
  Check,
  ChevronDown,
  Code2,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileOutput,
  KeyRound,
  Layers3,
  ListTree,
  Plus,
  RefreshCw,
  SlidersHorizontal,
  Trash2,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import {
  backend,
  openURL,
  type OAuthStart,
  type OAuthStatus,
  type RepositoryOwner,
} from "../lib/backend";
import type { Environment, Recipient, SecretsResponse } from "../lib/api";
import { useI18n } from "../lib/i18n";
import { useAuth } from "./__root";
import { TomlCodeEditor } from "../components/toml-code-editor";
import { ConfirmDeleteDialog } from "../components/confirm-delete-dialog";
import { TransferModal } from "../components/transfer-modal";
import { useFocusTrap } from "../lib/use-focus-trap";
import { LanguageSelector } from "../components/language-selector";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

export const Route = createFileRoute("/")({
  component: HomePage,
});

export function resolveWorkspaceEnvironment(requested: string, environments: Environment[]) {
  if (requested && environments.some((environment) => environment.name === requested)) {
    return requested;
  }
  return (
    environments.find((environment) => environment.current)?.name ?? environments[0]?.name ?? ""
  );
}

export function RepositoryOwnerSelect({
  owners,
  value,
  loading,
  onChange,
}: {
  owners: RepositoryOwner[];
  value: string;
  loading: boolean;
  onChange: (owner: string) => void;
}) {
  const { t } = useI18n();
  const selected = owners.find((owner) => owner.login === value);
  const SelectedIcon = selected?.organization ? Building2 : UserRound;
  return (
    <Box>
      <styled.label htmlFor="repository-owner" display="block" fontSize="sm" mb={1.5}>
        {t("init.repositoryOwner")}
      </styled.label>
      <Popover.Root positioning={{ placement: "bottom-start", sameWidth: true, gutter: 6 }}>
        <Popover.Trigger asChild>
          <Button
            id="repository-owner"
            type="button"
            variant="outline"
            w="full"
            h="52px"
            px="3"
            justifyContent="space-between"
            borderColor="border.default"
            borderRadius="lg"
            bg="bg.surface"
            boxShadow="xs"
            disabled={loading || owners.length === 0}
            _hover={{ borderColor: "accent.default", bg: "bg.muted" }}
          >
            <HStack gap="3" minW="0">
              <Box
                w="34px"
                h="34px"
                display="grid"
                placeItems="center"
                borderRadius="md"
                bg="accent.subtle"
                color="accent.default"
                flexShrink="0"
              >
                {loading ? <Spinner size="sm" /> : <SelectedIcon size={17} />}
              </Box>
              <VStack gap="0" alignItems="start" minW="0">
                <Text fontWeight="semibold" fontSize="sm" truncate>
                  {selected?.login ?? t("common.loading")}
                </Text>
                {selected && (
                  <Text color="fg.muted" fontSize="xs">
                    {t(selected.organization ? "init.organization" : "init.personalAccount")}
                  </Text>
                )}
              </VStack>
            </HStack>
            <ChevronDown size={16} color="currentColor" />
          </Button>
        </Popover.Trigger>
        <Popover.Positioner>
          <Popover.Content
            p="1.5"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="lg"
            boxShadow="dropdown"
            bg="bg.surface"
          >
            <VStack gap="1" alignItems="stretch">
              {owners.map((owner) => {
                const OwnerIcon = owner.organization ? Building2 : UserRound;
                const active = owner.login === value;
                return (
                  <Popover.CloseTrigger key={owner.login} asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      h="48px"
                      px="2.5"
                      justifyContent="space-between"
                      borderRadius="md"
                      bg={active ? "accent.subtle" : undefined}
                      onClick={() => onChange(owner.login)}
                    >
                      <HStack gap="3">
                        <Box
                          w="30px"
                          h="30px"
                          display="grid"
                          placeItems="center"
                          borderRadius="md"
                          bg={owner.organization ? "accent.subtle" : "bg.muted"}
                          color={owner.organization ? "accent.default" : "fg.muted"}
                        >
                          <OwnerIcon size={15} />
                        </Box>
                        <Box textAlign="left">
                          <Text fontSize="sm" fontWeight="semibold">
                            {owner.login}
                          </Text>
                          <Text fontSize="xs" color="fg.muted">
                            {t(owner.organization ? "init.organization" : "init.personalAccount")}
                          </Text>
                        </Box>
                      </HStack>
                      {active && <Check size={16} />}
                    </Button>
                  </Popover.CloseTrigger>
                );
              })}
            </VStack>
          </Popover.Content>
        </Popover.Positioner>
      </Popover.Root>
    </Box>
  );
}

export function HomePage() {
  const { t } = useI18n();
  const { status, loading: authLoading } = useAuth();

  const [repoStatus, setRepoStatus] = useState<{
    selected: boolean;
    repo?: {
      path?: string;
      owner: string;
      repo: string;
      initialized?: boolean;
      has_git?: boolean;
      has_remote?: boolean;
    };
  } | null>(null);
  const [repoPath, setRepoPath] = useState("");
  const [repoError, setRepoError] = useState("");
  const [selectingRepo, setSelectingRepo] = useState(false);
  const [oauthStart, setOAuthStart] = useState<OAuthStart | null>(null);
  const [oauthStatus, setOAuthStatus] = useState<OAuthStatus | null>(null);
  const [authError, setAuthError] = useState("");
  const [startingAuth, setStartingAuth] = useState(false);
  const [initializing, setInitializing] = useState(false);
  const [repositorySetupLoading, setRepositorySetupLoading] = useState(false);
  const [remoteRepoName, setRemoteRepoName] = useState("");
  const [repositoryOwners, setRepositoryOwners] = useState<RepositoryOwner[]>([]);
  const [selectedRepositoryOwner, setSelectedRepositoryOwner] = useState("");
  const [repositoryOwnersLoading, setRepositoryOwnersLoading] = useState(false);
  const [privateRepository, setPrivateRepository] = useState(true);
  const [workspaceLoading, setWorkspaceLoading] = useState(false);
  const [pullLoading, setPullLoading] = useState(false);
  const [exportLoading, setExportLoading] = useState(false);
  const [addLoading, setAddLoading] = useState(false);
  const [actionError, setActionError] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [secrets, setSecrets] = useState<SecretsResponse | null>(null);
  const [secretKey, setSecretKey] = useState("");
  const [secretValue, setSecretValue] = useState("");
  const [newEnv, setNewEnv] = useState("");
  const [environmentModalOpen, setEnvironmentModalOpen] = useState(false);
  const [environmentCreateLoading, setEnvironmentCreateLoading] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [recipientsLoading, setRecipientsLoading] = useState(false);
  const [recipientsError, setRecipientsError] = useState("");
  const recipientsRequestRef = useRef(0);
  const secretTransferInFlightRef = useRef(false);
  const addEnvironmentTriggerRef = useRef<HTMLButtonElement>(null);
  const [transferModal, setTransferModal] = useState<{
    open: boolean;
    op: "add" | "pull" | "export" | "sync" | "delete" | null;
    error: string | null;
  }>({ open: false, op: null, error: null });

  const runWithTransferAnimation = useCallback(
    async (op: "add" | "pull" | "export" | "sync" | "delete", task: () => Promise<void>) => {
      setTransferModal({ open: true, op, error: null });
      try {
        await task();
        await new Promise((r) => setTimeout(r, 1200));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setTransferModal({ open: true, op, error: msg });
        await new Promise((r) => setTimeout(r, 2200));
        throw err;
      } finally {
        setTransferModal({ open: false, op: null, error: null });
      }
    },
    [],
  );

  const fetchRepoStatus = useCallback(async () => {
    if (status?.authenticated) {
      setRepoStatus(await backend.repoStatus());
    }
  }, [status?.authenticated]);

  useEffect(() => {
    fetchRepoStatus().catch((err) =>
      setRepoError(err instanceof Error ? err.message : String(err)),
    );
  }, [fetchRepoStatus]);

  useEffect(() => {
    const onAuthChanged = () => void fetchRepoStatus();
    window.addEventListener("enbu-auth-changed", onAuthChanged);
    return () => window.removeEventListener("enbu-auth-changed", onAuthChanged);
  }, [fetchRepoStatus]);

  useEffect(() => {
    if (!oauthStart || oauthStatus?.state !== "pending") return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [oauthStart, oauthStatus?.state]);

  useEffect(() => {
    if (!oauthStart || oauthStatus?.state !== "pending") return;
    const poll = window.setInterval(async () => {
      try {
        const next = await backend.oauthStatus(oauthStart.session_id);
        if (next.state !== "success") {
          setOAuthStatus(next);
          return;
        }
        window.clearInterval(poll);
        setOAuthStart(null);
        setOAuthStatus(null);
        window.dispatchEvent(new Event("enbu-auth-changed"));
        try {
          setRepoStatus(await backend.repoStatus());
        } catch (err) {
          setRepoError(err instanceof Error ? err.message : String(err));
        }
      } catch (err) {
        setOAuthStatus({
          state: "error",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }, 1000);
    return () => window.clearInterval(poll);
  }, [oauthStart, oauthStatus?.state]);

  const expiresIn = useMemo(() => {
    if (!oauthStart) return 0;
    return Math.max(0, Math.ceil((new Date(oauthStart.expires_at).getTime() - now) / 1000));
  }, [oauthStart, now]);

  const currentEnvironment = useMemo(
    () => environments.find((env) => env.current)?.name ?? secrets?.environment ?? "",
    [environments, secrets?.environment],
  );

  const recipientRepoPath = repoStatus?.repo?.path ?? "";
  const fetchRecipients = useCallback(async () => {
    if (!recipientRepoPath) return;
    const request = ++recipientsRequestRef.current;
    setRecipientsLoading(true);
    setRecipientsError("");
    try {
      const list = await backend.listRecipients();
      if (request !== recipientsRequestRef.current) return;
      setRecipients((list ?? []).filter((r): r is Recipient => r != null));
    } catch (err) {
      if (request !== recipientsRequestRef.current) return;
      setRecipientsError(err instanceof Error ? err.message : String(err));
    } finally {
      if (request === recipientsRequestRef.current) setRecipientsLoading(false);
    }
  }, [recipientRepoPath]);

  async function refreshWorkspace(env = currentEnvironment) {
    setWorkspaceLoading(true);
    setActionError("");
    try {
      const envs = await backend.listEnvironments();
      const nextEnv = resolveWorkspaceEnvironment(env, envs);
      setEnvironments([...envs].sort((a, b) => a.name.localeCompare(b.name)));
      setSecrets(await backend.listSecrets(nextEnv));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setWorkspaceLoading(false);
    }
  }

  useEffect(() => {
    if (repoStatus?.selected && repoStatus.repo?.initialized) void refreshWorkspace();
  }, [repoStatus?.selected, repoStatus?.repo?.initialized]);

  useEffect(() => {
    if (repoStatus?.selected && repoStatus.repo?.initialized && recipientRepoPath) {
      void fetchRecipients();
      return;
    }
    recipientsRequestRef.current++;
    setRecipients([]);
    setRecipientsLoading(false);
  }, [repoStatus?.selected, repoStatus?.repo?.initialized, recipientRepoPath, fetchRecipients]);

  useEffect(() => {
    const path = repoStatus?.repo?.path?.replace(/[\\/]+$/, "");
    setRemoteRepoName(path?.split(/[\\/]/).pop() ?? "");
  }, [repoStatus?.repo?.path]);

  useEffect(() => {
    if (!repoStatus?.repo?.has_git || repoStatus.repo.has_remote) return;

    let cancelled = false;
    setRepositoryOwnersLoading(true);
    setActionError("");
    backend
      .listRepositoryOwners()
      .then((owners) => {
        if (cancelled) return;
        setRepositoryOwners(owners);
        setSelectedRepositoryOwner((current) => {
          if (owners.some((owner) => owner.login === current)) return current;
          return (
            owners.find((owner) => owner.login === status?.username)?.login ??
            owners[0]?.login ??
            ""
          );
        });
      })
      .catch((err) => {
        if (!cancelled) setActionError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setRepositoryOwnersLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [repoStatus?.repo?.has_git, repoStatus?.repo?.has_remote, status?.username]);

  async function handleStartAuth() {
    setStartingAuth(true);
    setAuthError("");
    try {
      const start = await backend.startOAuthLogin();
      setOAuthStart(start);
      setOAuthStatus({ state: "pending" });
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : String(err));
    } finally {
      setStartingAuth(false);
    }
  }

  // Screen 01: Loading
  if (authLoading) {
    return (
      <PageCenter>
        <VStack gap={3}>
          <Spinner size="xl" color="accent.default" />
          <Text color="fg.muted">{t("common.loading")}</Text>
        </VStack>
      </PageCenter>
    );
  }

  // Screen 02: Auth start
  if (!status?.authenticated && !oauthStart) {
    return (
      <PageCenter>
        <VStack gap={5} w="full" maxW="480px" textAlign="center">
          {authError && <ErrorAlert message={authError} onDismiss={() => setAuthError("")} />}
          <Button
            w="full"
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            loading={startingAuth}
            onClick={handleStartAuth}
          >
            <SiGithub size={16} aria-hidden="true" />
            {t("auth.connect")}
          </Button>
          <LanguageSelector w="full" justifyContent="flex-end" pt="3" />
        </VStack>
      </PageCenter>
    );
  }

  // Screen 03: OAuth callback wait
  if (!status?.authenticated && oauthStart) {
    return (
      <PageCenter>
        <OAuthLoginPanel
          status={oauthStatus}
          expiresIn={expiresIn}
          onCancel={async () => {
            await backend.cancelOAuthLogin(oauthStart.session_id);
            setOAuthStart(null);
            setOAuthStatus(null);
          }}
          onRetry={() => {
            setOAuthStart(null);
            setOAuthStatus(null);
            setAuthError("");
          }}
        />
      </PageCenter>
    );
  }

  if (status?.authenticated && oauthStart) {
    return (
      <PageCenter>
        <OAuthLoginPanel
          status={oauthStatus}
          expiresIn={expiresIn}
          onCancel={async () => {
            await backend.cancelOAuthLogin(oauthStart.session_id);
            setOAuthStart(null);
            setOAuthStatus(null);
          }}
          onRetry={() => {
            setOAuthStart(null);
            setOAuthStatus(null);
            setAuthError("");
          }}
        />
      </PageCenter>
    );
  }

  // Screen 04: Repository selection
  if (!repoStatus?.selected) {
    return (
      <PageCenter>
        <VStack gap={5} w="full" maxW="540px" alignItems="stretch">
          <Box>
            <Heading as="h1" size="2xl" fontWeight="extrabold" mb={2}>
              {t("repo.selectTitle")}
            </Heading>
            <Text color="fg.muted">{t("repo.selectDescription")}</Text>
          </Box>
          {repoError && <ErrorAlert message={repoError} onDismiss={() => setRepoError("")} />}
          <HStack>
            <Input
              aria-label={t("repo.pathPlaceholder")}
              value={repoPath}
              onChange={(e) => setRepoPath(e.target.value)}
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
              onClick={async () => {
                setSelectingRepo(true);
                setRepoError("");
                try {
                  const nextRepoStatus = await backend.browseRepository();
                  setRepoStatus(nextRepoStatus);
                  window.dispatchEvent(new Event("enbu-repo-changed"));
                  window.dispatchEvent(new Event("enbu-auth-changed"));
                } catch (err) {
                  setRepoError(err instanceof Error ? err.message : String(err));
                } finally {
                  setSelectingRepo(false);
                }
              }}
            >
              {t("repo.browse")}
            </Button>
          </HStack>
          <Button
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            loading={selectingRepo}
            onClick={async () => {
              setSelectingRepo(true);
              setRepoError("");
              try {
                const nextRepoStatus = await backend.selectRepository(repoPath);
                setRepoStatus(nextRepoStatus);
                window.dispatchEvent(new Event("enbu-repo-changed"));
                window.dispatchEvent(new Event("enbu-auth-changed"));
              } catch (err) {
                setRepoError(err instanceof Error ? err.message : String(err));
              } finally {
                setSelectingRepo(false);
              }
            }}
          >
            {t("repo.continue")}
          </Button>
        </VStack>
      </PageCenter>
    );
  }

  // Screen 05a: Initialize the selected folder as a Git repository.
  if (!repoStatus.repo?.has_git) {
    return (
      <PageCenter>
        <VStack gap={5} w="full" maxW="540px" alignItems="stretch">
          <Box>
            <Heading as="h1" size="2xl" fontWeight="extrabold" mb={2}>
              {t("init.gitTitle")}
            </Heading>
            <Text color="fg.muted">{t("init.gitDescription")}</Text>
          </Box>
          {actionError && <ErrorAlert message={actionError} onDismiss={() => setActionError("")} />}
          <Button
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            loading={repositorySetupLoading}
            onClick={async () => {
              setRepositorySetupLoading(true);
              setActionError("");
              try {
                setRepoStatus(await backend.gitInit(repoStatus.repo?.path ?? ""));
              } catch (err) {
                setActionError(err instanceof Error ? err.message : String(err));
              } finally {
                setRepositorySetupLoading(false);
              }
            }}
          >
            {t("init.gitAction")}
          </Button>
        </VStack>
      </PageCenter>
    );
  }

  // Screen 05b: Create and attach an origin remote before enbu setup.
  if (!repoStatus.repo.has_remote) {
    return (
      <PageCenter>
        <VStack gap={5} w="full" maxW="540px" alignItems="stretch">
          <Heading as="h1" size="2xl" fontWeight="extrabold">
            {t("init.remoteTitle")}
          </Heading>
          {actionError && <ErrorAlert message={actionError} onDismiss={() => setActionError("")} />}
          <RepositoryOwnerSelect
            owners={repositoryOwners}
            value={selectedRepositoryOwner}
            loading={repositoryOwnersLoading}
            onChange={setSelectedRepositoryOwner}
          />
          <Input
            aria-label={t("init.repositoryName")}
            value={remoteRepoName}
            onChange={(event) => setRemoteRepoName(event.target.value)}
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
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            loading={repositorySetupLoading}
            disabled={!remoteRepoName.trim() || !selectedRepositoryOwner}
            onClick={async () => {
              setRepositorySetupLoading(true);
              setActionError("");
              try {
                const nextRepoStatus = await backend.gitCreateRemote(
                  repoStatus.repo?.path ?? "",
                  selectedRepositoryOwner,
                  remoteRepoName.trim(),
                  privateRepository,
                );
                setRepoStatus(nextRepoStatus);
                window.dispatchEvent(new Event("enbu-repo-changed"));
                window.dispatchEvent(new Event("enbu-auth-changed"));
              } catch (err) {
                setActionError(err instanceof Error ? err.message : String(err));
              } finally {
                setRepositorySetupLoading(false);
              }
            }}
          >
            {t("init.createRemote")}
          </Button>
        </VStack>
      </PageCenter>
    );
  }

  // Screen 05c: Initialize enbu after Git and origin are ready.
  if (!repoStatus.repo?.initialized) {
    return (
      <PageCenter>
        <VStack gap={5} w="full" maxW="540px" alignItems="stretch">
          <Box>
            <Heading as="h1" size="2xl" fontWeight="extrabold" mb={2}>
              {t("init.title")}
            </Heading>
            <Text color="fg.muted">{t("init.description")}</Text>
          </Box>
          {actionError && <ErrorAlert message={actionError} onDismiss={() => setActionError("")} />}
          <Button
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            loading={initializing}
            onClick={async () => {
              setInitializing(true);
              setActionError("");
              try {
                await backend.initialize();
                setRepoStatus(await backend.repoStatus());
              } catch (err) {
                setActionError(err instanceof Error ? err.message : String(err));
              } finally {
                setInitializing(false);
              }
            }}
          >
            {t("init.action")}
          </Button>
        </VStack>
      </PageCenter>
    );
  }

  // Screen 06/07: Dashboard
  return (
    <Box
      minH="calc(100vh - 72px)"
      px={{ base: "4", md: "7", lg: "12" }}
      py={{ base: "7", lg: "10" }}
      bg="bg.muted"
    >
      <Box maxW="1120px" mx="auto">
        <Flex align={{ base: "start", sm: "center" }} justify="space-between" gap="4" mb="7">
          <Box>
            <Button
              variant="ghost"
              p="0"
              h="auto"
              color="fg.default"
              fontSize="3xl"
              fontWeight="extrabold"
              letterSpacing="tight"
              onClick={() =>
                openURL(`https://github.com/${repoStatus.repo?.owner}/${repoStatus.repo?.repo}`)
              }
            >
              <SiGithub size={24} aria-hidden="true" />
              {repoStatus.repo?.owner}/{repoStatus.repo?.repo}
            </Button>
          </Box>
        </Flex>

        {actionError && (
          <Box mb="4">
            <ErrorAlert message={actionError} onDismiss={() => setActionError("")} />
          </Box>
        )}

        <Tabs.Root defaultValue="secrets" lazyMount unmountOnExit variant="line">
          <Tabs.List w="full" h="auto" display="flex" gap="0" overflow="hidden">
            <DashboardTab
              value="secrets"
              icon={<KeyRound size={16} />}
              label={t("dashboard.secrets")}
            />
            <DashboardTab
              value="members"
              icon={<Users size={16} />}
              label={t("recipients.members")}
            />
            <DashboardTab
              value="settings"
              icon={<SlidersHorizontal size={16} />}
              label={t("config.settings")}
            />
          </Tabs.List>

          <DashboardTabContent value="secrets">
            <SectionHeader
              title={
                <EnvironmentSelector
                  environments={environments}
                  value={currentEnvironment}
                  addTriggerRef={addEnvironmentTriggerRef}
                  onSelect={async (environment) => {
                    if (environment === currentEnvironment) return;
                    try {
                      await backend.switchEnvironment(environment);
                      await refreshWorkspace(environment);
                    } catch (err) {
                      setActionError(err instanceof Error ? err.message : String(err));
                    }
                  }}
                  onAdd={() => setEnvironmentModalOpen(true)}
                />
              }
            >
              <HStack gap="2">
                <Button
                  size="sm"
                  variant="outline"
                  loading={pullLoading}
                  disabled={exportLoading || workspaceLoading}
                  title={t("dashboard.pullDescription")}
                  onClick={async () => {
                    if (secretTransferInFlightRef.current || workspaceLoading) return;
                    secretTransferInFlightRef.current = true;
                    setPullLoading(true);
                    try {
                      await runWithTransferAnimation("pull", async () => {
                        await backend.pullSecrets(currentEnvironment);
                        await refreshWorkspace(currentEnvironment);
                      });
                    } catch (err) {
                      setActionError(err instanceof Error ? err.message : String(err));
                    } finally {
                      setPullLoading(false);
                      secretTransferInFlightRef.current = false;
                    }
                  }}
                >
                  <Download size={14} />
                  {t("dashboard.pull")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  loading={exportLoading}
                  disabled={pullLoading || workspaceLoading}
                  title={t("dashboard.exportDescription")}
                  onClick={async () => {
                    if (secretTransferInFlightRef.current || workspaceLoading) return;
                    secretTransferInFlightRef.current = true;
                    setExportLoading(true);
                    try {
                      await runWithTransferAnimation("export", async () => {
                        await backend.exportSecrets(currentEnvironment);
                      });
                    } catch (err) {
                      setActionError(err instanceof Error ? err.message : String(err));
                    } finally {
                      setExportLoading(false);
                      secretTransferInFlightRef.current = false;
                    }
                  }}
                >
                  <FileOutput size={14} />
                  {t("dashboard.export")}
                </Button>
              </HStack>
            </SectionHeader>
            {workspaceLoading ? (
              <HStack role="status" py="8" justify="center">
                <Spinner size="sm" aria-hidden="true" />
                <Text color="fg.muted">{t("common.loading")}</Text>
              </HStack>
            ) : (
              <Box
                overflow="hidden"
                borderWidth="1px"
                borderColor="border.default"
                borderRadius="xl"
              >
                {secrets?.secrets.map((secret) => (
                  <SecretRow
                    key={secret.key}
                    secretKey={secret.key}
                    secretValue={secret.value}
                    onEdit={async (value) => {
                      try {
                        await backend.editSecret(secret.key, value, currentEnvironment);
                        await refreshWorkspace(currentEnvironment);
                      } catch (err) {
                        setActionError(err instanceof Error ? err.message : String(err));
                      }
                    }}
                    onDelete={async () => {
                      try {
                        await runWithTransferAnimation("delete", async () => {
                          await backend.deleteSecret(secret.key, currentEnvironment);
                          await refreshWorkspace(currentEnvironment);
                        });
                      } catch (err) {
                        setActionError(err instanceof Error ? err.message : String(err));
                      }
                    }}
                    deleteLabel={t("dashboard.delete")}
                  />
                ))}
                {(secrets?.secrets.length ?? 0) === 0 && (
                  <Text color="fg.muted" textAlign="center" py="8">
                    {t(secrets?.cached === false ? "dashboard.cacheEmpty" : "dashboard.empty")}
                  </Text>
                )}
              </Box>
            )}
            <Box
              mt="4"
              p="3"
              display="grid"
              gridTemplateColumns={{
                base: "1fr",
                md: "minmax(160px,.8fr) minmax(220px,1.2fr) auto",
              }}
              gap="2"
              bg="bg.muted"
              borderRadius="lg"
            >
              <Input
                aria-label={t("dashboard.key")}
                placeholder={t("dashboard.key")}
                value={secretKey}
                onChange={(event) => setSecretKey(event.target.value)}
              />
              <Input
                aria-label={t("dashboard.value")}
                placeholder={t("dashboard.value")}
                value={secretValue}
                onChange={(event) => setSecretValue(event.target.value)}
              />
              <Button
                colorPalette="accent"
                loading={addLoading}
                disabled={!secretKey.trim()}
                onClick={async () => {
                  const trimmedKey = secretKey.trim();
                  if (!trimmedKey) return;
                  if (secrets?.secrets.some((s) => s.key === trimmedKey)) {
                    setActionError(t("dashboard.duplicateKey", { key: trimmedKey }));
                    return;
                  }
                  setAddLoading(true);
                  try {
                    await runWithTransferAnimation("add", async () => {
                      await backend.addSecret(trimmedKey, secretValue, currentEnvironment);
                      setSecretKey("");
                      setSecretValue("");
                      await refreshWorkspace(currentEnvironment);
                    });
                  } catch (err) {
                    setActionError(err instanceof Error ? err.message : String(err));
                  } finally {
                    setAddLoading(false);
                  }
                }}
              >
                <Plus size={15} />
                {t("dashboard.add")}
              </Button>
            </Box>
          </DashboardTabContent>

          <DashboardTabContent value="members">
            <RecipientsPanel
              recipients={recipients}
              loading={recipientsLoading}
              error={recipientsError}
              onSync={async () => {
                setRecipientsLoading(true);
                try {
                  await runWithTransferAnimation("sync", async () => {
                    await backend.syncSecrets(currentEnvironment);
                    await fetchRecipients();
                  });
                } catch (err) {
                  setRecipientsError(err instanceof Error ? err.message : String(err));
                } finally {
                  setRecipientsLoading(false);
                }
              }}
              onErrorDismiss={() => setRecipientsError("")}
            />
          </DashboardTabContent>
          <DashboardTabContent value="settings">
            <ConfigPanel environments={environments} />
          </DashboardTabContent>
        </Tabs.Root>
        <CreateEnvironmentModal
          open={environmentModalOpen}
          value={newEnv}
          loading={environmentCreateLoading}
          triggerRef={addEnvironmentTriggerRef}
          onValueChange={setNewEnv}
          onClose={() => {
            if (environmentCreateLoading) return;
            setEnvironmentModalOpen(false);
            setNewEnv("");
          }}
          onCreate={async () => {
            const created = newEnv.trim();
            if (!created) return;
            setEnvironmentCreateLoading(true);
            setActionError("");
            try {
              await backend.createEnvironment(created);
              await backend.switchEnvironment(created);
              await refreshWorkspace(created);
              setEnvironmentModalOpen(false);
              setNewEnv("");
            } catch (err) {
              setActionError(err instanceof Error ? err.message : String(err));
            } finally {
              setEnvironmentCreateLoading(false);
            }
          }}
        />
        <TransferModal
          open={transferModal.open}
          operation={transferModal.op}
          error={transferModal.error}
          onClose={() => setTransferModal({ open: false, op: null, error: null })}
        />
      </Box>
    </Box>
  );
}

// --- Sub-components ---

export function EnvironmentSelector({
  environments,
  value,
  addTriggerRef,
  onSelect,
  onAdd,
}: {
  environments: Environment[];
  value: string;
  addTriggerRef?: RefObject<HTMLButtonElement | null>;
  onSelect: (environment: string) => void | Promise<void>;
  onAdd: () => void;
}) {
  const { t } = useI18n();
  return (
    <HStack gap="2" flexWrap="wrap">
      <Popover.Root positioning={{ placement: "bottom-start", gutter: 6 }}>
        <Popover.Trigger asChild>
          <Button
            ref={addTriggerRef}
            type="button"
            variant="outline"
            h="40px"
            px="3"
            color="fg.default"
            bg="bg.surface"
            borderColor="border.default"
            borderRadius="lg"
            fontSize="lg"
            fontWeight="extrabold"
            aria-label={t("dashboard.currentEnvironment")}
          >
            <Layers3 size={16} />
            {value}
            <ChevronDown size={15} />
          </Button>
        </Popover.Trigger>
        <Popover.Positioner>
          <Popover.Content
            minW="240px"
            p="1.5"
            bg="bg.surface"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="lg"
            boxShadow="dropdown"
          >
            <VStack alignItems="stretch" gap="1">
              {environments.map((environment) => {
                const selected = environment.name === value;
                return (
                  <Popover.CloseTrigger key={environment.name} asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      w="full"
                      justifyContent="space-between"
                      color="fg.default"
                      bg={selected ? "accent.subtle" : undefined}
                      onClick={() => void onSelect(environment.name)}
                    >
                      <HStack gap="2">
                        <Layers3 size={15} />
                        {environment.name}
                      </HStack>
                      {selected && <Check size={15} color="currentColor" />}
                    </Button>
                  </Popover.CloseTrigger>
                );
              })}
              <Box h="1px" my="1" bg="border.default" />
              <Popover.CloseTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  w="full"
                  justifyContent="start"
                  color="accent.default"
                  onClick={onAdd}
                >
                  <Plus size={15} />
                  {t("dashboard.addEnvironment")}
                </Button>
              </Popover.CloseTrigger>
            </VStack>
          </Popover.Content>
        </Popover.Positioner>
      </Popover.Root>
      <Text as="span" fontSize="xl" fontWeight="extrabold">
        {t("dashboard.secretHeadingSuffix")}
      </Text>
    </HStack>
  );
}

export function CreateEnvironmentModal({
  open,
  value,
  loading,
  triggerRef,
  onValueChange,
  onClose,
  onCreate,
}: {
  open: boolean;
  value: string;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  onValueChange: (value: string) => void;
  onClose: () => void;
  onCreate: () => void | Promise<void>;
}) {
  const { t } = useI18n();
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(open, dialogRef, triggerRef);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !loading) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [loading, onClose, open]);

  if (!open) return null;
  return (
    <Box
      position="fixed"
      inset="0"
      zIndex="50"
      display="grid"
      placeItems="center"
      p="4"
      bg="rgba(15, 23, 42, 0.48)"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !loading) onClose();
      }}
    >
      <Box
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        w="full"
        maxW="440px"
        p="5"
        bg="bg.surface"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="2xl"
        boxShadow="xl"
      >
        <Flex justify="space-between" align="start" gap="4" mb="5">
          <Heading id={titleId} size="lg" fontWeight="extrabold">
            {t("dashboard.createEnvironmentTitle")}
          </Heading>
          <Button
            type="button"
            variant="ghost"
            w="32px"
            h="32px"
            p="0"
            aria-label={t("config.cancel")}
            disabled={loading}
            onClick={onClose}
          >
            <X size={16} aria-hidden="true" />
          </Button>
        </Flex>
        <styled.label
          htmlFor="new-environment-name"
          display="block"
          mb="2"
          fontSize="sm"
          fontWeight="semibold"
        >
          {t("dashboard.environmentName")}
        </styled.label>
        <Input
          id="new-environment-name"
          autoFocus
          value={value}
          placeholder={t("dashboard.newEnvironment")}
          disabled={loading}
          onChange={(event) => onValueChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && value.trim() && !loading) void onCreate();
          }}
        />
        <HStack justify="end" gap="2" mt="5">
          <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
            {t("config.cancel")}
          </Button>
          <Button
            type="button"
            colorPalette="accent"
            loading={loading}
            disabled={!value.trim()}
            onClick={() => void onCreate()}
          >
            {t("dashboard.createEnvironment")}
          </Button>
        </HStack>
      </Box>
    </Box>
  );
}

function DashboardTab({
  value,
  icon,
  label,
}: {
  value: string;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <Tabs.Trigger
      value={value}
      aria-label={label}
      flex="1"
      minW="0"
      h={{ base: "48px", sm: "42px" }}
      px={{ base: "1.5", sm: "3" }}
      display="flex"
      alignItems="center"
      justifyContent="center"
      gap="2"
      color="fg.muted"
      bg="transparent"
      borderWidth="0"
      borderRadius="0"
      fontSize={{ base: "2xs", sm: "sm" }}
      fontWeight="semibold"
      position="relative"
      _after={{
        content: '""',
        position: "absolute",
        left: "3",
        right: "3",
        bottom: "0",
        h: "3px",
        bg: "transparent",
        borderRadius: "full",
      }}
      _selected={{
        color: "fg.default",
        bg: "transparent",
        _after: { bg: "accent.default" },
      }}
      _hover={{ color: "fg.default", bg: "transparent" }}
    >
      <Box as="span" aria-hidden="true">
        {icon}
      </Box>
      <Text as="span" display={{ base: "none", sm: "inline" }} fontSize="inherit">
        {label}
      </Text>
    </Tabs.Trigger>
  );
}

function DashboardTabContent({ value, children }: { value: string; children: React.ReactNode }) {
  return (
    <Tabs.Content
      value={value}
      minH="420px"
      mt="4.5"
      p={{ base: "4", md: "7" }}
      bg="bg.surface"
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="2xl"
      boxShadow="app"
    >
      {children}
    </Tabs.Content>
  );
}

function SectionHeader({
  title,
  children,
}: {
  title: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <Flex
      align={{ base: "start", sm: "center" }}
      justify="space-between"
      gap="3"
      mb="6"
      flexWrap="wrap"
    >
      <Heading size="lg" fontWeight="bold">
        {title}
      </Heading>
      {children}
    </Flex>
  );
}

function PageCenter({ children }: { children: React.ReactNode }) {
  return (
    <Box minH="calc(100vh - 72px)" display="grid" placeItems="center" px={6} py={12}>
      {children}
    </Box>
  );
}

function ErrorAlert({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  const { t } = useI18n();
  return (
    <Alert.Root
      borderRadius="md"
      borderWidth="1px"
      borderColor="status.danger"
      bg="status.dangerMuted"
      py={3}
      px={4}
    >
      <Alert.Indicator />
      <Alert.Content>
        <Text fontSize="sm">{message}</Text>
      </Alert.Content>
      {onDismiss && (
        <Button
          variant="ghost"
          w="24px"
          h="24px"
          p="0"
          flexShrink="0"
          color="status.danger"
          aria-label={t("common.close")}
          onClick={onDismiss}
        >
          <X size={14} />
        </Button>
      )}
    </Alert.Root>
  );
}

export function SecretRow({
  secretKey,
  secretValue,
  onEdit,
  onDelete,
  deleteLabel,
}: {
  secretKey: string;
  secretValue: string;
  onEdit: (val: string) => Promise<void>;
  onDelete: () => Promise<void>;
  deleteLabel: string;
}) {
  const { t } = useI18n();
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState<"key" | "value" | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = useState(false);
  const [editValue, setEditValue] = useState(secretValue);
  const deleteTriggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setEditValue(secretValue);
    setCopied(null);
  }, [secretValue]);

  return (
    <Box
      minH="62px"
      display="grid"
      gridTemplateColumns={{
        base: "minmax(0,1fr) auto",
        md: "minmax(160px,.8fr) minmax(220px,1.2fr) auto",
      }}
      alignItems="center"
      gap="3"
      px="4"
      py="3"
      borderBottomWidth="1px"
      borderColor="border.default"
      _last={{ borderBottomWidth: "0" }}
      _hover={{ bg: "bg.muted" }}
    >
      <HStack
        minW="0"
        gap="1"
        gridColumn={{ base: "1", md: "auto" }}
        gridRow={{ base: "1", md: "auto" }}
      >
        <Text flex="1" minW="0" fontFamily="mono" fontSize="sm" fontWeight="bold" truncate>
          {secretKey}
        </Text>
        <Button
          variant="ghost"
          w="30px"
          h="30px"
          p={0}
          flexShrink="0"
          color={copied === "key" ? "status.success" : "fg.muted"}
          aria-label={copied === "key" ? t("dashboard.keyCopied") : t("dashboard.copyKey")}
          title={copied === "key" ? t("dashboard.keyCopied") : t("dashboard.copyKey")}
          onClick={async () => {
            await navigator.clipboard.writeText(secretKey);
            setCopied("key");
          }}
        >
          {copied === "key" ? <Check size={15} /> : <Copy size={15} />}
        </Button>
      </HStack>
      <Input
        aria-label={`${t("dashboard.value")}: ${secretKey}`}
        value={editValue}
        type={visible ? "text" : "password"}
        h="38px"
        gridColumn={{ base: "1 / -1", md: "auto" }}
        gridRow={{ base: "2", md: "auto" }}
        borderColor="border.default"
        borderRadius="md"
        onChange={(e) => setEditValue(e.target.value)}
        onBlur={async (e) => {
          if (e.target.value !== secretValue) await onEdit(e.target.value);
        }}
      />
      <HStack gap="1" gridColumn={{ base: "2", md: "auto" }} gridRow={{ base: "1", md: "auto" }}>
        <Button
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color={copied === "value" ? "status.success" : "fg.muted"}
          aria-label={copied === "value" ? t("dashboard.valueCopied") : t("dashboard.copyValue")}
          title={copied === "value" ? t("dashboard.valueCopied") : t("dashboard.copyValue")}
          onClick={async () => {
            await navigator.clipboard.writeText(editValue);
            setCopied("value");
          }}
        >
          {copied === "value" ? <Check size={16} /> : <Copy size={16} />}
        </Button>
        <Button
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color="fg.muted"
          aria-label={visible ? t("dashboard.hideValue") : t("dashboard.showValue")}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? <EyeOff size={16} /> : <Eye size={16} />}
        </Button>
        <Button
          ref={deleteTriggerRef}
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color="fg.muted"
          aria-label={deleteLabel}
          title={deleteLabel}
          disabled={deleting}
          onClick={() => setDeleteConfirmationOpen(true)}
        >
          <Trash2 size={15} />
        </Button>
      </HStack>
      <ConfirmDeleteDialog
        open={deleteConfirmationOpen}
        title={t("dashboard.deleteSecretConfirm", { key: secretKey })}
        cancelLabel={t("config.cancel")}
        confirmLabel={deleteLabel}
        loading={deleting}
        triggerRef={deleteTriggerRef}
        onClose={() => setDeleteConfirmationOpen(false)}
        onConfirm={async () => {
          setDeleting(true);
          try {
            await onDelete();
            setDeleteConfirmationOpen(false);
          } finally {
            setDeleting(false);
          }
        }}
      />
    </Box>
  );
}

export function RecipientsPanel({
  recipients,
  loading,
  error,
  onSync,
  onErrorDismiss,
}: {
  recipients: Recipient[];
  loading: boolean;
  error: string;
  onSync: () => void | Promise<void>;
  onErrorDismiss: () => void;
}) {
  const { t } = useI18n();

  return (
    <>
      <SectionHeader title={t("recipients.members")}>
        <Button
          size="sm"
          variant="outline"
          loading={loading}
          title={t("dashboard.syncDescription")}
          onClick={() => void onSync()}
        >
          <RefreshCw size={14} />
          {t("dashboard.sync")}
        </Button>
      </SectionHeader>
      {error && (
        <Box mb="4">
          <ErrorAlert message={error} onDismiss={onErrorDismiss} />
        </Box>
      )}
      {loading ? (
        <HStack role="status" py="8" justify="center">
          <Spinner size="sm" aria-hidden="true" />
          <Text color="fg.muted">{t("common.loading")}</Text>
        </HStack>
      ) : recipients.length === 0 ? (
        <Text color="fg.muted" textAlign="center" py="8">
          {t("recipients.empty")}
        </Text>
      ) : (
        <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
          {recipients.map((recipient, index) => (
            <MemberRow
              key={recipient.fingerprint}
              recipient={recipient}
              last={index === recipients.length - 1}
            />
          ))}
        </Box>
      )}
    </>
  );
}

export function MemberRow({ recipient, last = false }: { recipient: Recipient; last?: boolean }) {
  const { t } = useI18n();
  return (
    <styled.button
      type="button"
      w="full"
      minH="64px"
      display="grid"
      gridTemplateColumns="auto minmax(0,1fr) auto"
      alignItems="center"
      gap="3"
      px="4"
      py="3"
      color="fg.default"
      bg="transparent"
      borderBottomWidth={last ? "0" : "1px"}
      borderColor="border.default"
      textAlign="left"
      cursor="pointer"
      _hover={{ bg: "bg.muted" }}
      _focusVisible={{ outline: "2px solid token(colors.accent.default)", outlineOffset: "-2px" }}
      aria-label={`${recipient.username} · GitHub`}
      onClick={() => openURL(`https://github.com/${encodeURIComponent(recipient.username)}`)}
    >
      <MemberAvatar username={recipient.username} />
      <Box minW="0">
        <Text fontWeight="semibold" fontSize="sm">
          {recipient.username}
        </Text>
        <Text fontSize="2xs" color="fg.muted" fontFamily="mono" truncate>
          {recipient.fingerprint}
        </Text>
      </Box>
      <Box
        px="2"
        py="1"
        bg="bg.muted"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="full"
        color="fg.muted"
        fontSize="2xs"
      >
        {t("recipients.member")}
      </Box>
    </styled.button>
  );
}

export function MemberAvatar({ username }: { username: string }) {
  return (
    <Box position="relative" w="38px" h="38px" flexShrink="0">
      <Box
        position="absolute"
        inset="0"
        display="grid"
        placeItems="center"
        color="accent.default"
        bg="accent.subtle"
        borderRadius="full"
        fontSize="2xs"
        fontWeight="extrabold"
      >
        {username.slice(0, 2).toUpperCase()}
      </Box>
      <img
        src={`https://avatars.githubusercontent.com/${encodeURIComponent(username)}?size=76`}
        width={38}
        height={38}
        loading="lazy"
        alt=""
        style={{ position: "absolute", inset: 0, borderRadius: "50%" }}
        onError={(event) => {
          event.currentTarget.style.display = "none";
        }}
      />
    </Box>
  );
}

export type EnbuConfigDraft = {
  version: string;
  default_env: string;
  env: Record<string, { output: string }>;
};

export function parseConfigDraft(content: string, environments: Environment[]): EnbuConfigDraft {
  const parsed = parseToml(content) as Record<string, unknown>;
  const parsedEnv =
    parsed.env && typeof parsed.env === "object" ? (parsed.env as Record<string, unknown>) : {};
  const env: Record<string, { output: string }> = {};
  const names = new Set([...Object.keys(parsedEnv), ...environments.map((item) => item.name)]);
  for (const name of names) {
    const value = parsedEnv[name];
    const output =
      value &&
      typeof value === "object" &&
      typeof (value as { output?: unknown }).output === "string"
        ? String((value as { output: string }).output)
        : name === "default"
          ? ".env"
          : `.env.${name}`;
    env[name] = { output };
  }
  const fallback =
    environments.find((item) => item.current)?.name ?? environments[0]?.name ?? "default";
  return {
    version: typeof parsed.version === "string" ? parsed.version : "v1alpha1",
    default_env: typeof parsed.default_env === "string" ? parsed.default_env : fallback,
    env,
  };
}

export function serializeConfigDraft(config: EnbuConfigDraft): string {
  const header = stringifyToml({
    version: config.version,
    default_env: config.default_env,
  }).trimEnd();
  const environments = Object.entries(config.env)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, environment]) => {
      const key = /^[A-Za-z0-9_-]+$/.test(name) ? name : JSON.stringify(name);
      return `[env.${key}]\n${stringifyToml({ output: environment.output }).trimEnd()}`;
    });
  return [header, ...environments].join("\n\n") + "\n";
}

function ConfigPanel({ environments }: { environments: Environment[] }) {
  const { t } = useI18n();
  const defaultEnvId = useId();
  const [content, setContent] = useState("");
  const [draft, setDraft] = useState("");
  const [gui, setGui] = useState<EnbuConfigDraft>();
  const [view, setView] = useState<"gui" | "code">("gui");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [saveError, setSaveError] = useState("");

  const load = useCallback(async () => {
    try {
      const text = await backend.readConfig();
      setContent(text ?? "");
      setDraft(text ?? "");
      setGui(parseConfigDraft(text ?? "", environments));
      setLoadError("");
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [environments]);

  useEffect(() => {
    void load();
  }, [load]);

  const updateGui = (next: EnbuConfigDraft) => {
    setGui(next);
    setDraft(serializeConfigDraft(next));
    setSaveError("");
  };

  const save = async () => {
    setSaving(true);
    setSaveError("");
    try {
      await backend.writeConfig(draft);
      setContent(draft);
    } catch {
      setSaveError(t("config.saveError"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SectionHeader title={t("config.settings")}>
        <HStack gap="2">
          <Button
            size="sm"
            variant="outline"
            aria-pressed={view === "code"}
            onClick={() => {
              if (view === "code") {
                try {
                  setGui(parseConfigDraft(draft, environments));
                  setView("gui");
                  setSaveError("");
                } catch {
                  setSaveError(t("config.invalidToml"));
                }
              } else setView("code");
            }}
          >
            {view === "code" ? <ListTree size={15} /> : <Code2 size={15} />}
            {view === "code" ? t("config.guiView") : t("config.codeView")}
          </Button>
          {view === "gui" && (
            <Button
              size="sm"
              colorPalette="accent"
              loading={saving}
              disabled={draft === content}
              onClick={() => void save()}
            >
              {t("config.save")}
            </Button>
          )}
        </HStack>
      </SectionHeader>
      {loadError && (
        <Box mb="4">
          <ErrorAlert message={loadError} onDismiss={() => setLoadError("")} />
        </Box>
      )}
      {saveError && (
        <Box mb="4">
          <ErrorAlert message={saveError} onDismiss={() => setSaveError("")} />
        </Box>
      )}
      {loading ? (
        <HStack role="status" py="8" justify="center">
          <Spinner size="sm" aria-hidden="true" />
          <Text color="fg.muted">{t("common.loading")}</Text>
        </HStack>
      ) : view === "code" ? (
        <TomlCodeEditor
          value={draft}
          onChange={setDraft}
          saving={saving}
          onSave={() => void save()}
        />
      ) : gui ? (
        <VStack alignItems="stretch" gap="4">
          <SettingsGroup title={t("config.general")}>
            <SettingRow label={t("config.defaultEnvironment")} htmlFor={defaultEnvId}>
              <styled.select
                id={defaultEnvId}
                value={gui.default_env}
                {...settingControlStyles}
                onChange={(event) => updateGui({ ...gui, default_env: event.target.value })}
              >
                {Object.keys(gui.env).map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </styled.select>
            </SettingRow>
          </SettingsGroup>
          <SettingsGroup title={t("config.outputFileNames")}>
            {Object.entries(gui.env).map(([name, config]) => {
              const inputId = `config-output-${name}`;
              return (
                <SettingRow key={name} label={name} htmlFor={inputId}>
                  <styled.input
                    id={inputId}
                    value={config.output}
                    {...settingControlStyles}
                    onChange={(event) =>
                      updateGui({
                        ...gui,
                        env: { ...gui.env, [name]: { output: event.target.value } },
                      })
                    }
                  />
                </SettingRow>
              );
            })}
          </SettingsGroup>
        </VStack>
      ) : null}
    </>
  );
}

const settingControlStyles = {
  w: "full",
  h: "38px",
  px: "3",
  color: "fg.default",
  bg: "bg.muted",
  borderWidth: "1px",
  borderColor: "border.default",
  borderRadius: "md",
} as const;

function SettingsGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
      <Text
        px="4"
        py="3"
        color="fg.muted"
        bg="bg.muted"
        borderBottomWidth="1px"
        borderColor="border.default"
        fontSize="2xs"
        fontWeight="bold"
        textTransform="uppercase"
        letterSpacing="widest"
      >
        {title}
      </Text>
      {children}
    </Box>
  );
}

function SettingRow({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <Box
      minH="60px"
      display="grid"
      gridTemplateColumns={{ base: "1fr", sm: "minmax(140px,.65fr) minmax(220px,1.35fr)" }}
      alignItems="center"
      gap={{ base: "2", sm: "6" }}
      px="4"
      py="3"
      borderBottomWidth="1px"
      borderColor="border.default"
      _last={{ borderBottomWidth: "0" }}
    >
      {htmlFor ? (
        <styled.label htmlFor={htmlFor} fontSize="sm" fontWeight="semibold">
          {label}
        </styled.label>
      ) : (
        <Text fontSize="sm" fontWeight="semibold">
          {label}
        </Text>
      )}
      {children}
    </Box>
  );
}

function OAuthLoginPanel({
  status,
  expiresIn,
  onCancel,
  onRetry,
}: {
  status: OAuthStatus | null;
  expiresIn: number;
  onCancel: () => Promise<void>;
  onRetry: () => void;
}) {
  const { t } = useI18n();
  const terminal = status?.state && status.state !== "pending";

  return (
    <VStack gap={5} w="full" maxW="480px" alignItems="stretch">
      <Heading as="h1" size="2xl" fontWeight="extrabold" textAlign="center">
        {t("auth.authorizeTitle")}
      </Heading>

      <VStack gap={2} alignItems="center">
        <Text fontSize="sm" color="fg.muted">
          {t("auth.browserInstruction")}
        </Text>
      </VStack>

      {!terminal && status?.state === "pending" && (
        <HStack justifyContent="center">
          <Spinner size="sm" color="accent.default" />
          <Text fontSize="sm">{t("auth.waiting")}</Text>
          <Text fontSize="xs" color="fg.muted">
            {t("auth.expiresIn", { seconds: expiresIn })}
          </Text>
        </HStack>
      )}
      {status?.state === "denied" && <ErrorAlert message={t("auth.denied")} />}
      {status?.state === "expired" && <ErrorAlert message={t("auth.expired")} />}
      {status?.state === "error" && <ErrorAlert message={status.message ?? t("auth.error")} />}

      {/* Actions */}
      <HStack justifyContent="center" flexWrap="wrap">
        {terminal ? (
          <Button
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            h="38px"
            onClick={onRetry}
          >
            {t("auth.tryAgain")}
          </Button>
        ) : (
          <Button variant="ghost" h="38px" color="fg.muted" onClick={onCancel}>
            {t("auth.cancel")}
          </Button>
        )}
      </HStack>
    </VStack>
  );
}
