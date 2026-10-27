import { useRef, useState } from "react";
import { Download, Plus, X } from "lucide-react";
import { Box, HStack, styled } from "styled-system/jsx";
import { Alert, Button, Input, Spinner, Text } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { ConflictPanel } from "../../components/conflict-panel";
import { SectionHeader } from "../../components/layout";
import { displayError, toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import type { PullResult } from "../../lib/types";
import type { RunTransfer } from "../dashboard/use-transfer";
import type { Workspace } from "../dashboard/use-workspace";
import { CreateEnvironmentModal, EnvironmentSelector } from "./environment-selector";
import { SecretRow } from "./secret-row";

export function SecretsTab({
  workspace,
  transfer,
}: {
  workspace: Workspace;
  transfer: RunTransfer;
}) {
  const { t } = useI18n();
  const { currentEnvironment: env, secrets, conflicts, refresh, setError } = workspace;
  const [pullLoading, setPullLoading] = useState(false);
  const [pullNotice, setPullNotice] = useState<PullResult | null>(null);
  const [replaceFile, setReplaceFile] = useState<string | null>(null);
  const [resolveLoading, setResolveLoading] = useState(false);
  const addEnvironmentTriggerRef = useRef<HTMLButtonElement>(null);
  const [environmentModalOpen, setEnvironmentModalOpen] = useState(false);
  const [newEnv, setNewEnv] = useState("");
  const [environmentCreateLoading, setEnvironmentCreateLoading] = useState(false);

  const report = (err: unknown) => setError(toDisplayError(err));

  // A pull refuses to overwrite an output file it cannot read; the person
  // confirms, and the pull runs again replacing the file.
  async function pull(replace: boolean) {
    setPullLoading(true);
    try {
      await transfer("pull", async () => {
        const result = await backend.pullSecrets(env, replace);
        setPullNotice(result.kept.length > 0 || result.removed.length > 0 ? result : null);
        await refresh(env);
      });
      setReplaceFile(null);
    } catch (err) {
      const display = toDisplayError(err);
      if (display.code === "output_unreadable" && !replace) {
        setReplaceFile(display.params.file ?? "");
      } else {
        setReplaceFile(null);
        setError(display);
      }
    } finally {
      setPullLoading(false);
    }
  }

  async function createEnvironment() {
    const created = newEnv.trim();
    if (!created) return;
    setEnvironmentCreateLoading(true);
    setError(null);
    try {
      await backend.createEnvironment(created);
      await backend.switchEnvironment(created);
      await refresh(created);
      setEnvironmentModalOpen(false);
      setNewEnv("");
    } catch (err) {
      report(err);
    } finally {
      setEnvironmentCreateLoading(false);
    }
  }

  return (
    <>
      <SectionHeader
        title={
          <EnvironmentSelector
            environments={workspace.environments}
            value={env}
            addTriggerRef={addEnvironmentTriggerRef}
            onSelect={async (environment) => {
              if (environment === env) return;
              try {
                await backend.switchEnvironment(environment);
                await refresh(environment);
              } catch (err) {
                report(err);
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
            title={t("dashboard.pullDescription")}
            onClick={() => void pull(false)}
          >
            <Download size={14} />
            {t("dashboard.pull")}
          </Button>
        </HStack>
      </SectionHeader>
      {pullNotice && <PullNotice result={pullNotice} onDismiss={() => setPullNotice(null)} />}
      <ConfirmDeleteDialog
        open={replaceFile !== null}
        title={t("dashboard.pullReplaceTitle", { file: replaceFile ?? "" })}
        description={t("dashboard.pullReplaceDescription")}
        cancelLabel={t("config.cancel")}
        confirmLabel={t("dashboard.pullReplace")}
        loading={pullLoading}
        onClose={() => setReplaceFile(null)}
        onConfirm={() => pull(true)}
      />
      {workspace.loading ? (
        <HStack role="status" py="8" justify="center">
          <Spinner size="sm" aria-hidden="true" />
          <Text color="fg.muted">{t("common.loading")}</Text>
        </HStack>
      ) : conflicts && conflicts.conflicts.length > 0 ? (
        <ConflictPanel
          key={conflicts.heads.join()}
          set={conflicts}
          loading={resolveLoading}
          onResolve={async (choices) => {
            setResolveLoading(true);
            let failure: DisplayError | null = null;
            try {
              await backend.resolveConflicts(env, conflicts.heads, choices);
            } catch (err) {
              failure = toDisplayError(err);
            } finally {
              setResolveLoading(false);
            }
            // If someone wrote meanwhile, this shows the values they added.
            await refresh(env);
            if (failure) setError(failure);
          }}
        />
      ) : (
        <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
          {secrets?.secrets.map((secret) => (
            <SecretRow
              key={secret.key}
              secretKey={secret.key}
              secretValue={secret.value}
              onEdit={async (value) => {
                try {
                  await backend.editSecret(secret.key, value, env);
                  await refresh(env);
                } catch (err) {
                  report(err);
                }
              }}
              onDelete={async () => {
                try {
                  await transfer("delete", async () => {
                    await backend.deleteSecret(secret.key, env);
                    await refresh(env);
                  });
                } catch (err) {
                  report(err);
                }
              }}
              deleteLabel={t("dashboard.delete")}
            />
          ))}
          {(secrets?.secrets.length ?? 0) === 0 && (
            <Text color="fg.muted" textAlign="center" py="8">
              {t("dashboard.empty")}
            </Text>
          )}
        </Box>
      )}
      <AddSecretForm
        existingKeys={secrets?.secrets.map((secret) => secret.key) ?? []}
        onDuplicate={(key) => setError(displayError("secret_already_exists", { key }))}
        onAdd={async (key, value) => {
          try {
            await transfer("add", async () => {
              await backend.addSecret(key, value, env);
              await refresh(env);
            });
            return true;
          } catch (err) {
            report(err);
            return false;
          }
        }}
      />
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
        onCreate={createEnvironment}
      />
    </>
  );
}

function PullNotice({ result, onDismiss }: { result: PullResult; onDismiss: () => void }) {
  const { t } = useI18n();
  return (
    <Alert.Root role="status" borderRadius="md" borderWidth="1px" py={3} px={4} mb="4">
      <Alert.Content>
        {result.removed.length > 0 && (
          <Text fontSize="sm">
            {t("dashboard.pullRemoved", { keys: result.removed.join(", ") })}
          </Text>
        )}
        {result.kept.length > 0 && (
          <Text fontSize="sm">{t("dashboard.pullKept", { keys: result.kept.join(", ") })}</Text>
        )}
      </Alert.Content>
      <Button
        variant="ghost"
        w="24px"
        h="24px"
        p="0"
        flexShrink="0"
        aria-label={t("common.close")}
        onClick={onDismiss}
      >
        <X size={14} />
      </Button>
    </Alert.Root>
  );
}

/** Adds a secret; Enter in either field submits. */
function AddSecretForm({
  existingKeys,
  onDuplicate,
  onAdd,
}: {
  existingKeys: string[];
  onDuplicate: (key: string) => void;
  /** Resolves true when the secret was added, so the form clears. */
  onAdd: (key: string, value: string) => Promise<boolean>;
}) {
  const { t } = useI18n();
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    const trimmedKey = key.trim();
    if (!trimmedKey || loading) return;
    if (existingKeys.includes(trimmedKey)) {
      onDuplicate(trimmedKey);
      return;
    }
    setLoading(true);
    try {
      if (await onAdd(trimmedKey, value)) {
        setKey("");
        setValue("");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <styled.form
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
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Input
        aria-label={t("dashboard.key")}
        placeholder={t("dashboard.key")}
        autoComplete="off"
        spellCheck={false}
        value={key}
        onChange={(event) => setKey(event.target.value)}
      />
      <Input
        aria-label={t("dashboard.value")}
        placeholder={t("dashboard.value")}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
      <Button type="submit" colorPalette="accent" loading={loading} disabled={!key.trim()}>
        <Plus size={15} />
        {t("dashboard.add")}
      </Button>
    </styled.form>
  );
}
