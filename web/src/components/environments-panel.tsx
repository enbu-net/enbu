import { useId, useRef, useState } from "react";
import { Pencil, Trash2 } from "lucide-react";
import { Box, HStack, VStack } from "styled-system/jsx";
import { Alert, Button, Heading, Input, Text } from "./ui";
import { ConfirmDialog } from "./confirm-dialog";
import { useI18n } from "../lib/i18n";
import { toDisplayError, type DisplayError } from "../lib/app-error";
import type { Environment } from "../lib/api";

/**
 * Renames and deletes environments. Deleting can also delete the stored
 * revisions, and an admin can delete the revisions of an environment deleted
 * earlier by its incarnation; both are admin-only and cannot be undone.
 */
export function EnvironmentsPanel({
  environments,
  admin,
  onRename,
  onDelete,
  onPurgeIncarnation,
  onError,
}: {
  environments: Environment[];
  /** Whether this device is a workspace admin, which purging needs. */
  admin: boolean;
  onRename: (name: string, newName: string) => Promise<void>;
  /** Returns how many stored revisions were deleted when purge is set. */
  onDelete: (name: string, purge: boolean) => Promise<number>;
  onPurgeIncarnation: (incarnation: string) => Promise<number>;
  onError: (error: DisplayError) => void;
}) {
  const { t } = useI18n();
  const renameId = useId();
  const incarnationId = useId();
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [purge, setPurge] = useState(false);
  const [incarnation, setIncarnation] = useState("");
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const triggerRef = useRef<HTMLElement | null>(null);

  async function run(action: () => Promise<void>, close: () => void) {
    setBusy(true);
    setNotice("");
    try {
      await action();
    } catch (err) {
      onError(toDisplayError(err));
    } finally {
      close();
      setBusy(false);
    }
  }

  return (
    <VStack alignItems="stretch" gap="4">
      {notice && (
        <Alert.Root role="status">
          <Alert.Content>
            <Alert.Description>{notice}</Alert.Description>
          </Alert.Content>
        </Alert.Root>
      )}
      <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
        {environments.map((env, index) => (
          <HStack
            key={env.name}
            justify="space-between"
            gap="3"
            px="4"
            py="3"
            borderBottomWidth={index === environments.length - 1 ? "0" : "1px"}
            borderColor="border.default"
          >
            <Text fontWeight="semibold" fontSize="sm">
              {env.name}
              {env.current ? ` · ${t("dashboard.current")}` : ""}
            </Text>
            <HStack gap="1">
              <Button
                size="sm"
                variant="ghost"
                aria-label={`${t("environments.rename")}: ${env.name}`}
                onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setNewName(env.name);
                  setRenaming(env.name);
                }}
              >
                <Pencil size={14} aria-hidden="true" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={env.current}
                title={env.current ? t("environments.deleteCurrent") : undefined}
                aria-label={`${t("dashboard.delete")}: ${env.name}`}
                onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setPurge(false);
                  setDeleting(env.name);
                }}
              >
                <Trash2 size={14} aria-hidden="true" />
              </Button>
            </HStack>
          </HStack>
        ))}
      </Box>

      {admin && (
        <Box borderWidth="1px" borderColor="border.default" borderRadius="xl" p="4">
          <Heading as="h4" size="sm" fontWeight="bold" mb="1">
            {t("environments.purgeTitle")}
          </Heading>
          <Text fontSize="sm" color="fg.muted" mb="3">
            {t("environments.purgeHint")}
          </Text>
          <HStack gap="2" alignItems="end">
            <VStack alignItems="stretch" gap="1" flex="1">
              <label htmlFor={incarnationId}>
                <Text as="span" fontSize="sm" fontWeight="semibold">
                  {t("environments.incarnation")}
                </Text>
              </label>
              <Input
                id={incarnationId}
                value={incarnation}
                fontFamily="mono"
                placeholder="00000000-0000-0000-0000-000000000000"
                onChange={(event) => setIncarnation(event.target.value)}
              />
            </VStack>
            <Button
              variant="outline"
              disabled={!incarnation.trim()}
              onClick={(event) => {
                triggerRef.current = event.currentTarget;
                setConfirmPurge(true);
              }}
            >
              {t("environments.purge")}
            </Button>
          </HStack>
        </Box>
      )}

      <ConfirmDialog
        open={renaming !== null}
        title={t("environments.renameTitle", { name: renaming ?? "" })}
        cancelLabel={t("config.cancel")}
        confirmLabel={t("environments.rename")}
        disabled={!newName.trim() || newName.trim() === renaming}
        loading={busy}
        triggerRef={triggerRef}
        onClose={() => setRenaming(null)}
        onConfirm={() => {
          const from = renaming;
          const to = newName.trim();
          if (!from || !to) return;
          return run(
            () => onRename(from, to),
            () => setRenaming(null),
          );
        }}
      >
        <label htmlFor={renameId}>
          <Text as="span" fontSize="sm" fontWeight="semibold">
            {t("dashboard.environmentName")}
          </Text>
        </label>
        <Input
          id={renameId}
          mt="1"
          autoFocus
          value={newName}
          disabled={busy}
          onChange={(event) => setNewName(event.target.value)}
        />
      </ConfirmDialog>

      <ConfirmDialog
        open={deleting !== null}
        title={t("environments.deleteTitle", { name: deleting ?? "" })}
        description={t("environments.deleteHint")}
        cancelLabel={t("config.cancel")}
        confirmLabel={t("dashboard.delete")}
        danger
        loading={busy}
        triggerRef={triggerRef}
        onClose={() => setDeleting(null)}
        onConfirm={() => {
          const target = deleting;
          if (!target) return;
          return run(
            async () => {
              const purged = await onDelete(target, purge);
              const incarnation = environments.find((e) => e.name === target)?.incarnation;
              if (purge) setNotice(t("environments.purged", { count: String(purged) }));
              else if (incarnation) setNotice(t("environments.revisionsKept", { incarnation }));
            },
            () => setDeleting(null),
          );
        }}
      >
        {admin && (
          <HStack as="label" gap="2" alignItems="start" cursor="pointer">
            <input
              type="checkbox"
              checked={purge}
              disabled={busy}
              onChange={(event) => setPurge(event.target.checked)}
            />
            <Text fontSize="sm">{t("environments.deleteRevisions")}</Text>
          </HStack>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmPurge}
        title={t("environments.purgeConfirm")}
        description={t("environments.purgeConfirmHint", { incarnation: incarnation.trim() })}
        cancelLabel={t("config.cancel")}
        confirmLabel={t("environments.purge")}
        danger
        loading={busy}
        triggerRef={triggerRef}
        onClose={() => setConfirmPurge(false)}
        onConfirm={() =>
          run(
            async () => {
              const purged = await onPurgeIncarnation(incarnation.trim());
              setIncarnation("");
              setNotice(t("environments.purged", { count: String(purged) }));
            },
            () => setConfirmPurge(false),
          )
        }
      />
    </VStack>
  );
}
