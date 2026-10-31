import { useRef, useState } from "react";
import { Layers3, Pencil, Trash2 } from "lucide-react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Badge, Button, Input, Text } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { ErrorAlert } from "../../components/error-alert";
import { Notice } from "../../components/notice";
import { SectionHeader } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { Environment } from "../../lib/types";
import type { Workspace } from "../dashboard/use-workspace";
import { EnvironmentNameModal } from "../secrets/environment-selector";
import { m } from "../../paraglide/messages";

/**
 * Renames and deletes environments, and deletes stored revisions, as
 * `enbu switch --move`, `--delete [--purge]` and `--purge-incarnation` do.
 */
export function EnvironmentsTab({ workspace }: { workspace: Workspace }) {
  const [renaming, setRenaming] = useState<Environment | null>(null);
  const [newName, setNewName] = useState("");
  const [deleting, setDeleting] = useState<Environment | null>(null);
  const [purge, setPurge] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  // What the last deletion left behind, and what a purge deleted.
  const [kept, setKept] = useState<{ name: string; incarnation: string } | null>(null);
  const [purged, setPurged] = useState<number | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);

  /** Runs action and shows its failure; resolves whether it succeeded. */
  async function run(action: () => Promise<void>): Promise<boolean> {
    setBusy(true);
    setError(null);
    try {
      await action();
      return true;
    } catch (err) {
      setError(toDisplayError(err));
      return false;
    } finally {
      setBusy(false);
    }
  }

  function purgeIncarnation(incarnation: string) {
    return run(async () => {
      setPurged(await backend.purgeIncarnation(incarnation));
      setKept(null);
    });
  }

  return (
    <>
      <SectionHeader title={m.dashboard_environments()} />
      {error && (
        <Box mb="4">
          <ErrorAlert error={error} onDismiss={() => setError(null)} />
        </Box>
      )}
      {kept && (
        <Notice onDismiss={() => setKept(null)}>
          <Text fontSize="sm">{m.environments_kept({ name: kept.name })}</Text>
          <Button
            size="sm"
            variant="outline"
            loading={busy}
            onClick={() => void purgeIncarnation(kept.incarnation)}
          >
            {m.environments_purgeKept()}
          </Button>
        </Notice>
      )}
      {purged !== null && (
        <Notice onDismiss={() => setPurged(null)}>
          <Text fontSize="sm">{m.environments_purged({ count: String(purged) })}</Text>
        </Notice>
      )}
      <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
        {workspace.environments.map((environment) => (
          <HStack
            key={environment.name}
            justify="space-between"
            gap="3"
            px="4"
            py="3"
            borderBottomWidth="1px"
            borderColor="border.default"
            _last={{ borderBottomWidth: "0" }}
          >
            <HStack gap="2" minW="0">
              <Layers3 size={15} aria-hidden="true" />
              <Text fontWeight="semibold" truncate>
                {environment.name}
              </Text>
              {environment.current && <Badge size="sm">{m.environments_current()}</Badge>}
            </HStack>
            <HStack gap="1">
              <Button
                size="sm"
                variant="ghost"
                aria-label={`${m.environments_rename()}: ${environment.name}`}
                onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setNewName(environment.name);
                  setRenaming(environment);
                }}
              >
                <Pencil size={14} aria-hidden="true" />
                {m.environments_rename()}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                color="status.danger"
                disabled={environment.current}
                title={environment.current ? m.environments_currentCannotBeDeleted() : undefined}
                aria-label={`${m.environments_delete()}: ${environment.name}`}
                onClick={(event) => {
                  triggerRef.current = event.currentTarget;
                  setPurge(false);
                  setDeleting(environment);
                }}
              >
                <Trash2 size={14} aria-hidden="true" />
                {m.environments_delete()}
              </Button>
            </HStack>
          </HStack>
        ))}
      </Box>
      <PurgeEarlier busy={busy} onPurge={purgeIncarnation} />
      <EnvironmentNameModal
        open={renaming !== null}
        title={m.environments_renameTitle({ name: renaming?.name ?? "" })}
        confirmLabel={m.environments_rename()}
        value={newName}
        loading={busy}
        triggerRef={triggerRef}
        onValueChange={setNewName}
        onClose={() => setRenaming(null)}
        onCreate={async () => {
          const from = renaming?.name ?? "";
          const to = newName.trim();
          await run(async () => {
            if (to !== from) {
              await backend.renameEnvironment(from, to);
              await workspace.refresh();
            }
          });
          setRenaming(null);
        }}
      />
      <ConfirmDeleteDialog
        open={deleting !== null}
        title={m.environments_deleteTitle({ name: deleting?.name ?? "" })}
        description={m.environments_deleteDescription()}
        cancelLabel={m.config_cancel()}
        confirmLabel={m.environments_delete()}
        loading={busy}
        triggerRef={triggerRef}
        onClose={() => setDeleting(null)}
        onConfirm={async () => {
          const name = deleting?.name ?? "";
          await run(async () => {
            const result = await backend.deleteEnvironment(name, purge);
            setKept(result.incarnation ? { name, incarnation: result.incarnation } : null);
            setPurged(purge ? result.purged : null);
            await workspace.refresh();
          });
          setDeleting(null);
        }}
      >
        <HStack mt="4" gap="2" alignItems="start">
          <input
            id="purge-environment"
            type="checkbox"
            checked={purge}
            disabled={busy}
            onChange={(event) => setPurge(event.target.checked)}
          />
          <styled.label htmlFor="purge-environment" fontSize="sm">
            {m.environments_purge()}
          </styled.label>
        </HStack>
      </ConfirmDeleteDialog>
    </>
  );
}

function PurgeEarlier({
  busy,
  onPurge,
}: {
  busy: boolean;
  /** Resolves true when the revisions were deleted, so the field clears. */
  onPurge: (incarnation: string) => Promise<boolean>;
}) {
  const [incarnation, setIncarnation] = useState("");
  return (
    <VStack mt="6" alignItems="stretch" gap="2">
      <Text fontWeight="semibold">{m.environments_purgeEarlierTitle()}</Text>
      <Text fontSize="sm" color="fg.muted">
        {m.environments_purgeEarlierDescription()}
      </Text>
      <styled.form
        display="flex"
        gap="2"
        onSubmit={(event) => {
          event.preventDefault();
          void onPurge(incarnation.trim()).then((done) => done && setIncarnation(""));
        }}
      >
        <Input
          aria-label={m.environments_incarnation()}
          placeholder={m.environments_incarnation()}
          autoComplete="off"
          spellCheck={false}
          value={incarnation}
          onChange={(event) => setIncarnation(event.target.value)}
        />
        <Button
          type="submit"
          variant="outline"
          color="status.danger"
          flexShrink={0}
          loading={busy}
          disabled={!incarnation.trim()}
        >
          {m.environments_purgeEarlier()}
        </Button>
      </styled.form>
    </VStack>
  );
}
