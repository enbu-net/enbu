import { useCallback, useEffect, useId, useRef, useState } from "react";
import { History, RotateCcw } from "lucide-react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Badge, Button, Spinner, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { Notice } from "../../components/notice";
import { SectionHeader } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import type { Diff, HistoryEntry } from "../../lib/types";
import type { Workspace } from "../dashboard/use-workspace";

/**
 * The revisions that changed an environment's secrets, with the comparison
 * and restore of `enbu history diff` and `enbu history restore`.
 */
export function HistoryTab({ workspace }: { workspace: Workspace }) {
  const { t, locale } = useI18n();
  const envId = useId();
  const fromId = useId();
  const toId = useId();
  // The environment picked here, or until then the current one.
  const [picked, setPicked] = useState("");
  const env = picked || workspace.currentEnvironment;
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [from, setFrom] = useState(0);
  const [to, setTo] = useState(0);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [busy, setBusy] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);
  const [error, setError] = useState<DisplayError | null>(null);
  const request = useRef(0);

  const load = useCallback(async (name: string) => {
    // A newer load, for example after picking another environment, wins.
    const id = ++request.current;
    setError(null);
    setDiff(null);
    // Drop the previous list, so its indexes cannot be restored in another environment.
    setEntries(null);
    try {
      const list = await backend.listHistory(name);
      if (id !== request.current) return;
      setEntries(list);
      setTo(list.length);
      setFrom(Math.max(1, list.length - 1));
    } catch (err) {
      if (id === request.current) setError(toDisplayError(err));
    }
  }, []);

  useEffect(() => {
    if (env) void load(env);
  }, [env, load]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setBusy(false);
    }
  }

  const newestFirst = [...(entries ?? [])].reverse();
  const formatTime = (timestamp: string) =>
    new Date(timestamp).toLocaleString(locale === "ja" ? "ja-JP" : "en-US");

  return (
    <>
      <SectionHeader title={t("history.title")}>
        <HStack gap="2">
          <styled.label htmlFor={envId} fontSize="sm" color="fg.muted">
            {t("history.environment")}
          </styled.label>
          <styled.select
            id={envId}
            value={env}
            {...selectStyles}
            onChange={(event) => {
              setRestored(null);
              setPicked(event.target.value);
            }}
          >
            {workspace.environments.map((environment) => (
              <option key={environment.name} value={environment.name}>
                {environment.name}
              </option>
            ))}
          </styled.select>
        </HStack>
      </SectionHeader>
      {error && (
        <Box mb="4">
          <ErrorAlert error={error} onDismiss={() => setError(null)} />
        </Box>
      )}
      {restored !== null && (
        <Notice onDismiss={() => setRestored(null)}>
          {t("history.restored", { index: String(restored) })}
        </Notice>
      )}
      {entries === null ? (
        !error && (
          <HStack role="status" py="8" justify="center">
            <Spinner size="sm" aria-hidden="true" />
            <Text color="fg.muted">{t("common.loading")}</Text>
          </HStack>
        )
      ) : entries.length === 0 ? (
        <Text color="fg.muted" textAlign="center" py="8">
          {t("history.empty")}
        </Text>
      ) : (
        <VStack alignItems="stretch" gap="5">
          <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
            {newestFirst.map((entry) => {
              const latest = entry.index === entries.length;
              return (
                <HStack
                  key={entry.tag}
                  justify="space-between"
                  gap="3"
                  px="4"
                  py="3"
                  borderBottomWidth="1px"
                  borderColor="border.default"
                  _last={{ borderBottomWidth: "0" }}
                >
                  <HStack gap="2" minW="0">
                    <History size={15} aria-hidden="true" />
                    <Text fontWeight="semibold">
                      {t("history.revision", { index: String(entry.index) })}
                    </Text>
                    <Text fontSize="sm" color="fg.muted">
                      {formatTime(entry.timestamp)}
                    </Text>
                    {latest && <Badge size="sm">{t("history.latest")}</Badge>}
                  </HStack>
                  {!latest && (
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy}
                      aria-label={`${t("history.restore")}: ${t("history.revision", { index: String(entry.index) })}`}
                      onClick={() =>
                        void run(async () => {
                          await backend.restoreHistory(env, entry.index);
                          setRestored(entry.index);
                          await Promise.all([load(env), workspace.refresh()]);
                        })
                      }
                    >
                      <RotateCcw size={14} aria-hidden="true" />
                      {t("history.restore")}
                    </Button>
                  )}
                </HStack>
              );
            })}
          </Box>
          {entries.length > 1 && (
            <VStack alignItems="stretch" gap="3">
              <HStack gap="2" flexWrap="wrap">
                <styled.label htmlFor={fromId} fontSize="sm" color="fg.muted">
                  {t("history.from")}
                </styled.label>
                <RevisionSelect id={fromId} entries={newestFirst} value={from} onChange={setFrom} />
                <styled.label htmlFor={toId} fontSize="sm" color="fg.muted">
                  {t("history.to")}
                </styled.label>
                <RevisionSelect id={toId} entries={newestFirst} value={to} onChange={setTo} />
                <Button
                  size="sm"
                  variant="outline"
                  loading={busy}
                  onClick={() =>
                    void run(async () => setDiff(await backend.diffHistory(env, from, to)))
                  }
                >
                  {t("history.compare")}
                </Button>
              </HStack>
              {diff && <DiffView diff={diff} />}
            </VStack>
          )}
        </VStack>
      )}
    </>
  );
}

function RevisionSelect({
  id,
  entries,
  value,
  onChange,
}: {
  id: string;
  entries: HistoryEntry[];
  value: number;
  onChange: (index: number) => void;
}) {
  const { t } = useI18n();
  return (
    <styled.select
      id={id}
      value={value}
      {...selectStyles}
      onChange={(event) => onChange(Number(event.target.value))}
    >
      {entries.map((entry) => (
        <option key={entry.tag} value={entry.index}>
          {t("history.revision", { index: String(entry.index) })}
        </option>
      ))}
    </styled.select>
  );
}

function DiffView({ diff }: { diff: Diff }) {
  const { t } = useI18n();
  const groups = [
    { sign: "+", label: t("history.added"), keys: diff.added, color: "status.success" },
    { sign: "-", label: t("history.removed"), keys: diff.removed, color: "status.danger" },
    { sign: "~", label: t("history.modified"), keys: diff.modified, color: "fg.default" },
  ].filter((group) => group.keys.length > 0);
  if (groups.length === 0) {
    return <Text color="fg.muted">{t("history.noDifferences")}</Text>;
  }
  return (
    <VStack
      alignItems="stretch"
      gap="1"
      p="3"
      bg="bg.muted"
      borderRadius="lg"
      fontFamily="mono"
      fontSize="sm"
    >
      {groups.flatMap((group) =>
        group.keys.map((key) => (
          <Text key={`${group.sign}${key}`} color={group.color} title={group.label}>
            {group.sign} {key}
          </Text>
        )),
      )}
    </VStack>
  );
}

const selectStyles = {
  h: "32px",
  px: "2",
  color: "fg.default",
  bg: "bg.muted",
  borderWidth: "1px",
  borderColor: "border.default",
  borderRadius: "md",
  fontSize: "sm",
} as const;
