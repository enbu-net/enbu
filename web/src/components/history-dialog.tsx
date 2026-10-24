import { type RefObject, useEffect, useId, useRef, useState } from "react";
import { History, X } from "lucide-react";
import { Box, Flex, HStack, VStack } from "styled-system/jsx";
import { Button, Heading, Spinner, Text } from "./ui";
import { useFocusTrap } from "../lib/use-focus-trap";
import { useI18n } from "../lib/i18n";
import { formatDisplayError, toDisplayError, type DisplayError } from "../lib/app-error";
import type { DiffResult, HistoryEntry } from "../lib/api";

/**
 * Lists the retained revisions of an environment that changed its secrets,
 * newest first, shows which keys an older revision differs in from the latest
 * (names only, never values), and restores one after a second click. Render it
 * only while open, so a reopened dialog starts from a fresh list.
 */
export function HistoryDialog({
  environment,
  triggerRef,
  listHistory,
  diffHistory,
  restoreHistory,
  onRestored,
  onClose,
}: {
  environment: string;
  triggerRef?: RefObject<HTMLElement | null>;
  listHistory: () => Promise<HistoryEntry[]>;
  diffHistory: (from: number, to: number) => Promise<DiffResult>;
  restoreHistory: (index: number) => Promise<void>;
  onRestored: () => void | Promise<void>;
  onClose: () => void;
}) {
  const { locale, t } = useI18n();
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  useFocusTrap(true, dialogRef, triggerRef);

  useEffect(() => {
    let cancelled = false;
    listHistory()
      .then((list) => {
        if (!cancelled) setEntries([...list].sort((a, b) => b.index - a.index));
      })
      .catch((err) => {
        if (!cancelled) setError(toDisplayError(err));
      });
    return () => {
      cancelled = true;
    };
  }, [listHistory]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [busy, onClose]);

  const latest = entries?.[0]?.index ?? 0;

  // The comparison that answers the latest selection; an earlier one that
  // finishes later must not show its keys under the newer selection.
  const selectionRef = useRef(0);

  async function select(index: number) {
    const request = ++selectionRef.current;
    setSelected(index);
    setDiff(null);
    setConfirming(false);
    setError(null);
    try {
      const result = await diffHistory(index, latest);
      if (request === selectionRef.current) setDiff(result);
    } catch (err) {
      if (request === selectionRef.current) setError(toDisplayError(err));
    }
  }

  async function restore(index: number) {
    setBusy(true);
    setError(null);
    try {
      await restoreHistory(index);
      await onRestored();
      onClose();
    } catch (err) {
      setError(toDisplayError(err));
      setConfirming(false);
    } finally {
      setBusy(false);
    }
  }

  const changed = diff ? diff.added.length + diff.removed.length + diff.modified.length : 0;

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
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <Box
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        w="full"
        maxW="560px"
        maxH="80vh"
        overflowY="auto"
        p="5"
        bg="bg.surface"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="2xl"
        boxShadow="xl"
      >
        <Flex justify="space-between" align="start" gap="4" mb="2">
          <Heading id={titleId} size="lg" fontWeight="extrabold">
            {t("history.title", { environment })}
          </Heading>
          <Button
            type="button"
            variant="ghost"
            w="32px"
            h="32px"
            p="0"
            aria-label={t("common.close")}
            disabled={busy}
            onClick={onClose}
          >
            <X size={16} aria-hidden="true" />
          </Button>
        </Flex>
        <Text fontSize="sm" color="fg.muted" mb="4">
          {t("history.description")}
        </Text>
        {error && (
          <Text role="alert" fontSize="sm" color="status.danger" mb="3">
            {formatDisplayError(error, locale)}
          </Text>
        )}
        {entries === null && !error ? (
          <HStack role="status" py="6" justify="center">
            <Spinner size="sm" aria-hidden="true" />
            <Text color="fg.muted">{t("common.loading")}</Text>
          </HStack>
        ) : entries && entries.length === 0 ? (
          <Text color="fg.muted" textAlign="center" py="6">
            {t("history.empty")}
          </Text>
        ) : (
          <VStack alignItems="stretch" gap="0">
            {entries?.map((entry) => {
              const time = new Date(entry.timestamp);
              const label = Number.isNaN(time.getTime())
                ? `#${entry.index}`
                : `#${entry.index} · ${time.toLocaleString()}`;
              return (
                <Box key={entry.index} py="2" borderBottomWidth="1px" borderColor="border.default">
                  <HStack justify="space-between" gap="2">
                    <HStack gap="2">
                      <History size={14} aria-hidden="true" />
                      <Text fontSize="sm" fontFamily="mono">
                        {label}
                        {entry.index === latest ? ` · ${t("history.latest")}` : ""}
                      </Text>
                    </HStack>
                    {entry.index !== latest && (
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`${t("history.compare")}: #${entry.index}`}
                        onClick={() => void select(entry.index)}
                      >
                        {t("history.compare")}
                      </Button>
                    )}
                  </HStack>
                  {selected === entry.index && diff && (
                    <Box mt="2" pl="6">
                      {changed === 0 ? (
                        <Text fontSize="sm" color="fg.muted">
                          {t("history.same")}
                        </Text>
                      ) : (
                        <VStack alignItems="stretch" gap="1" fontFamily="mono" fontSize="sm">
                          {diff.removed.map((key) => (
                            <Text key={`a-${key}`}>{t("history.onlyThen", { key })}</Text>
                          ))}
                          {diff.added.map((key) => (
                            <Text key={`r-${key}`}>{t("history.onlyNow", { key })}</Text>
                          ))}
                          {diff.modified.map((key) => (
                            <Text key={`m-${key}`}>{t("history.changed", { key })}</Text>
                          ))}
                        </VStack>
                      )}
                      <HStack mt="2" gap="2">
                        {confirming ? (
                          <>
                            <Text fontSize="sm">{t("history.restoreConfirm")}</Text>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => setConfirming(false)}
                            >
                              {t("config.cancel")}
                            </Button>
                            <Button
                              size="sm"
                              colorPalette="accent"
                              loading={busy}
                              onClick={() => void restore(entry.index)}
                            >
                              {t("history.restore")}
                            </Button>
                          </>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={changed === 0}
                            onClick={() => setConfirming(true)}
                          >
                            {t("history.restore")}
                          </Button>
                        )}
                      </HStack>
                    </Box>
                  )}
                </Box>
              );
            })}
          </VStack>
        )}
      </Box>
    </Box>
  );
}
