import { useId, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { Box, HStack, VStack } from "styled-system/jsx";
import { Button, Heading, Text } from "./ui";
import { useI18n } from "../lib/i18n";
import type { ConflictChoice, ConflictSet } from "../lib/types";

/**
 * ConflictPanel asks for one value per secret that concurrent edits changed
 * differently. Nothing is preselected: a value is published only once a person
 * has chosen it for every key.
 */
export function ConflictPanel({
  set,
  loading,
  onResolve,
}: {
  set: ConflictSet;
  loading: boolean;
  onResolve: (choices: ConflictChoice[]) => void | Promise<void>;
}) {
  const { t } = useI18n();
  const name = useId();
  // The index of the chosen candidate for each key.
  const [picked, setPicked] = useState<Record<string, number>>({});
  const decided = set.conflicts.every((c) => picked[c.key] !== undefined);

  return (
    <Box
      role="region"
      aria-labelledby={`${name}-title`}
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="xl"
      p="4"
    >
      <HStack gap="2" mb="2">
        <AlertTriangle size={16} aria-hidden="true" />
        <Heading as="h3" id={`${name}-title`} size="md">
          {t("conflicts.title")}
        </Heading>
      </HStack>
      <Text color="fg.muted" mb="4">
        {t("conflicts.description")}
      </Text>
      <VStack alignItems="stretch" gap="4">
        {set.conflicts.map((conflict) => (
          <Box as="fieldset" key={conflict.key} data-conflict-key={conflict.key}>
            <Box as="legend" fontFamily="mono" fontWeight="semibold" mb="2">
              {conflict.key}
            </Box>
            <VStack alignItems="stretch" gap="1">
              {conflict.candidates.map((candidate, index) => (
                <HStack as="label" key={index} gap="2" cursor="pointer">
                  <input
                    type="radio"
                    name={`${name}-${conflict.key}`}
                    checked={picked[conflict.key] === index}
                    disabled={loading}
                    aria-label={t("conflicts.candidate", { number: String(index + 1) })}
                    onChange={() => setPicked((current) => ({ ...current, [conflict.key]: index }))}
                  />
                  <Text fontFamily="mono" wordBreak="break-all">
                    {candidate.deleted ? t("conflicts.deleted") : candidate.value}
                  </Text>
                </HStack>
              ))}
            </VStack>
          </Box>
        ))}
      </VStack>
      <HStack justify="flex-end" gap="3" mt="4">
        {!decided && (
          <Text color="fg.muted" fontSize="sm">
            {t("conflicts.undecided")}
          </Text>
        )}
        <Button
          colorPalette="accent"
          loading={loading}
          disabled={!decided}
          onClick={() =>
            onResolve(
              set.conflicts.map((conflict) => {
                const candidate = conflict.candidates[picked[conflict.key] ?? 0];
                return {
                  key: conflict.key,
                  value: candidate?.deleted ? "" : (candidate?.value ?? ""),
                  delete: candidate?.deleted ?? false,
                };
              }),
            )
          }
        >
          {t("conflicts.resolve")}
        </Button>
      </HStack>
    </Box>
  );
}
