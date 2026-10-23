import { type RefObject, useId, useState } from "react";
import { HStack, VStack, styled } from "styled-system/jsx";
import { Text } from "./ui";
import { ConfirmDialog } from "./confirm-dialog";
import { useI18n } from "../lib/i18n";

/**
 * Collects a dotenv file to import into the current environment, by choosing
 * a file or pasting its contents. Nothing is read until a file is chosen, and
 * the contents leave this dialog only through onImport. Render it only while
 * open, so what was pasted does not linger in state after it closes.
 */
export function ImportDialog({
  open,
  environment,
  loading,
  triggerRef,
  onClose,
  onImport,
}: {
  open: boolean;
  environment: string;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  onClose: () => void;
  onImport: (dotenv: string, overwrite: boolean) => void | Promise<void>;
}) {
  const { t } = useI18n();
  const contentId = useId();
  const fileId = useId();
  const [content, setContent] = useState("");
  const [overwrite, setOverwrite] = useState(false);

  return (
    <ConfirmDialog
      open={open}
      title={t("import.title", { environment })}
      description={t("import.description")}
      cancelLabel={t("config.cancel")}
      confirmLabel={t("import.action")}
      disabled={!content.trim()}
      loading={loading}
      triggerRef={triggerRef}
      onClose={onClose}
      onConfirm={() => onImport(content, overwrite)}
    >
      <VStack alignItems="stretch" gap="3">
        <VStack alignItems="stretch" gap="1">
          <styled.label htmlFor={fileId} fontSize="sm" fontWeight="semibold">
            {t("import.file")}
          </styled.label>
          <styled.input
            id={fileId}
            type="file"
            fontSize="sm"
            disabled={loading}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (file) setContent(await file.text());
            }}
          />
        </VStack>
        <VStack alignItems="stretch" gap="1">
          <styled.label htmlFor={contentId} fontSize="sm" fontWeight="semibold">
            {t("import.content")}
          </styled.label>
          <styled.textarea
            id={contentId}
            value={content}
            rows={8}
            spellCheck={false}
            autoComplete="off"
            placeholder={"API_KEY=...\nDATABASE_URL=..."}
            disabled={loading}
            fontFamily="mono"
            fontSize="sm"
            p="2"
            color="fg.default"
            bg="bg.muted"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="md"
            onChange={(event) => setContent(event.target.value)}
          />
        </VStack>
        <HStack as="label" gap="2" alignItems="start" cursor="pointer">
          <input
            type="checkbox"
            checked={overwrite}
            disabled={loading}
            onChange={(event) => setOverwrite(event.target.checked)}
          />
          <Text fontSize="sm">{t("import.overwrite")}</Text>
        </HStack>
      </VStack>
    </ConfirmDialog>
  );
}
