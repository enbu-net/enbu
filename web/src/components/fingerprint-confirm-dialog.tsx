import { type RefObject, useEffect, useId, useState } from "react";
import { Box, HStack } from "styled-system/jsx";
import { hstack } from "styled-system/patterns";
import { UserCheck } from "lucide-react";
import { Button, Heading, Text } from "./ui";
import { ModalDialog } from "./modal-dialog";

/**
 * Asks an admin to compare a device's fingerprint with the one shown on that
 * device before trusting it. Approving needs an explicit acknowledgement, so a
 * stray Enter cannot grant access to every secret.
 */
export function FingerprintConfirmDialog({
  open,
  title,
  fingerprint,
  warning,
  acknowledgeLabel,
  cancelLabel,
  confirmLabel,
  loading,
  triggerRef,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  fingerprint: string;
  warning: string;
  acknowledgeLabel: string;
  cancelLabel: string;
  confirmLabel: string;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
}) {
  const titleId = useId();
  const warningId = useId();
  const [acknowledged, setAcknowledged] = useState(false);

  useEffect(() => {
    if (!open) setAcknowledged(false);
  }, [open]);

  if (!open) return null;
  return (
    <ModalDialog
      labelledBy={titleId}
      describedBy={warningId}
      dismissible={!loading}
      returnFocusRef={triggerRef}
      wide
      onClose={onClose}
    >
      <Heading id={titleId} size="lg" fontWeight="extrabold">
        {title}
      </Heading>
      <Box
        mt="4"
        p="4"
        bg="bg.muted"
        borderRadius="lg"
        fontFamily="mono"
        fontSize="lg"
        textAlign="center"
        letterSpacing="wider"
        data-testid="fingerprint"
      >
        {fingerprint}
      </Box>
      <Text id={warningId} mt="3" fontSize="sm" color="fg.muted">
        {warning}
      </Text>
      <label className={hstack({ mt: "4", gap: "2", alignItems: "start", fontSize: "sm" })}>
        <input
          type="checkbox"
          checked={acknowledged}
          disabled={loading}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        {acknowledgeLabel}
      </label>
      <HStack justify="end" gap="2" mt="6">
        <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
          {cancelLabel}
        </Button>
        <Button
          type="button"
          bg="accent.default"
          color="accent.fg"
          loading={loading}
          disabled={!acknowledged}
          onClick={() => void onConfirm()}
        >
          <UserCheck size={15} aria-hidden="true" />
          {confirmLabel}
        </Button>
      </HStack>
    </ModalDialog>
  );
}
