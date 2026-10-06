import { type RefObject, useEffect, useId, useRef, useState } from "react";
import { Box, HStack } from "styled-system/jsx";
import { UserCheck } from "lucide-react";
import { Button, Heading, Text } from "./ui";
import { useFocusTrap } from "../lib/use-focus-trap";

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
  const dialogRef = useRef<HTMLDivElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  useFocusTrap(open, dialogRef, triggerRef);

  useEffect(() => {
    if (!open) setAcknowledged(false);
  }, [open]);

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
      zIndex="60"
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
        maxW="480px"
        p="5"
        bg="bg.surface"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="2xl"
        boxShadow="xl"
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
        <Text mt="3" fontSize="sm" color="fg.muted">
          {warning}
        </Text>
        <label>
          <HStack mt="4" gap="2" alignItems="start">
            <input
              type="checkbox"
              checked={acknowledged}
              disabled={loading}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <Text fontSize="sm">{acknowledgeLabel}</Text>
          </HStack>
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
      </Box>
    </Box>
  );
}
