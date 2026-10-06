import { type RefObject, useEffect, useId, useRef } from "react";
import { Box, HStack } from "styled-system/jsx";
import { Button, Heading, Text } from "./ui";
import { Trash2 } from "lucide-react";
import { useFocusTrap } from "../lib/use-focus-trap";

export function ConfirmDeleteDialog({
  open,
  title,
  description,
  cancelLabel,
  confirmLabel,
  loading,
  triggerRef,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  /** Extra text shown under the title, such as what the action cannot undo. */
  description?: string;
  cancelLabel: string;
  confirmLabel: string;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
}) {
  const titleId = useId();
  const descriptionId = useId();
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
        aria-describedby={description ? descriptionId : undefined}
        w="full"
        maxW="440px"
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
        {description && (
          <Text id={descriptionId} mt="3" fontSize="sm" color="fg.muted">
            {description}
          </Text>
        )}
        <HStack justify="end" gap="2" mt="6">
          <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
            {cancelLabel}
          </Button>
          <Button
            type="button"
            bg="status.danger"
            color="white"
            loading={loading}
            aria-label={`${confirmLabel}: ${title}`}
            onClick={() => void onConfirm()}
          >
            <Trash2 size={15} aria-hidden="true" />
            {confirmLabel}
          </Button>
        </HStack>
      </Box>
    </Box>
  );
}
