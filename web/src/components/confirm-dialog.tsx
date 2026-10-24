import { type ReactNode, type RefObject, useEffect, useId, useRef } from "react";
import { Box, HStack } from "styled-system/jsx";
import { Button, Heading, Text } from "./ui";
import { useFocusTrap } from "../lib/use-focus-trap";

/**
 * Asks before an action that changes the workspace for everyone, such as
 * promoting an admin. `danger` styles the confirm button for actions that
 * cannot be undone; `children` holds extra inputs such as an opt-in checkbox.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  cancelLabel,
  confirmLabel,
  danger = false,
  disabled = false,
  loading,
  triggerRef,
  children,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  description?: string;
  cancelLabel: string;
  confirmLabel: string;
  danger?: boolean;
  /** Keeps the confirm button off until the inputs in children are complete. */
  disabled?: boolean;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  children?: ReactNode;
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
        {description && (
          <Text id={descriptionId} mt="3" fontSize="sm" color="fg.muted">
            {description}
          </Text>
        )}
        {children && <Box mt="4">{children}</Box>}
        <HStack justify="end" gap="2" mt="6">
          <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
            {cancelLabel}
          </Button>
          <Button
            type="button"
            {...(danger ? { bg: "status.danger", color: "white" } : { colorPalette: "accent" })}
            loading={loading}
            disabled={disabled}
            onClick={() => void onConfirm()}
          >
            {confirmLabel}
          </Button>
        </HStack>
      </Box>
    </Box>
  );
}
