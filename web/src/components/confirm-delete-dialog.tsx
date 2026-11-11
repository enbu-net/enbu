import { type ReactNode, type RefObject, useId } from "react";
import { HStack } from "styled-system/jsx";
import { Button, Heading, Text } from "./ui";
import { Trash2 } from "lucide-react";
import { ModalDialog } from "./modal-dialog";

export function ConfirmDeleteDialog({
  open,
  title,
  description,
  cancelLabel,
  confirmLabel,
  loading,
  triggerRef,
  children,
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
  /** Options shown above the buttons, such as what else to delete. */
  children?: ReactNode;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
}) {
  const titleId = useId();
  const descriptionId = useId();
  if (!open) return null;
  return (
    <ModalDialog
      labelledBy={titleId}
      describedBy={description ? descriptionId : undefined}
      dismissible={!loading}
      returnFocusRef={triggerRef}
      onClose={onClose}
    >
      <Heading id={titleId} size="lg" fontWeight="extrabold">
        {title}
      </Heading>
      {description && (
        <Text id={descriptionId} mt="3" fontSize="sm" color="fg.muted">
          {description}
        </Text>
      )}
      {children}
      <HStack justify="end" gap="2" mt="6">
        <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
          {cancelLabel}
        </Button>
        <Button
          type="button"
          bg="status.dangerSolid"
          color="status.dangerFg"
          loading={loading}
          aria-label={`${confirmLabel}: ${title}`}
          onClick={() => void onConfirm()}
        >
          <Trash2 size={15} aria-hidden="true" />
          {confirmLabel}
        </Button>
      </HStack>
    </ModalDialog>
  );
}
