import { useEffect, useRef, useState } from "react";
import { Check, Copy, Eye, EyeOff, Trash2 } from "lucide-react";
import { Box, HStack } from "styled-system/jsx";
import { Button, Input, Text } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { m } from "../../paraglide/messages";

export function SecretRow({
  secretKey,
  secretValue,
  onEdit,
  onDelete,
  deleteLabel,
}: {
  secretKey: string;
  secretValue: string;
  onEdit: (val: string) => Promise<void>;
  onDelete: () => Promise<void>;
  deleteLabel: string;
}) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState<"key" | "value" | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = useState(false);
  const [editValue, setEditValue] = useState(secretValue);
  const deleteTriggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setEditValue(secretValue);
    setCopied(null);
  }, [secretValue]);

  return (
    <Box
      minH="62px"
      display="grid"
      gridTemplateColumns={{
        base: "minmax(0,1fr) auto",
        md: "minmax(160px,.8fr) minmax(220px,1.2fr) auto",
      }}
      alignItems="center"
      gap="3"
      px="4"
      py="3"
      borderBottomWidth="1px"
      borderColor="border.default"
      _last={{ borderBottomWidth: "0" }}
      _hover={{ bg: "bg.muted" }}
    >
      <HStack
        minW="0"
        gap="1"
        gridColumn={{ base: "1", md: "auto" }}
        gridRow={{ base: "1", md: "auto" }}
      >
        <Text flex="1" minW="0" fontFamily="mono" fontSize="sm" fontWeight="bold" truncate>
          {secretKey}
        </Text>
        <Button
          variant="ghost"
          w="30px"
          h="30px"
          p={0}
          flexShrink="0"
          color={copied === "key" ? "status.success" : "fg.muted"}
          aria-label={copied === "key" ? m.dashboard_keyCopied() : m.dashboard_copyKey()}
          title={copied === "key" ? m.dashboard_keyCopied() : m.dashboard_copyKey()}
          onClick={async () => {
            await navigator.clipboard.writeText(secretKey);
            setCopied("key");
          }}
        >
          {copied === "key" ? <Check size={15} /> : <Copy size={15} />}
        </Button>
      </HStack>
      <Input
        aria-label={`${m.dashboard_value()}: ${secretKey}`}
        value={editValue}
        type={visible ? "text" : "password"}
        h="38px"
        gridColumn={{ base: "1 / -1", md: "auto" }}
        gridRow={{ base: "2", md: "auto" }}
        borderColor="border.default"
        borderRadius="md"
        onChange={(e) => setEditValue(e.target.value)}
        onBlur={async (e) => {
          if (e.target.value !== secretValue) await onEdit(e.target.value);
        }}
      />
      <HStack gap="1" gridColumn={{ base: "2", md: "auto" }} gridRow={{ base: "1", md: "auto" }}>
        <Button
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color={copied === "value" ? "status.success" : "fg.muted"}
          aria-label={copied === "value" ? m.dashboard_valueCopied() : m.dashboard_copyValue()}
          title={copied === "value" ? m.dashboard_valueCopied() : m.dashboard_copyValue()}
          onClick={async () => {
            await navigator.clipboard.writeText(editValue);
            setCopied("value");
          }}
        >
          {copied === "value" ? <Check size={16} /> : <Copy size={16} />}
        </Button>
        <Button
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color="fg.muted"
          aria-label={visible ? m.dashboard_hideValue() : m.dashboard_showValue()}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? <EyeOff size={16} /> : <Eye size={16} />}
        </Button>
        <Button
          ref={deleteTriggerRef}
          variant="ghost"
          w="34px"
          h="34px"
          p={0}
          color="fg.muted"
          aria-label={deleteLabel}
          title={deleteLabel}
          disabled={deleting}
          onClick={() => setDeleteConfirmationOpen(true)}
        >
          <Trash2 size={15} />
        </Button>
      </HStack>
      <ConfirmDeleteDialog
        open={deleteConfirmationOpen}
        title={m.dashboard_deleteSecretConfirm({ key: secretKey })}
        cancelLabel={m.config_cancel()}
        confirmLabel={deleteLabel}
        loading={deleting}
        triggerRef={deleteTriggerRef}
        onClose={() => setDeleteConfirmationOpen(false)}
        onConfirm={async () => {
          setDeleting(true);
          try {
            await onDelete();
            setDeleteConfirmationOpen(false);
          } finally {
            setDeleting(false);
          }
        }}
      />
    </Box>
  );
}
