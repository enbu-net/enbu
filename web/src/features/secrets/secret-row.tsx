import { useEffect, useRef, useState } from "react";
import { Check, Copy, Eye, EyeOff, Save, Trash2 } from "lucide-react";
import { Box, HStack, styled } from "styled-system/jsx";
import { Button, Input } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { copySecret } from "../../lib/clipboard";
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
  const [saving, setSaving] = useState(false);
  const [deleteConfirmationOpen, setDeleteConfirmationOpen] = useState(false);
  const [editValue, setEditValue] = useState(secretValue);
  const deleteTriggerRef = useRef<HTMLButtonElement>(null);

  const copiedTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    setEditValue(secretValue);
    setCopied(null);
  }, [secretValue]);

  useEffect(() => () => clearTimeout(copiedTimer.current), []);

  // The check mark and the status message last a moment; a new copy restarts them.
  function showCopied(what: "key" | "value") {
    clearTimeout(copiedTimer.current);
    setCopied(what);
    copiedTimer.current = setTimeout(() => setCopied(null), 2000);
  }

  async function saveValue() {
    if (saving || editValue === secretValue) return;
    setSaving(true);
    try {
      await onEdit(editValue);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Box
      minH="62px"
      display="grid"
      gridTemplateColumns={{
        base: "minmax(0,1fr) auto",
        lg: "minmax(160px,.8fr) minmax(220px,1.2fr) auto",
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
        gridColumn={{ base: "1", lg: "auto" }}
        gridRow={{ base: "1", lg: "auto" }}
      >
        <styled.button
          type="button"
          minW="0"
          maxW="full"
          overflow="hidden"
          textOverflow="ellipsis"
          whiteSpace="nowrap"
          textAlign="left"
          fontFamily="mono"
          fontSize="sm"
          fontWeight="bold"
          color={copied === "key" ? "status.success" : "fg.default"}
          cursor="pointer"
          _hover={{ textDecoration: "underline" }}
          aria-label={`${m.dashboard_copyKey()}: ${secretKey}`}
          title={copied === "key" ? m.dashboard_keyCopied() : m.dashboard_copyKey()}
          onClick={async () => {
            await navigator.clipboard.writeText(secretKey);
            showCopied("key");
          }}
        >
          {secretKey}
        </styled.button>
      </HStack>
      <Box
        position="relative"
        gridColumn={{ base: "1 / -1", lg: "auto" }}
        gridRow={{ base: "2", lg: "auto" }}
      >
        <Input
          aria-label={`${m.dashboard_value()}: ${secretKey}`}
          value={editValue}
          type={visible ? "text" : "password"}
          h="auto"
          minH="38px"
          pr="10"
          borderColor="border.default"
          borderRadius="md"
          onChange={(e) => setEditValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.nativeEvent.isComposing) {
              e.preventDefault();
              void saveValue();
            }
          }}
        />
        <Button
          variant="ghost"
          position="absolute"
          right="1"
          top="50%"
          transform="translateY(-50%)"
          w="30px"
          h="30px"
          p={0}
          color={copied === "value" ? "status.success" : "fg.muted"}
          aria-label={m.dashboard_copyValue()}
          title={copied === "value" ? m.dashboard_valueCopied() : m.dashboard_copyValue()}
          onClick={async () => {
            await copySecret(editValue);
            showCopied("value");
          }}
        >
          {copied === "value" ? (
            <Check size={16} aria-hidden="true" />
          ) : (
            <Copy size={16} aria-hidden="true" />
          )}
        </Button>
      </Box>
      <HStack gap="1" gridColumn={{ base: "2", lg: "auto" }} gridRow={{ base: "1", lg: "auto" }}>
        {editValue !== secretValue && (
          <Button
            variant="ghost"
            w="34px"
            h="34px"
            p={0}
            color="accent.text"
            aria-label={m.dashboard_save()}
            title={m.dashboard_save()}
            loading={saving}
            onClick={() => void saveValue()}
          >
            <Save size={16} />
          </Button>
        )}
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
      {copied && (
        <styled.div
          data-toast=""
          role="status"
          position="fixed"
          right="4"
          bottom="4"
          zIndex="2001"
          px="4"
          py="3"
          bg="bg.surface"
          color="fg.default"
          borderWidth="1px"
          borderColor="border.default"
          borderRadius="md"
          boxShadow="dropdown"
          pointerEvents="none"
        >
          {copied === "key" ? m.dashboard_keyCopied() : m.dashboard_valueCopied()}
        </styled.div>
      )}
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
