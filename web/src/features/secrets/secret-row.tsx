import { useEffect, useRef, useState } from "react";
import { Check, Copy, Eye, EyeOff, Save, Trash2 } from "lucide-react";
import { Box, HStack, styled } from "styled-system/jsx";
import { Button, Input } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { copySecret } from "../../lib/clipboard";
import { m } from "../../paraglide/messages";

function applyTextareaEdit(previous: string, next: string): string {
  if (!previous.includes("\r")) return next;
  // Textareas expose CRLF and CR as LF. Keep the original bytes on both
  // sides of the edited span and take the new text only for that span.
  const original = previous.match(/\r\n|[^]/g) ?? [];
  const normalized = previous.replace(/\r\n?/g, "\n");
  let start = 0;
  while (start < next.length && normalized[start] === next[start]) start++;
  let end = normalized.length;
  let nextEnd = next.length;
  while (end > start && nextEnd > start && normalized[end - 1] === next[nextEnd - 1]) {
    end--;
    nextEnd--;
  }
  return (
    original.slice(0, start).join("") + next.slice(start, nextEnd) + original.slice(end).join("")
  );
}

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
  const multiline = /[\r\n]/.test(editValue);
  const valueLabel = `${m.dashboard_value()}: ${secretKey}`;

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

  const copyStatus = copied === "key" ? m.dashboard_keyCopied() : m.dashboard_valueCopied();

  return (
    <styled.form
      data-secret-value-row=""
      onSubmit={(event) => {
        event.preventDefault();
        void saveValue();
      }}
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
        {visible ? (
          <styled.textarea
            aria-label={valueLabel}
            value={editValue}
            disabled={saving}
            rows={multiline ? 4 : 1}
            w="full"
            minH="38px"
            px="3"
            py="2"
            pr="10"
            resize="vertical"
            fontSize="sm"
            bg="bg.surface"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="md"
            onChange={(event) => setEditValue(applyTextareaEdit(editValue, event.target.value))}
          />
        ) : (
          <Input
            aria-label={valueLabel}
            value={multiline ? "********" : editValue}
            disabled={saving}
            type="password"
            readOnly={multiline}
            h="auto"
            minH="38px"
            pr="10"
            borderColor="border.default"
            borderRadius="md"
            onChange={(event) => setEditValue(event.target.value)}
            onKeyDown={(e) => {
              // WebKit may report isComposing=false on the Enter that commits an IME candidate.
              if (e.key === "Enter" && (e.nativeEvent.isComposing || e.keyCode === 229)) {
                e.preventDefault();
              }
            }}
          />
        )}
        <Button
          type="button"
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
            type="submit"
            variant="ghost"
            w="34px"
            h="34px"
            p={0}
            color="accent.text"
            aria-label={m.dashboard_save()}
            title={m.dashboard_save()}
            loading={saving}
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
      <styled.span srOnly role="status">
        {copied ? copyStatus : ""}
      </styled.span>
      {copied && (
        <styled.div
          data-toast=""
          aria-hidden="true"
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
          {copyStatus}
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
    </styled.form>
  );
}
