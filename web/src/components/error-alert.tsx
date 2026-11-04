import { X } from "lucide-react";
import { Alert, Button, Text } from "./ui";
import { formatDisplayError, type DisplayError } from "../lib/app-error";
import { m } from "../paraglide/messages";

export function ErrorAlert({ error, onDismiss }: { error: DisplayError; onDismiss?: () => void }) {
  const message = formatDisplayError(error);
  return (
    <Alert.Root
      borderRadius="md"
      borderWidth="1px"
      borderColor="status.danger"
      bg="status.dangerMuted"
      py={3}
      px={4}
    >
      <Alert.Indicator />
      <Alert.Content>
        <Text fontSize="sm">{message}</Text>
      </Alert.Content>
      {onDismiss && (
        <Button
          variant="ghost"
          w="24px"
          h="24px"
          p="0"
          flexShrink="0"
          color="status.danger"
          aria-label={m.common_close()}
          onClick={onDismiss}
        >
          <X size={14} />
        </Button>
      )}
    </Alert.Root>
  );
}
