import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Alert, Button } from "./ui";
import { m } from "../paraglide/messages";

/** A dismissible status message, such as what an operation did. */
export function Notice({ children, onDismiss }: { children: ReactNode; onDismiss: () => void }) {
  return (
    <Alert.Root role="status" borderRadius="md" borderWidth="1px" py={3} px={4} mb="4">
      <Alert.Content display="flex" flexWrap="wrap" alignItems="center" gap="3" fontSize="sm">
        {children}
      </Alert.Content>
      <Button
        variant="ghost"
        w="24px"
        h="24px"
        p="0"
        flexShrink="0"
        aria-label={m.common_close()}
        onClick={onDismiss}
      >
        <X size={14} />
      </Button>
    </Alert.Root>
  );
}
