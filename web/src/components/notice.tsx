import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Alert, Button } from "./ui";
import { useI18n } from "../lib/i18n";

/** A dismissible status message, such as what an operation did. */
export function Notice({ children, onDismiss }: { children: ReactNode; onDismiss: () => void }) {
  const { t } = useI18n();
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
        aria-label={t("common.close")}
        onClick={onDismiss}
      >
        <X size={14} />
      </Button>
    </Alert.Root>
  );
}
