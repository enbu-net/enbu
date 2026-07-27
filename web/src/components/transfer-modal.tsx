import { useEffect, useId, useRef, useState } from "react";
import { User, Cloud, Lock, KeyRound, CheckCircle2, AlertCircle } from "lucide-react";
import { Box, HStack, VStack } from "../../styled-system/jsx";
import { Button, Text } from "./ui";
import { useI18n } from "../lib/i18n";
import { useFocusTrap } from "../lib/use-focus-trap";

export interface ProgressStep {
  op: "add" | "pull" | "export" | "sync" | "delete";
  step: string;
  status: "start" | "done";
}

interface TransferModalProps {
  open: boolean;
  operation: "add" | "pull" | "export" | "sync" | "delete" | null;
  error?: string | null;
  onClose: () => void;
}

const DEFAULT_STEPS: Record<"add" | "pull" | "export" | "sync" | "delete", string[]> = {
  add: ["pull_recipients", "pull_secrets", "encrypt", "push"],
  pull: ["download", "validate", "cache"],
  export: ["load", "decrypt", "export"],
  sync: ["pull_secrets", "pull_recipients", "reencrypt", "push"],
  delete: ["pull_recipients", "pull_secrets", "encrypt", "push"],
};

export function TransferModal({ open, operation, error, onClose }: TransferModalProps) {
  const { t } = useI18n();
  const [currentStep, setCurrentStep] = useState<ProgressStep | null>(null);
  const [isDone, setIsDone] = useState(false);
  const isDoneRef = useRef(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  isDoneRef.current = isDone;
  useFocusTrap(open, dialogRef);

  // Event listener & Fallback simulation
  useEffect(() => {
    if (!open || !operation) {
      setCurrentStep(null);
      setIsDone(false);
      isDoneRef.current = false;
      return;
    }

    let hasRealEvents = false;
    const fallbackSteps = DEFAULT_STEPS[operation];
    const terminalStep = fallbackSteps[fallbackSteps.length - 1];

    const handleProgress = (step: ProgressStep) => {
      if (step.op !== operation) return;
      hasRealEvents = true;
      setCurrentStep(step);
      if (step.status === "done" && step.step === terminalStep) {
        setIsDone(true);
      }
    };

    const handleCustomEvent = (e: Event) => {
      const customEvent = e as CustomEvent<ProgressStep>;
      if (customEvent.detail) {
        handleProgress(customEvent.detail);
      }
    };
    window.addEventListener("enbu:progress", handleCustomEvent);

    const wailsRuntime = (window as unknown as { runtime?: { EventsOn?: (event: string, callback: (data: ProgressStep) => void) => () => void } }).runtime;
    let unsubscribeWails: (() => void) | undefined;

    if (wailsRuntime?.EventsOn) {
      unsubscribeWails = wailsRuntime.EventsOn("enbu:progress", (step: ProgressStep) => {
        handleProgress(step);
      });
    }

    // Fallback simulation timer for mock environment
    let stepIdx = 0;

    const timer = setInterval(() => {
      if (!hasRealEvents && !isDoneRef.current) {
        if (stepIdx < fallbackSteps.length - 1) {
          stepIdx++;
          const stepName = fallbackSteps[stepIdx];
          setCurrentStep({
            op: operation,
            step: stepName,
            status: "start",
          });
        }
      }
    }, 1200);

    const firstStep = fallbackSteps[0];
    setCurrentStep({
      op: operation,
      step: firstStep,
      status: "start",
    });

    return () => {
      window.removeEventListener("enbu:progress", handleCustomEvent);
      if (typeof unsubscribeWails === "function") {
        unsubscribeWails();
      }
      clearInterval(timer);
    };
  }, [open, operation]);

  useEffect(() => {
    if (!open) return;
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [onClose, open]);

  if (!open || !operation) return null;

  const stepType = currentStep?.step;
  const isLeftToRight = stepType === "push" || stepType === "reencrypt";
  const isRightToLeft = stepType === "pull_secrets" || stepType === "pull_recipients" || stepType === "download";
  const isLocal = stepType === "encrypt" || stepType === "decrypt" || stepType === "write" || stepType === "validate" || stepType === "cache" || stepType === "load" || stepType === "export";

  const modalTitle =
    operation === "add"
      ? t("transfer.addTitle")
      : operation === "pull"
      ? t("transfer.pullTitle")
      : operation === "export"
      ? t("transfer.exportTitle")
      : operation === "delete"
      ? t("transfer.deleteTitle")
      : t("transfer.syncTitle");

  const stepKey = `transfer.steps.${stepType}` as Parameters<typeof t>[0];
  const stepTranslated = stepType ? t(stepKey) : "";

  const statusText = error
    ? error || t("transfer.error")
    : isDone
    ? t("transfer.done")
    : stepTranslated !== stepKey
    ? stepTranslated
    : t("common.loading");

  return (
    <Box
      position="fixed"
      inset="0"
      zIndex="1000"
      bg="rgba(15, 23, 42, 0.5)"
      backdropFilter="blur(4px)"
      display="flex"
      alignItems="center"
      justifyContent="center"
      p="4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <Box
        ref={dialogRef}
        bg="bg.surface"
        borderWidth="1px"
        borderColor="border.default"
        borderRadius="2xl"
        p="6"
        maxW="480px"
        w="100%"
        boxShadow="2xl"
        display="flex"
        flexDirection="column"
        alignItems="center"
        gap="6"
      >
        {/* Header */}
        <HStack justify="space-between" w="100%" px="2">
          <Text id={titleId} fontSize="sm" fontWeight="extrabold" textTransform="uppercase" letterSpacing="wider" color="fg.muted">
            {modalTitle}
          </Text>
        </HStack>

        {/* Stage */}
        <Box
          position="relative"
          w="100%"
          h="140px"
          display="flex"
          alignItems="center"
          justifyContent="space-between"
          px="8"
        >
          {/* Track Line (exact length matching node centers) */}
          <Box
            position="absolute"
            top="50%"
            left="64px"
            right="64px"
            h="2px"
            borderColor="border.default"
            style={{
              background: "repeating-linear-gradient(90deg, currentColor 0, currentColor 5px, transparent 5px, transparent 10px)",
              opacity: 0.3,
              transform: "translateY(-50%)",
            }}
          />

          {/* User Node (You) */}
          <VStack gap="2" zIndex="2">
            <Box
              w="64px"
              h="64px"
              borderRadius="full"
              bg="bg.subtle"
              borderWidth="2px"
              borderColor={isLeftToRight || isLocal ? "accent.default" : "border.default"}
              boxShadow={isLeftToRight || isLocal ? "0 0 16px var(--colors-accent-default)" : "none"}
              display="flex"
              alignItems="center"
              justifyContent="center"
              style={{
                transition: "all 0.3s ease",
                transform: isLocal ? "scale(1.08)" : "scale(1)",
              }}
            >
              <User size={30} style={{ color: isLeftToRight || isLocal ? "var(--colors-accent-default)" : "var(--colors-fg-muted)" }} />
            </Box>
            <Text fontSize="sm" fontWeight="bold" color="fg.muted">
              YOU
            </Text>
          </VStack>

          {/* Transfer Packet */}
          {!error && !isDone && (
            <Box
              data-transfer-direction={
                isRightToLeft ? "download" : isLeftToRight ? "upload" : "local"
              }
              position="absolute"
              top="calc(50% - 16px)"
              left="50%"
              style={{
                animation: isRightToLeft
                  ? "transfer-left 1.4s ease-in-out infinite"
                  : isLeftToRight
                  ? "transfer-right 1.4s ease-in-out infinite"
                  : "pulse-packet 1.2s ease-in-out infinite",
              }}
            >
              <Box
                w="40px"
                h="32px"
                bg="bg.surface"
                borderWidth="2px"
                borderColor="accent.default"
                borderRadius="md"
                boxShadow="0 0 12px var(--colors-accent-default)"
                display="flex"
                alignItems="center"
                justifyContent="center"
              >
                {stepType === "pull_recipients" ? (
                  <KeyRound size={16} style={{ color: "var(--colors-accent-default)" }} />
                ) : (
                  <Lock size={16} style={{ color: "var(--colors-accent-default)" }} />
                )}
              </Box>
            </Box>
          )}

          {/* Status Badge */}
          {(isDone || error) && (
            <Box
              position="absolute"
              top="50%"
              left="50%"
              style={{ transform: "translate(-50%, -50%)" }}
              zIndex="10"
            >
              {error ? (
                <AlertCircle size={38} style={{ color: "var(--colors-status-danger, #f85149)" }} />
              ) : (
                <CheckCircle2 size={38} style={{ color: "var(--colors-accent-default)" }} />
              )}
            </Box>
          )}

          {/* Registry Node (Cloud) */}
          <VStack gap="2" zIndex="2">
            <Box
              w="64px"
              h="64px"
              borderRadius="full"
              bg="bg.subtle"
              borderWidth="2px"
              borderColor={isRightToLeft ? "accent.default" : "border.default"}
              boxShadow={isRightToLeft ? "0 0 16px var(--colors-accent-default)" : "none"}
              display="flex"
              alignItems="center"
              justifyContent="center"
              style={{ transition: "all 0.3s ease" }}
            >
              <Cloud size={30} style={{ color: isRightToLeft ? "var(--colors-accent-default)" : "var(--colors-fg-muted)" }} />
            </Box>
            <Text fontSize="sm" fontWeight="bold" color="fg.muted">
              REGISTRY
            </Text>
          </VStack>
        </Box>

        {/* Status Text Area (Single clean line) */}
        <VStack gap="1" textAlign="center" minH="40px" justify="center">
          <Text
            fontSize="md"
            fontWeight="bold"
            style={{
              color: error
                ? "var(--colors-status-danger, #f85149)"
                : isDone
                ? "var(--colors-accent-default)"
                : "var(--colors-fg-default)",
            }}
          >
            {statusText}
          </Text>
          {error && (
            <Button type="button" variant="outline" onClick={onClose}>
              {t("common.close")}
            </Button>
          )}
        </VStack>

        <style>{`
          @keyframes transfer-right {
            0% { left: 64px; opacity: 0; transform: translate(-50%, 0) scale(0.6); }
            15% { opacity: 1; transform: translate(-50%, 0) scale(1); }
            85% { opacity: 1; transform: translate(-50%, 0) scale(1); }
            100% { left: calc(100% - 64px); opacity: 0; transform: translate(-50%, 0) scale(0.6); }
          }
          @keyframes transfer-left {
            0% { left: calc(100% - 64px); opacity: 0; transform: translate(-50%, 0) scale(0.6); }
            15% { opacity: 1; transform: translate(-50%, 0) scale(1); }
            85% { opacity: 1; transform: translate(-50%, 0) scale(1); }
            100% { left: 64px; opacity: 0; transform: translate(-50%, 0) scale(0.6); }
          }
          @keyframes pulse-packet {
            0% { transform: translate(-50%, 0) scale(0.95); opacity: 0.7; }
            50% { transform: translate(-50%, 0) scale(1.1); opacity: 1; }
            100% { transform: translate(-50%, 0) scale(0.95); opacity: 0.7; }
          }
        `}</style>
      </Box>
    </Box>
  );
}
