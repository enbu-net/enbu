import {
  Component,
  useCallback,
  useEffect,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { AlertCircle, X } from "lucide-react";
import { Box, HStack } from "../../styled-system/jsx";
import { Button, Text } from "./ui";
import {
  formatDisplayError,
  toDisplayError,
  type DisplayError,
} from "../lib/app-error";
import { m } from "../paraglide/messages";

export function UserErrorGate({ children }: { children: ReactNode }) {
  const [error, setError] = useState<DisplayError | null>(null);
  const report = useCallback((value: unknown) => setError(toDisplayError(value)), []);

  useEffect(() => {
    const onError = (event: ErrorEvent) => report(event.error);
    const onUnhandledRejection = (event: PromiseRejectionEvent) => report(event.reason);
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onUnhandledRejection);
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
    };
  }, [report]);

  return (
    <RenderErrorBoundary
      onError={report}
      fallback={<GlobalError error={error} onDismiss={() => window.location.reload()} />}
    >
      {error && <GlobalError error={error} onDismiss={() => setError(null)} />}
      {children}
    </RenderErrorBoundary>
  );
}

function GlobalError({
  error,
  onDismiss,
}: {
  error: DisplayError | null;
  onDismiss?: () => void;
}) {
  if (!error) return null;
  return (
    <Box
      role="alert"
      position="fixed"
      top="4"
      left="50%"
      transform="translateX(-50%)"
      zIndex="2000"
      w="calc(100% - 2rem)"
      maxW="600px"
      p="4"
      borderWidth="1px"
      borderColor="status.danger"
      borderRadius="lg"
      bg="status.dangerMuted"
      boxShadow="lg"
    >
      <HStack gap="3">
        <AlertCircle size={18} aria-hidden="true" />
        <Text flex="1" fontSize="sm">
          {formatDisplayError(error)}
        </Text>
        {onDismiss && (
          <Button
            variant="ghost"
            w="28px"
            h="28px"
            p="0"
            aria-label={m.common_close()}
            onClick={onDismiss}
          >
            <X size={14} />
          </Button>
        )}
      </HStack>
    </Box>
  );
}

class RenderErrorBoundary extends Component<
  {
    children: ReactNode;
    fallback: ReactNode;
    onError: (error: unknown) => void;
  },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("React render error", error, info);
    this.props.onError(error);
  }

  render(): ReactNode {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}
