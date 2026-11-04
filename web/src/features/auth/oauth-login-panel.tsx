import { HStack, VStack } from "styled-system/jsx";
import { Button, Heading, Spinner, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { displayError } from "../../lib/app-error";
import type { OAuthStatus } from "../../lib/types";
import { m } from "../../paraglide/messages";

export function OAuthLoginPanel({
  status,
  expiresIn,
  onCancel,
  onRetry,
}: {
  status: OAuthStatus | null;
  expiresIn: number;
  onCancel: () => Promise<void>;
  onRetry: () => void;
}) {
  const terminal = status?.state && status.state !== "pending";

  return (
    <VStack gap={5} w="full" maxW="480px" alignItems="stretch">
      <Heading as="h1" size="2xl" fontWeight="extrabold" textAlign="center">
        {m.auth_authorizeTitle()}
      </Heading>

      <VStack gap={2} alignItems="center">
        <Text fontSize="sm" color="fg.muted">
          {m.auth_browserInstruction()}
        </Text>
      </VStack>

      {!terminal && status?.state === "pending" && (
        <HStack justifyContent="center">
          <Spinner size="sm" color="accent.default" />
          <Text fontSize="sm">{m.auth_waiting()}</Text>
          <Text fontSize="xs" color="fg.muted">
            {m.auth_expiresIn({ seconds: expiresIn })}
          </Text>
        </HStack>
      )}
      {status?.state === "denied" && <ErrorAlert error={displayError("access_denied")} />}
      {status?.state === "expired" && <ErrorAlert error={displayError("authentication_expired")} />}
      {status?.state === "error" && <ErrorAlert error={status.error ?? displayError("internal")} />}

      {/* Actions */}
      <HStack justifyContent="center" flexWrap="wrap">
        {terminal ? (
          <Button
            bg="accent.default"
            color="accent.fg"
            fontWeight="semibold"
            h="38px"
            onClick={onRetry}
          >
            {m.auth_tryAgain()}
          </Button>
        ) : (
          <Button variant="ghost" h="38px" color="fg.muted" onClick={onCancel}>
            {m.auth_cancel()}
          </Button>
        )}
      </HStack>
    </VStack>
  );
}
