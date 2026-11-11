import { HStack, VStack } from "styled-system/jsx";
import { Button, Heading, Spinner, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { displayError, type DisplayError } from "../../lib/app-error";
import { m } from "../../paraglide/messages";

/** Where a sign-in stands, as the panel shows it. */
export type LoginStatus = {
  state: "pending" | "success" | "expired" | "denied" | "error";
  error?: DisplayError;
};

export function OAuthLoginPanel({
  userCode,
  verificationURI,
  status,
  expiresIn,
  onCancel,
  onRetry,
}: {
  /** The Device Flow code to enter at verificationURI. */
  userCode: string;
  verificationURI: string;
  status: LoginStatus | null;
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
          {m.auth_deviceInstruction({ url: verificationURI })}
        </Text>
        <Text
          fontSize="3xl"
          fontWeight="bold"
          fontFamily="mono"
          letterSpacing="widest"
          userSelect="all"
        >
          {userCode}
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
            h="auto"
            minH="38px"
            onClick={onRetry}
          >
            {m.auth_tryAgain()}
          </Button>
        ) : (
          <Button variant="ghost" h="auto" minH="38px" color="fg.muted" onClick={onCancel}>
            {m.auth_cancel()}
          </Button>
        )}
      </HStack>
    </VStack>
  );
}
