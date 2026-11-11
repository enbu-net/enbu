import { useState } from "react";
import { Download, RefreshCw, RotateCcw } from "lucide-react";
import { Box, Flex, VStack, styled } from "styled-system/jsx";
import { Button, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { host } from "../../lib/host";
import type { UpdateStatus } from "../../lib/types";
import { m } from "../../paraglide/messages";

/** The Homebrew cask of the desktop app (enbu-net/homebrew-tap). */
export const homebrewCommand = "brew upgrade --cask enbu-desktop";

type Phase = "idle" | "checking" | "checked" | "installing" | "installed";

/**
 * What an update means for this installation, by who updates it: the app
 * itself, Homebrew, the system's package manager, the person (an app they
 * cannot overwrite), or nobody (development builds).
 */
export function updateAdvice(
  status: UpdateStatus,
): "install" | "homebrew" | "system_package" | "manual" | null {
  if (!status.available) return null;
  switch (status.method as string) {
    case "self":
      return "install";
    case "homebrew":
      return "homebrew";
    case "system_package":
      return "system_package";
    case "manual":
      return "manual";
    default:
      return null;
  }
}

function Code({ children }: { children: string }) {
  return (
    <styled.code
      fontFamily="mono"
      fontSize="xs"
      px="1.5"
      py="0.5"
      borderRadius="sm"
      bg="bg.muted"
      userSelect="all"
    >
      {children}
    </styled.code>
  );
}

/**
 * Checks for a newer release on request and, where the app manages its own
 * installation, installs it and restarts. VS Code updates its extension, so
 * there it only says so.
 */
export function UpdateSection() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [error, setError] = useState<DisplayError | null>(null);

  if (host === "vscode") {
    return (
      <Text fontSize="sm" color="fg.muted">
        {m.update_editor()}
      </Text>
    );
  }

  async function check() {
    setPhase("checking");
    setError(null);
    try {
      setStatus(await backend.CheckForUpdate());
      setPhase("checked");
    } catch (err) {
      setError(toDisplayError(err));
      setPhase("idle");
    }
  }

  async function install() {
    setPhase("installing");
    setError(null);
    try {
      setStatus(await backend.InstallUpdate());
      setPhase("installed");
    } catch (err) {
      setError(toDisplayError(err));
      setPhase("checked");
    }
  }

  async function restart() {
    setError(null);
    try {
      await backend.RestartApp();
    } catch (err) {
      setError(toDisplayError(err));
    }
  }

  const advice = status ? updateAdvice(status) : null;
  const releaseLink = status?.url ? (
    <styled.a
      href={status.url}
      target="_blank"
      rel="noopener noreferrer"
      fontSize="sm"
      color="accent.text"
    >
      {m.update_releaseNotes()}
    </styled.a>
  ) : null;

  return (
    <VStack alignItems="stretch" gap="3" w="full">
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}
      <Flex align="center" justify="space-between" gap="3" flexWrap="wrap">
        <Box minW="0" role="status" aria-live="polite">
          {phase === "idle" && null}
          {phase === "checking" && (
            <Text fontSize="sm" color="fg.muted">
              {m.update_checking()}
            </Text>
          )}
          {phase === "installing" && (
            <Text fontSize="sm" color="fg.muted">
              {m.update_installing()}
            </Text>
          )}
          {phase === "installed" && status && (
            <Text fontSize="sm">{m.update_installed({ version: status.current })}</Text>
          )}
          {phase === "checked" && status && (status.method as string) === "development" && (
            <Text fontSize="sm" color="fg.muted">
              {m.update_development()}
            </Text>
          )}
          {phase === "checked" &&
            status &&
            (status.method as string) !== "development" &&
            !status.available && <Text fontSize="sm">{m.update_upToDate()}</Text>}
          {phase === "checked" && status?.available && (
            <Flex align="center" gap="3" flexWrap="wrap">
              <Text fontSize="sm" fontWeight="semibold">
                {m.update_available({ version: status.latest ?? "" })}
              </Text>
              {releaseLink}
            </Flex>
          )}
        </Box>
        <Flex gap="2">
          {(phase === "idle" ||
            phase === "checking" ||
            (phase === "checked" && advice !== "install")) && (
            <Button
              size="sm"
              variant="outline"
              loading={phase === "checking"}
              onClick={() => void check()}
            >
              <RefreshCw size={14} aria-hidden="true" />
              {m.update_check()}
            </Button>
          )}
          {(phase === "installing" || (phase === "checked" && advice === "install")) && (
            <Button
              size="sm"
              colorPalette="accent"
              loading={phase === "installing"}
              onClick={() => void install()}
            >
              <Download size={14} aria-hidden="true" />
              {m.update_install()}
            </Button>
          )}
          {phase === "installed" && (
            <Button size="sm" colorPalette="accent" onClick={() => void restart()}>
              <RotateCcw size={14} aria-hidden="true" />
              {m.update_restart()}
            </Button>
          )}
        </Flex>
      </Flex>
      {phase === "checked" && advice === "homebrew" && (
        <Text fontSize="sm" color="fg.muted">
          {m.update_homebrew()} <Code>{homebrewCommand}</Code>
        </Text>
      )}
      {phase === "checked" && advice === "system_package" && (
        <Text fontSize="sm" color="fg.muted">
          {m.update_systemPackage()}
        </Text>
      )}
      {phase === "checked" && advice === "manual" && (
        <Text fontSize="sm" color="fg.muted">
          {m.update_manual()}
        </Text>
      )}
    </VStack>
  );
}
