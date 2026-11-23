import { useState } from "react";
import { Box, HStack, styled } from "styled-system/jsx";
import { Button, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { backend } from "../../lib/backend";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import type { RemovalReview } from "../../lib/types";
import { m } from "../../paraglide/messages";

export function RemovalRecovery({
  targets,
  onApplied,
}: {
  targets: string;
  onApplied: (target: string) => void;
}) {
  return targets
    .split("\n")
    .filter(Boolean)
    .map((target) => {
      const [resource, revision] = target.split(" ");
      return (
        <RecoveryRevision
          key={target}
          resource={resource}
          revision={revision}
          onApplied={() => onApplied(target)}
        />
      );
    });
}

function RecoveryRevision({
  resource,
  revision,
  onApplied,
}: {
  resource: string;
  revision: string;
  onApplied: () => void;
}) {
  const [preview, setPreview] = useState<RemovalReview | null>(null);
  const diff = preview?.diff;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);

  async function review(baseline: string) {
    setBusy(true);
    setError(null);
    try {
      setPreview(await backend.ReviewRemovedRevision(resource, revision, baseline));
      if (baseline) onApplied();
    } catch (err) {
      setError(toDisplayError(err));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box mb="4">
      <Text fontFamily="mono" overflowWrap="anywhere">
        {resource} {revision}
      </Text>
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}
      <>
        {diff && (
          <>
            <Text>{m.members_recoveryChanges()}</Text>
            <styled.ul>
              {(diff.added ?? []).map((key) => (
                <li key={key}>+ {key}</li>
              ))}
              {(diff.removed ?? []).map((key) => (
                <li key={key}>- {key}</li>
              ))}
              {(diff.modified ?? []).map((key) => (
                <li key={key}>~ {key}</li>
              ))}
            </styled.ul>
          </>
        )}
        {Boolean(preview?.kept?.length) && (
          <>
            <Text>{m.members_recoveryKept()}</Text>
            <styled.ul>
              {preview?.kept.map((key) => (
                <li key={key}>{key}</li>
              ))}
            </styled.ul>
          </>
        )}
        <HStack>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void review("")}>
            {m.members_recoveryReview()}
          </Button>
          {preview && (
            <Button size="sm" disabled={busy} onClick={() => void review(preview.baseline)}>
              {m.members_recoveryApply()}
            </Button>
          )}
        </HStack>
      </>
    </Box>
  );
}
