import { useState } from "react";
import { Box, HStack, styled } from "styled-system/jsx";
import { Button, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { backend } from "../../lib/backend";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import type { Diff } from "../../lib/types";
import { m } from "../../paraglide/messages";

export function RemovalRecovery({ targets }: { targets: string }) {
  return targets
    .split("\n")
    .filter(Boolean)
    .map((target) => {
      const [resource, revision] = target.split(" ");
      return <RecoveryRevision key={target} resource={resource} revision={revision} />;
    });
}

function RecoveryRevision({ resource, revision }: { resource: string; revision: string }) {
  const [diff, setDiff] = useState<Diff | null>(null);
  const [applied, setApplied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);

  async function review(apply: boolean) {
    setBusy(true);
    setError(null);
    try {
      setDiff(await backend.ReviewRemovedRevision(resource, revision, apply));
      setApplied(apply);
    } catch (err) {
      setError(toDisplayError(err));
      setDiff(null);
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
      {applied ? (
        <Text role="status">{m.members_recoveryApplied()}</Text>
      ) : (
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
          <HStack>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void review(false)}>
              {m.members_recoveryReview()}
            </Button>
            {diff && (
              <Button size="sm" disabled={busy} onClick={() => void review(true)}>
                {m.members_recoveryApply()}
              </Button>
            )}
          </HStack>
        </>
      )}
    </Box>
  );
}
