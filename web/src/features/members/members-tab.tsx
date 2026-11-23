import { useCallback, useEffect, useRef, useState } from "react";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { JoinRequestInfo, MemberInfo } from "../../lib/types";
import type { RunTransfer } from "../dashboard/use-transfer";
import { DevicePanel } from "./device-panel";
import { RemovalRecovery } from "./removal-recovery";
import { MembersPanel } from "./members-panel";

/** The members and pending join requests of the selected repository. */
export function useMembers(repoPath: string) {
  const [members, setMembers] = useState<MemberInfo[]>([]);
  const [requests, setRequests] = useState<JoinRequestInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  const request = useRef(0);

  const refresh = useCallback(async () => {
    // A newer fetch, for example after switching repositories, wins.
    const id = ++request.current;
    setLoading(true);
    setError(null);
    try {
      const [memberList, requestList] = await Promise.all([
        backend.ListMembers(),
        backend.ListJoinRequests(),
      ]);
      if (id !== request.current) return;
      setMembers(memberList);
      setRequests(requestList);
    } catch (err) {
      if (id === request.current) setError(toDisplayError(err));
    } finally {
      if (id === request.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (repoPath) void refresh();
  }, [repoPath, refresh]);

  return { members, requests, loading, error, setError, refresh };
}

export function MembersTab({
  repoPath,
  environment,
  transfer,
  recoveryTargets,
  rememberRecovery,
  clearRecovery,
}: {
  repoPath: string;
  /** The environment a sync re-encrypts and merges. */
  environment: string;
  transfer: RunTransfer;
  recoveryTargets: string;
  rememberRecovery: (targets: string) => void;
  clearRecovery: (target: string) => void;
}) {
  const { members, requests, loading, error, setError, refresh } = useMembers(repoPath);
  return (
    <>
      {recoveryTargets && <RemovalRecovery targets={recoveryTargets} onApplied={clearRecovery} />}
      <MembersPanel
        members={members}
        requests={requests}
        loading={loading}
        error={error}
        onSync={async () => {
          try {
            await transfer("sync", async () => {
              await backend.SyncSecrets(environment);
              await refresh();
            });
          } catch (err) {
            setError(toDisplayError(err));
          }
        }}
        onApprove={async (deviceID) => {
          await backend.ApproveMember(deviceID);
          await refresh();
        }}
        onRemove={async (deviceID) => {
          try {
            await backend.RemoveMember(deviceID);
          } catch (err) {
            const error = toDisplayError(err);
            if (error.code === "removal_write_race" && error.params.targets) {
              rememberRecovery(error.params.targets);
            }
            throw err;
          } finally {
            await refresh();
          }
        }}
        onSetAdmin={async (deviceID, admin) => {
          await backend.SetAdmin(deviceID, admin);
          await refresh();
        }}
        onErrorDismiss={() => setError(null)}
      />
      <DevicePanel repoPath={repoPath} />
    </>
  );
}
