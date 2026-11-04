import { useCallback, useEffect, useRef, useState } from "react";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { JoinRequest, Member } from "../../lib/types";
import type { RunTransfer } from "../dashboard/use-transfer";
import { DevicePanel } from "./device-panel";
import { MembersPanel } from "./members-panel";

/** The members and pending join requests of the selected repository. */
export function useMembers(repoPath: string) {
  const [members, setMembers] = useState<Member[]>([]);
  const [requests, setRequests] = useState<JoinRequest[]>([]);
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
        backend.listMembers(),
        backend.listJoinRequests(),
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
}: {
  repoPath: string;
  /** The environment a sync re-encrypts and merges. */
  environment: string;
  transfer: RunTransfer;
}) {
  const { members, requests, loading, error, setError, refresh } = useMembers(repoPath);
  // Until the members load, assume the key is current rather than offer an upgrade.
  const postQuantum = members.find((member) => member.self)?.post_quantum ?? true;
  return (
    <>
      <MembersPanel
        members={members}
        requests={requests}
        loading={loading}
        error={error}
        onSync={async () => {
          try {
            await transfer("sync", async () => {
              await backend.syncSecrets(environment);
              await refresh();
            });
          } catch (err) {
            setError(toDisplayError(err));
          }
        }}
        onApprove={async (deviceID) => {
          await backend.approveMember(deviceID);
          await refresh();
        }}
        onRemove={async (deviceID) => {
          await backend.removeMember(deviceID);
          await refresh();
        }}
        onSetAdmin={async (deviceID, admin) => {
          await backend.setAdmin(deviceID, admin);
          await refresh();
        }}
        onResolveFork={async () => {
          await backend.resolveMemberFork();
          await refresh();
        }}
        onErrorDismiss={() => setError(null)}
      />
      <DevicePanel repoPath={repoPath} postQuantum={postQuantum} onUpgraded={refresh} />
    </>
  );
}
