import { useRef, useState, type ReactNode } from "react";
import { RefreshCw, Shield, ShieldOff, Trash2 } from "lucide-react";
import { Box, HStack } from "styled-system/jsx";
import { Button, Heading, Spinner, Text } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { FingerprintConfirmDialog } from "../../components/fingerprint-confirm-dialog";
import { ErrorAlert } from "../../components/error-alert";
import { SectionHeader } from "../../components/layout";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { useI18n } from "../../lib/i18n";
import type { JoinRequest, Member } from "../../lib/types";

export function MembersPanel({
  members,
  requests,
  loading,
  error,
  onSync,
  onApprove,
  onRemove,
  onSetAdmin,
  onResolveFork,
  onErrorDismiss,
}: {
  members: Member[];
  requests: JoinRequest[];
  loading: boolean;
  error: DisplayError | null;
  onSync: () => void | Promise<void>;
  onApprove: (deviceID: string) => Promise<void>;
  onRemove: (deviceID: string) => Promise<void>;
  onSetAdmin: (deviceID: string, admin: boolean) => Promise<void>;
  /** Joins member changes two admins made at the same time. */
  onResolveFork: () => Promise<void>;
  onErrorDismiss: () => void;
}) {
  const { t } = useI18n();
  const [approving, setApproving] = useState<JoinRequest | null>(null);
  const [removing, setRemoving] = useState<Member | null>(null);
  const [granting, setGranting] = useState<Member | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<DisplayError | null>(null);
  const approveTriggerRef = useRef<HTMLElement | null>(null);
  const removeTriggerRef = useRef<HTMLElement | null>(null);
  const grantTriggerRef = useRef<HTMLElement | null>(null);
  // Only an admin can change who is an admin.
  const selfAdmin = members.some((member) => member.self && member.admin);

  // The dialog closes whether or not the action worked; a failure is shown in
  // the panel, so the admin starts again from a fresh list instead of retrying
  // on a stale dialog.
  async function run(action: () => Promise<void>, close: () => void) {
    setBusy(true);
    setActionError(null);
    try {
      await action();
    } catch (err) {
      setActionError(toDisplayError(err));
    } finally {
      close();
      setBusy(false);
    }
  }

  const shownError = actionError ?? error;
  return (
    <>
      <SectionHeader title={t("members.title")}>
        <Button
          size="sm"
          variant="outline"
          loading={loading}
          title={t("dashboard.syncDescription")}
          onClick={() => void onSync()}
        >
          <RefreshCw size={14} />
          {t("dashboard.sync")}
        </Button>
      </SectionHeader>
      {shownError && (
        <Box mb="4">
          <ErrorAlert
            error={shownError}
            onDismiss={() => {
              setActionError(null);
              onErrorDismiss();
            }}
          />
          {/* A failed resolution replaces the fork error, but the fork remains. */}
          {(error?.code === "control_forked" || shownError.code === "control_forked") && (
            <Button
              size="sm"
              mt="2"
              loading={busy}
              onClick={() => void run(onResolveFork, () => {})}
            >
              {t("members.resolveFork")}
            </Button>
          )}
        </Box>
      )}
      {loading ? (
        <HStack role="status" py="8" justify="center">
          <Spinner size="sm" aria-hidden="true" />
          <Text color="fg.muted">{t("common.loading")}</Text>
        </HStack>
      ) : (
        <>
          {requests.length > 0 && (
            <Box mb="6">
              <Heading as="h3" size="md" fontWeight="bold" mb="1">
                {t("members.pendingTitle")}
              </Heading>
              <Text fontSize="sm" color="fg.muted" mb="3">
                {t("members.pendingHint")}
              </Text>
              <Box
                overflow="hidden"
                borderWidth="1px"
                borderColor="border.default"
                borderRadius="xl"
              >
                {requests.map((request, index) => (
                  <PendingRow
                    key={request.device_id}
                    request={request}
                    last={index === requests.length - 1}
                    onApprove={(trigger) => {
                      approveTriggerRef.current = trigger;
                      setApproving(request);
                    }}
                  />
                ))}
              </Box>
            </Box>
          )}
          {members.length === 0 ? (
            <Text color="fg.muted" textAlign="center" py="8">
              {t("members.empty")}
            </Text>
          ) : (
            <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
              {members.map((member, index) => (
                <MemberRow
                  key={member.device_id}
                  member={member}
                  last={index === members.length - 1}
                  onRemove={(trigger) => {
                    removeTriggerRef.current = trigger;
                    setRemoving(member);
                  }}
                  onToggleAdmin={
                    selfAdmin
                      ? (trigger) => {
                          if (member.admin) {
                            void run(
                              () => onSetAdmin(member.device_id, false),
                              () => {},
                            );
                            return;
                          }
                          // Granting admin is as sensitive as approving a device.
                          grantTriggerRef.current = trigger;
                          setGranting(member);
                        }
                      : undefined
                  }
                />
              ))}
            </Box>
          )}
        </>
      )}
      <FingerprintConfirmDialog
        open={approving !== null}
        title={t("members.approveTitle")}
        fingerprint={approving?.fingerprint ?? ""}
        warning={t("members.approveWarning")}
        acknowledgeLabel={t("members.fingerprintMatches")}
        cancelLabel={t("members.cancel")}
        confirmLabel={t("members.approve")}
        loading={busy}
        triggerRef={approveTriggerRef}
        onClose={() => setApproving(null)}
        onConfirm={() => {
          const target = approving;
          if (!target) return;
          return run(
            () => onApprove(target.device_id),
            () => setApproving(null),
          );
        }}
      />
      <FingerprintConfirmDialog
        open={granting !== null}
        title={t("members.grantAdminTitle")}
        fingerprint={granting?.fingerprint ?? ""}
        warning={t("members.grantAdminWarning")}
        acknowledgeLabel={t("members.fingerprintConfirmed")}
        cancelLabel={t("members.cancel")}
        confirmLabel={t("members.makeAdmin")}
        loading={busy}
        triggerRef={grantTriggerRef}
        onClose={() => setGranting(null)}
        onConfirm={() => {
          const target = granting;
          if (!target) return;
          return run(
            () => onSetAdmin(target.device_id, true),
            () => setGranting(null),
          );
        }}
      />
      <ConfirmDeleteDialog
        open={removing !== null}
        title={t("members.removeTitle", { fingerprint: removing?.fingerprint ?? "" })}
        description={t("members.removeHint")}
        cancelLabel={t("members.cancel")}
        confirmLabel={t("members.remove")}
        loading={busy}
        triggerRef={removeTriggerRef}
        onClose={() => setRemoving(null)}
        onConfirm={() => {
          const target = removing;
          if (!target) return;
          return run(
            () => onRemove(target.device_id),
            () => setRemoving(null),
          );
        }}
      />
    </>
  );
}

function RowShell({ last, children }: { last: boolean; children: ReactNode }) {
  return (
    <Box
      w="full"
      minH="64px"
      display="grid"
      gridTemplateColumns="auto minmax(0,1fr) auto"
      alignItems="center"
      gap="3"
      px="4"
      py="3"
      color="fg.default"
      bg="transparent"
      borderBottomWidth={last ? "0" : "1px"}
      borderColor="border.default"
      textAlign="left"
    >
      {children}
    </Box>
  );
}

function FingerprintAvatar({ fingerprint }: { fingerprint: string }) {
  return (
    <Box
      w="38px"
      h="38px"
      borderRadius="full"
      bg="bg.muted"
      display="grid"
      placeItems="center"
      fontFamily="mono"
      fontSize="xs"
    >
      {fingerprint.slice(0, 2).toUpperCase()}
    </Box>
  );
}

export function PendingRow({
  request,
  last = false,
  onApprove,
}: {
  request: JoinRequest;
  last?: boolean;
  onApprove: (trigger: HTMLElement) => void;
}) {
  const { t } = useI18n();
  const requested = new Date(request.requested_at);
  const time = Number.isNaN(requested.getTime()) ? "" : requested.toLocaleString();
  return (
    <RowShell last={last}>
      <FingerprintAvatar fingerprint={request.fingerprint} />
      <Box minW="0">
        <Text fontWeight="semibold" fontSize="sm" fontFamily="mono">
          {request.fingerprint}
        </Text>
        <Text fontSize="2xs" color="fg.muted">
          {request.algorithm.toUpperCase()}
          {request.key_update ? ` · ${t("members.keyUpdate")}` : ""}
          {time ? ` · ${t("members.requestedAt", { time })}` : ""}
        </Text>
      </Box>
      <Button size="sm" onClick={(event) => onApprove(event.currentTarget)}>
        {t("members.approve")}
      </Button>
    </RowShell>
  );
}

export function MemberRow({
  member,
  last = false,
  onRemove,
  onToggleAdmin,
}: {
  member: Member;
  last?: boolean;
  onRemove?: (trigger: HTMLElement) => void;
  /** Grants or revokes admin; left out when this device cannot. */
  onToggleAdmin?: (trigger: HTMLElement) => void;
}) {
  const { t } = useI18n();
  return (
    <RowShell last={last}>
      <FingerprintAvatar fingerprint={member.fingerprint} />
      <Box minW="0">
        <Text fontWeight="semibold" fontSize="sm" fontFamily="mono">
          {member.fingerprint}
        </Text>
        <Text fontSize="2xs" color="fg.muted">
          {member.algorithm.toUpperCase()}
          {member.post_quantum ? ` · ${t("device.postQuantum")}` : ""}
          {member.self ? ` · ${t("members.you")}` : ""}
        </Text>
      </Box>
      <HStack gap="2">
        <Box
          px="2"
          py="1"
          bg="bg.muted"
          borderWidth="1px"
          borderColor="border.default"
          borderRadius="full"
          color="fg.muted"
          fontSize="2xs"
        >
          {member.admin ? t("members.admin") : t("members.member")}
        </Box>
        {onToggleAdmin && (
          <Button
            size="sm"
            variant="ghost"
            aria-label={`${member.admin ? t("members.revokeAdmin") : t("members.makeAdmin")}: ${member.fingerprint}`}
            onClick={(event) => onToggleAdmin(event.currentTarget)}
          >
            {member.admin ? (
              <ShieldOff size={14} aria-hidden="true" />
            ) : (
              <Shield size={14} aria-hidden="true" />
            )}
          </Button>
        )}
        {onRemove && !member.self && (
          <Button
            size="sm"
            variant="ghost"
            aria-label={`${t("members.remove")}: ${member.fingerprint}`}
            onClick={(event) => onRemove(event.currentTarget)}
          >
            <Trash2 size={14} aria-hidden="true" />
          </Button>
        )}
      </HStack>
    </RowShell>
  );
}

export function MemberAvatar({ username }: { username: string }) {
  return (
    <Box position="relative" w="38px" h="38px" flexShrink="0">
      <Box
        position="absolute"
        inset="0"
        display="grid"
        placeItems="center"
        color="accent.default"
        bg="accent.subtle"
        borderRadius="full"
        fontSize="2xs"
        fontWeight="extrabold"
      >
        {username.slice(0, 2).toUpperCase()}
      </Box>
      <img
        src={`https://avatars.githubusercontent.com/${encodeURIComponent(username)}?size=76`}
        width={38}
        height={38}
        loading="lazy"
        alt=""
        style={{ position: "absolute", inset: 0, borderRadius: "50%" }}
        onError={(event) => {
          event.currentTarget.style.display = "none";
        }}
      />
    </Box>
  );
}
