import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Cpu, ShieldCheck } from "lucide-react";
import { Box, HStack, VStack } from "styled-system/jsx";
import { Button, Heading, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { Diagnosis, PublicInfo } from "../../lib/types";
import { m } from "../../paraglide/messages";

/**
 * This device's keys, as `enbu identity show` prints them, the hardware check
 * of `enbu doctor`, and the switch to a post-quantum key of `enbu identity upgrade`.
 */
export function DevicePanel({
  repoPath,
  postQuantum,
  onUpgraded,
}: {
  repoPath: string;
  /** Whether this device's member key is already hybrid ML-KEM. */
  postQuantum: boolean;
  /** Called after an upgrade, so the member list shows the new key. */
  onUpgraded: () => void | Promise<void>;
}) {
  const [info, setInfo] = useState<PublicInfo | null>(null);
  const [diagnosis, setDiagnosis] = useState<Diagnosis | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);

  const load = useCallback(async () => {
    try {
      setInfo(await backend.identity());
    } catch (err) {
      setError(toDisplayError(err));
    }
  }, []);

  useEffect(() => {
    if (repoPath) void load();
  }, [repoPath, load]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box mt="8">
      <Heading as="h3" size="md" fontWeight="bold" mb="3">
        {m.device_title()}
      </Heading>
      {error && (
        <Box mb="3">
          <ErrorAlert error={error} onDismiss={() => setError(null)} />
        </Box>
      )}
      {info && (
        <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
          <Field label={m.device_fingerprint()} mono>
            {info.fingerprint ?? ""}
          </Field>
          <Field label={m.device_algorithm()}>{info.algorithm}</Field>
          <Field label={m.device_backend()}>{info.backend}</Field>
          {info.device && <Field label={m.device_hardware()}>{info.device}</Field>}
          <Field label={m.device_recipient()} mono>
            {info.recipient}
          </Field>
        </Box>
      )}
      {notice && (
        <Text role="status" mt="3" fontSize="sm">
          {notice}
        </Text>
      )}
      {diagnosis && (
        <VStack role="status" alignItems="stretch" gap="1" mt="3" fontSize="sm">
          <Text>
            {diagnosis.available
              ? m.device_hardwareAvailable({ backend: diagnosis.backend })
              : m.device_hardwareUnavailable({
                  backend: diagnosis.backend,
                  reason: diagnosis.reason ?? "",
                })}
          </Text>
          <Text>
            {diagnosis.fallback_available
              ? m.device_keyringAvailable()
              : m.device_keyringUnavailable({ reason: diagnosis.fallback_reason ?? "" })}
          </Text>
        </VStack>
      )}
      <HStack mt="3" gap="2" flexWrap="wrap">
        {!postQuantum && (
          <Button
            size="sm"
            variant="outline"
            loading={busy}
            title={m.device_upgradeHint()}
            onClick={() =>
              void run(async () => {
                const result = await backend.upgradeIdentity();
                setNotice(
                  result.pending
                    ? m.device_upgradePending({ fingerprint: result.fingerprint })
                    : m.device_upgraded(),
                );
                await Promise.all([load(), onUpgraded()]);
              })
            }
          >
            <ShieldCheck size={14} aria-hidden="true" />
            {m.device_upgrade()}
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={() => void run(async () => setDiagnosis(await backend.diagnoseIdentity()))}
        >
          <Cpu size={14} aria-hidden="true" />
          {m.device_diagnose()}
        </Button>
      </HStack>
    </Box>
  );
}

function Field({ label, mono, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <Box
      display="grid"
      gridTemplateColumns={{ base: "1fr", sm: "minmax(140px,.4fr) minmax(0,1.6fr)" }}
      gap={{ base: "1", sm: "4" }}
      px="4"
      py="3"
      borderBottomWidth="1px"
      borderColor="border.default"
      _last={{ borderBottomWidth: "0" }}
    >
      <Text fontSize="sm" color="fg.muted">
        {label}
      </Text>
      <Text fontSize="sm" fontFamily={mono ? "mono" : undefined} wordBreak="break-all">
        {children}
      </Text>
    </Box>
  );
}
