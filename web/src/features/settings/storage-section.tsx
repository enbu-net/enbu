import { useEffect, useId, useState } from "react";
import { VStack, styled } from "styled-system/jsx";
import { Button, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import type { StorageConfig } from "../../lib/types";
import { parseConfigDraft } from "../config/config-draft";
import { m } from "../../paraglide/messages";
import { Section } from "./section";

export function StorageSection() {
  const { repo, reloadRepo } = useSession();
  if (!repo?.initialized) return null;
  return <WorkspaceStorage key={repo.path} onChanged={reloadRepo} />;
}

function WorkspaceStorage({ onChanged }: { onChanged: () => Promise<void> }) {
  const id = useId();
  const [storage, setStorage] = useState<StorageConfig | null>(null);
  const [original, setOriginal] = useState<StorageConfig | null>(null);
  const [paused, setPaused] = useState(false);
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);
  useEffect(() => {
    let active = true;
    void backend
      .ReadConfig()
      .then((text) => {
        if (!active) return;
        const value = parseConfigDraft(text, []).storage;
        const settings: StorageConfig = {
          url: typeof value?.url === "string" ? value.url : "",
          region: typeof value?.region === "string" ? value.region : "",
          endpoint: typeof value?.endpoint === "string" ? value.endpoint : "",
          path_style: value?.path_style === true,
          plain_http: value?.plain_http === true,
        };
        setStorage(settings);
        setOriginal(settings);
      })
      .catch((err: unknown) => {
        if (active) setError(toDisplayError(err));
      });
    return () => {
      active = false;
    };
  }, []);
  const set = (change: Partial<StorageConfig>) => {
    setStorage((current) => (current ? { ...current, ...change } : current));
    setDone(false);
  };
  async function migrate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!storage || !paused) return;
    setSaving(true);
    setError(null);
    setDone(false);
    try {
      const next = { ...storage, url: storage.url.trim() };
      await backend.ChangeStorage(next);
      setOriginal(next);
      setStorage(next);
      setPaused(false);
      setDone(true);
      await onChanged();
    } catch (err) {
      setError(toDisplayError(err));
    } finally {
      setSaving(false);
    }
  }
  return (
    <Section title={m.storage_title()}>
      <Text fontSize="sm" color="fg.muted">
        {m.storage_description()}
      </Text>
      {error && <ErrorAlert error={error} onDismiss={() => setError(null)} />}
      {done && <Text role="status">{m.storage_done()}</Text>}
      {storage && (
        <styled.form onSubmit={(event) => void migrate(event)}>
          <VStack alignItems="stretch" gap="3">
            <styled.label htmlFor={id}>{m.init_storage()}</styled.label>
            <Input
              id={id}
              value={storage.url}
              disabled={saving}
              onChange={(event) => set({ url: event.target.value })}
            />
            {storage.url.startsWith("s3://") && (
              <>
                <Input
                  aria-label={m.init_region()}
                  value={storage.region}
                  disabled={saving}
                  onChange={(event) => set({ region: event.target.value })}
                />
                <Input
                  aria-label={m.init_endpoint()}
                  value={storage.endpoint}
                  disabled={saving}
                  onChange={(event) => set({ endpoint: event.target.value })}
                />
                <label>
                  <input
                    type="checkbox"
                    checked={storage.path_style}
                    disabled={saving}
                    onChange={(event) => set({ path_style: event.target.checked })}
                  />{" "}
                  {m.init_pathStyle()}
                </label>
              </>
            )}
            {storage.url.startsWith("oci://") && (
              <label>
                <input
                  type="checkbox"
                  checked={storage.plain_http}
                  disabled={saving}
                  onChange={(event) => set({ plain_http: event.target.checked })}
                />{" "}
                {m.init_plainHttp()}
              </label>
            )}
            <label>
              <input
                type="checkbox"
                checked={paused}
                disabled={saving}
                onChange={(event) => setPaused(event.target.checked)}
              />{" "}
              {m.storage_writesPaused()}
            </label>
            <Button
              type="submit"
              loading={saving}
              disabled={
                !paused ||
                !storage.url.trim() ||
                JSON.stringify(storage) === JSON.stringify(original)
              }
            >
              {m.storage_migrate()}
            </Button>
          </VStack>
        </styled.form>
      )}
    </Section>
  );
}
