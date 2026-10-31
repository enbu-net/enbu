import { useCallback, useEffect, useId, useState, type ReactNode } from "react";
import { Code2, ListTree } from "lucide-react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Spinner, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { SectionHeader } from "../../components/layout";
import { TomlCodeEditor } from "../../components/toml-code-editor";
import { displayError, toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { Environment } from "../../lib/types";
import { parseConfigDraft, serializeConfigDraft, type EnbuConfigDraft } from "./config-draft";
import { m } from "../../paraglide/messages";

export function ConfigPanel({ environments }: { environments: Environment[] }) {
  const defaultEnvId = useId();
  const [content, setContent] = useState("");
  const [draft, setDraft] = useState("");
  const [gui, setGui] = useState<EnbuConfigDraft>();
  const [view, setView] = useState<"gui" | "code">("gui");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<DisplayError | null>(null);
  const [saveError, setSaveError] = useState<DisplayError | null>(null);

  const load = useCallback(async () => {
    try {
      const text = await backend.readConfig();
      setContent(text ?? "");
      setDraft(text ?? "");
      setGui(parseConfigDraft(text ?? "", environments));
      setLoadError(null);
    } catch (err) {
      setLoadError(toDisplayError(err));
    } finally {
      setLoading(false);
    }
  }, [environments]);

  useEffect(() => {
    void load();
  }, [load]);

  const updateGui = (next: EnbuConfigDraft) => {
    setGui(next);
    setDraft(serializeConfigDraft(next));
    setSaveError(null);
  };

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      await backend.writeConfig(draft);
      setContent(draft);
    } catch (err) {
      setSaveError(toDisplayError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SectionHeader title={m.config_settings()}>
        <HStack gap="2">
          <Button
            size="sm"
            variant="outline"
            aria-pressed={view === "code"}
            onClick={() => {
              if (view === "code") {
                try {
                  setGui(parseConfigDraft(draft, environments));
                  setView("gui");
                  setSaveError(null);
                } catch (err) {
                  console.error("invalid TOML", err);
                  setSaveError(displayError("invalid_argument"));
                }
              } else setView("code");
            }}
          >
            {view === "code" ? <ListTree size={15} /> : <Code2 size={15} />}
            {view === "code" ? m.config_guiView() : m.config_codeView()}
          </Button>
          {view === "gui" && (
            <Button
              size="sm"
              colorPalette="accent"
              loading={saving}
              disabled={draft === content}
              onClick={() => void save()}
            >
              {m.config_save()}
            </Button>
          )}
        </HStack>
      </SectionHeader>
      {loadError && (
        <Box mb="4">
          <ErrorAlert error={loadError} onDismiss={() => setLoadError(null)} />
        </Box>
      )}
      {saveError && (
        <Box mb="4">
          <ErrorAlert error={saveError} onDismiss={() => setSaveError(null)} />
        </Box>
      )}
      {loading ? (
        <HStack role="status" py="8" justify="center">
          <Spinner size="sm" aria-hidden="true" />
          <Text color="fg.muted">{m.common_loading()}</Text>
        </HStack>
      ) : view === "code" ? (
        <TomlCodeEditor
          value={draft}
          onChange={setDraft}
          saving={saving}
          onSave={() => void save()}
        />
      ) : gui ? (
        <VStack alignItems="stretch" gap="4">
          <SettingsGroup title={m.config_general()}>
            <SettingRow label={m.config_defaultEnvironment()} htmlFor={defaultEnvId}>
              <styled.select
                id={defaultEnvId}
                value={gui.default_env}
                {...settingControlStyles}
                onChange={(event) => updateGui({ ...gui, default_env: event.target.value })}
              >
                {Object.keys(gui.env).map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </styled.select>
            </SettingRow>
          </SettingsGroup>
          <SettingsGroup title={m.config_outputFileNames()}>
            {Object.entries(gui.env).map(([name, config]) => {
              const inputId = `config-output-${name}`;
              return (
                <SettingRow key={name} label={name} htmlFor={inputId}>
                  <styled.input
                    id={inputId}
                    value={config.output}
                    {...settingControlStyles}
                    onChange={(event) =>
                      updateGui({
                        ...gui,
                        // Keep the incarnation: it says where the environment is
                        // stored, and the backend refuses a config that changes it.
                        env: { ...gui.env, [name]: { ...config, output: event.target.value } },
                      })
                    }
                  />
                </SettingRow>
              );
            })}
          </SettingsGroup>
        </VStack>
      ) : null}
    </>
  );
}

const settingControlStyles = {
  w: "full",
  h: "38px",
  px: "3",
  color: "fg.default",
  bg: "bg.muted",
  borderWidth: "1px",
  borderColor: "border.default",
  borderRadius: "md",
} as const;

function SettingsGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Box overflow="hidden" borderWidth="1px" borderColor="border.default" borderRadius="xl">
      <Text
        px="4"
        py="3"
        color="fg.muted"
        bg="bg.muted"
        borderBottomWidth="1px"
        borderColor="border.default"
        fontSize="2xs"
        fontWeight="bold"
        textTransform="uppercase"
        letterSpacing="widest"
      >
        {title}
      </Text>
      {children}
    </Box>
  );
}

function SettingRow({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: ReactNode;
}) {
  return (
    <Box
      minH="60px"
      display="grid"
      gridTemplateColumns={{ base: "1fr", sm: "minmax(140px,.65fr) minmax(220px,1.35fr)" }}
      alignItems="center"
      gap={{ base: "2", sm: "6" }}
      px="4"
      py="3"
      borderBottomWidth="1px"
      borderColor="border.default"
      _last={{ borderBottomWidth: "0" }}
    >
      {htmlFor ? (
        <styled.label htmlFor={htmlFor} fontSize="sm" fontWeight="semibold">
          {label}
        </styled.label>
      ) : (
        <Text fontSize="sm" fontWeight="semibold">
          {label}
        </Text>
      )}
      {children}
    </Box>
  );
}
