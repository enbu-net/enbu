import { useEffect, useState, type ReactNode } from "react";
import { Braces, ListTree } from "lucide-react";
import { Box, Flex, VStack, styled } from "styled-system/jsx";
import { Button, Input, Text } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { LanguageSelector } from "../../components/language-selector";
import { SectionHeader } from "../../components/layout";
import { ThemeSelector } from "../../components/theme-selector";
import { displayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import {
  clipboardClearRange,
  fontSizeRange,
  getSettings,
  parseSettings,
  themePreferences,
  updateSettings,
  useSettings,
  type Settings,
} from "../../lib/settings";
import { m } from "../../paraglide/messages";
import { getLocale, locales, setLocale, type Locale } from "../../paraglide/runtime";
import { AccountList } from "./account-list";
import { Section } from "./section";
import { SettingsJsonEditor } from "./settings-json-editor";
import { StorageSection } from "./storage-section";
import { UpdateSection } from "./update-section";

/** What the JSON view shows: the settings and the language, in one object. */
export type SettingsDocument = Settings & { language: Locale };

export function settingsDocument(settings: Settings, language: Locale): string {
  const document: SettingsDocument = {
    theme: settings.theme,
    language,
    fontSize: settings.fontSize,
    clipboardClearSeconds: settings.clipboardClearSeconds,
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * Reads the JSON view. Throws on text that is not JSON, an unknown key or a
 * bad value; a missing key takes its default and a missing language keeps the
 * current one.
 */
export function parseSettingsDocument(text: string, language: Locale): SettingsDocument {
  const value: unknown = JSON.parse(text);
  const settings = parseSettings(value, ["language"]);
  const next = (value as { language?: unknown }).language ?? language;
  if (!locales.includes(next as Locale)) throw new Error("unknown language");
  return { ...settings, language: next as Locale };
}

/** The JSON schema the editor checks against, with the same limits as the form. */
export function settingsSchema(): object {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      theme: {
        enum: [...themePreferences],
        default: "system",
        description: m.settings_themeDescription(),
      },
      language: { enum: [...locales], description: m.settings_languageDescription() },
      fontSize: {
        type: "integer",
        minimum: fontSizeRange.min,
        maximum: fontSizeRange.max,
        default: 14,
        description: m.settings_fontSizeDescription(),
      },
      clipboardClearSeconds: {
        type: "integer",
        minimum: clipboardClearRange.min,
        maximum: clipboardClearRange.max,
        default: 30,
        description: m.settings_clipboardClearDescription(),
      },
    },
  };
}

function Row({ label, hint, children }: { label: ReactNode; hint?: string; children: ReactNode }) {
  return (
    <Flex
      align="center"
      justify="space-between"
      gap="4"
      px="3.5"
      py="3"
      borderTopWidth="1px"
      borderColor="border.default"
      _first={{ borderTopWidth: "0" }}
      flexWrap="wrap"
    >
      <Box minW="0">
        {label}
        {hint && (
          <Text fontSize="xs" color="fg.muted">
            {hint}
          </Text>
        )}
      </Box>
      {children}
    </Flex>
  );
}

function Card({ children }: { children: ReactNode }) {
  return (
    <Box borderWidth="1px" borderColor="border.default" borderRadius="lg" bg="bg.surface">
      {children}
    </Box>
  );
}

/**
 * A number field that saves a whole number within range as it is typed, and
 * shows the saved value again when it loses focus with anything else.
 */
function NumberSetting({
  id,
  value,
  range,
  onCommit,
}: {
  id: string;
  value: number;
  range: { min: number; max: number };
  onCommit: (value: number) => void;
}) {
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  const commit = (next: string) => {
    const number = Number(next);
    if (
      next.trim() !== "" &&
      Number.isInteger(number) &&
      number >= range.min &&
      number <= range.max
    )
      onCommit(number);
  };
  return (
    <Input
      id={id}
      type="number"
      inputMode="numeric"
      min={range.min}
      max={range.max}
      step={1}
      value={text}
      w="96px"
      h="auto"
      minH="34px"
      onChange={(event) => {
        setText(event.target.value);
        commit(event.target.value);
      }}
      onBlur={() => setText(String(value))}
    />
  );
}

function Label({ htmlFor, children }: { htmlFor: string; children: ReactNode }) {
  return (
    <styled.label htmlFor={htmlFor} fontSize="sm" fontWeight="medium">
      {children}
    </styled.label>
  );
}

function SettingsForm({
  settings,
  version,
  onAddAccount,
}: {
  settings: Settings;
  version: string;
  onAddAccount: () => void;
}) {
  return (
    <VStack alignItems="stretch" gap="8">
      <AccountList onAddAccount={onAddAccount} />
      <StorageSection />

      <Section title={m.settings_display()}>
        <Card>
          <Row label={<Label htmlFor="theme-select">{m.theme_label()}</Label>}>
            <ThemeSelector label={false} />
          </Row>
          <Row label={<Label htmlFor="language-select">{m.app_language()}</Label>}>
            <LanguageSelector label={false} />
          </Row>
          <Row
            label={<Label htmlFor="font-size">{m.settings_fontSize()}</Label>}
            hint={m.settings_fontSizeHint({ min: fontSizeRange.min, max: fontSizeRange.max })}
          >
            <NumberSetting
              id="font-size"
              value={settings.fontSize}
              range={fontSizeRange}
              onCommit={(fontSize) => updateSettings({ fontSize })}
            />
          </Row>
        </Card>
      </Section>

      <Section title={m.settings_security()}>
        <Card>
          <Row
            label={<Label htmlFor="clipboard-clear">{m.settings_clipboardClear()}</Label>}
            hint={m.settings_clipboardClearHint()}
          >
            <NumberSetting
              id="clipboard-clear"
              value={settings.clipboardClearSeconds}
              range={clipboardClearRange}
              onCommit={(clipboardClearSeconds) => updateSettings({ clipboardClearSeconds })}
            />
          </Row>
        </Card>
      </Section>

      <Section title={m.settings_about()}>
        <Card>
          <Row label={<Text fontSize="sm">{m.settings_version()}</Text>}>
            <Text fontSize="sm" fontFamily="mono" color="fg.muted">
              {version || "-"}
            </Text>
          </Row>
          <Row label={<Text fontSize="sm">{m.update_title()}</Text>}>
            <Box flex="1" minW="240px">
              <UpdateSection />
            </Box>
          </Row>
        </Card>
      </Section>
    </VStack>
  );
}

/**
 * The settings of this app on this device: accounts, display, clipboard and
 * version. Like VS Code, the same settings open as JSON with one button.
 */
export function SettingsPage({ onAddAccount }: { onAddAccount: () => void }) {
  const settings = useSettings();
  const [view, setView] = useState<"form" | "json">("form");
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<DisplayError | null>(null);
  const [version, setVersion] = useState("");

  useEffect(() => {
    backend
      .GetAppVersion()
      .then(setVersion)
      .catch(() => {});
  }, []);

  /** Applies the JSON view; returns whether it was valid. */
  function applyDraft(): boolean {
    let next: SettingsDocument;
    try {
      next = parseSettingsDocument(draft, getLocale());
    } catch (err) {
      console.error("invalid settings", err);
      setError(displayError("invalid_argument"));
      return false;
    }
    setError(null);
    const { language, ...rest } = next;
    updateSettings(rest);
    // Switching the language reloads the page, so it goes last.
    if (language !== getLocale()) void setLocale(language);
    return true;
  }

  return (
    <Box
      minH="calc(100vh - 72px)"
      px={{ base: "4", md: "7", lg: "12" }}
      py={{ base: "7", lg: "10" }}
      bg="bg.page"
    >
      <Box maxW="760px" mx="auto">
        <SectionHeader title={m.settings_title()}>
          <Button
            size="sm"
            variant="outline"
            aria-pressed={view === "json"}
            onClick={() => {
              if (view === "json") {
                if (applyDraft()) setView("form");
              } else {
                setDraft(settingsDocument(getSettings(), getLocale()));
                setError(null);
                setView("json");
              }
            }}
          >
            {view === "json" ? <ListTree size={15} /> : <Braces size={15} />}
            {view === "json" ? m.settings_openForm() : m.settings_openJson()}
          </Button>
        </SectionHeader>
        {error && (
          <Box mb="4">
            <ErrorAlert error={error} onDismiss={() => setError(null)} />
          </Box>
        )}
        {view === "json" ? (
          <SettingsJsonEditor
            value={draft}
            schema={settingsSchema()}
            fontSize={Math.max(fontSizeRange.min, settings.fontSize - 1)}
            onChange={setDraft}
            onSave={() => void applyDraft()}
          />
        ) : (
          <SettingsForm settings={settings} version={version} onAddAccount={onAddAccount} />
        )}
      </Box>
    </Box>
  );
}
