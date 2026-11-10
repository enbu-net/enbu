import type { ComponentProps } from "react";
import { Flex, styled } from "styled-system/jsx";
import { NativeSelect } from "./ui/native-select";
import { host } from "../lib/host";
import { themePreferences, useThemePreference, type ThemePreference } from "../lib/theme";
import { m } from "../paraglide/messages";

type ThemeSelectorProps = ComponentProps<typeof Flex> & {
  /** false when the caller labels the select itself (its id is theme-select). */
  label?: boolean;
};

function preferenceName(preference: ThemePreference): string {
  switch (preference) {
    case "system":
      // In VS Code, "system" follows the editor's color theme.
      return host === "vscode" ? m.theme_matchEditor() : m.theme_system();
    case "light":
      return m.theme_light();
    case "dark":
      return m.theme_dark();
  }
}

export function ThemeSelector({ label = true, ...props }: ThemeSelectorProps) {
  const [preference, setPreference] = useThemePreference();
  return (
    <Flex alignItems="center" gap="2" {...props}>
      {label && (
        <styled.label htmlFor="theme-select" fontSize="sm" color="fg.muted">
        {m.theme_label()}
      </styled.label>
      )}
      <NativeSelect
        id="theme-select"
        value={preference}
        onChange={(event) => setPreference(event.target.value as ThemePreference)}
        style={{ width: "148px" }}
      >
        {themePreferences.map((option) => (
          <option key={option} value={option}>
            {preferenceName(option)}
          </option>
        ))}
      </NativeSelect>
    </Flex>
  );
}
