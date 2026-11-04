import type { ComponentProps } from "react";
import { Flex, styled } from "styled-system/jsx";
import { NativeSelect } from "./ui/native-select";
import { getLocale, locales, setLocale, type Locale } from "../paraglide/runtime";
import { m } from "../paraglide/messages";

type LanguageSelectorProps = ComponentProps<typeof Flex>;

const localeNames: Record<Locale, string> = { en: "English", ja: "日本語" };

export function LanguageSelector(props: LanguageSelectorProps) {
  return (
    <Flex alignItems="center" gap="2" {...props}>
      <styled.label htmlFor="language-select" fontSize="sm" color="fg.muted">
        {m.app_language()}
      </styled.label>
      <NativeSelect
        id="language-select"
        value={getLocale()}
        // Switching reloads the page, which renders every message in the new locale.
        onChange={(event) => void setLocale(event.target.value as Locale)}
        style={{ width: "118px" }}
      >
        {locales.map((locale) => (
          <option key={locale} value={locale}>
            {localeNames[locale]}
          </option>
        ))}
      </NativeSelect>
    </Flex>
  );
}
