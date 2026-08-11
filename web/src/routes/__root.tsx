import { Outlet, createRootRoute } from "@tanstack/react-router";
import { Flex, styled } from "styled-system/jsx";
import { Text } from "../components/ui";
import { LanguageSelector } from "../components/language-selector";
import { UserErrorGate } from "../components/user-error-gate";
import { I18nProvider } from "../lib/i18n";

export const Route = createRootRoute({ component: Root });

function Root() {
  return (
    <I18nProvider>
      <UserErrorGate>
        <styled.header
          display="flex"
          h="72px"
          alignItems="center"
          justifyContent="space-between"
          px={{ base: "4", md: "6" }}
          bg="bg.surface"
          borderBottomWidth="1px"
          borderColor="border.default"
        >
          <Flex align="center" gap="2">
            <Text as="span" fontSize="2xl" aria-hidden="true">
              💃
            </Text>
            <Text fontWeight="extrabold" fontSize="2xl">
              enbu
            </Text>
          </Flex>
          <LanguageSelector />
        </styled.header>
        <Outlet />
      </UserErrorGate>
    </I18nProvider>
  );
}
