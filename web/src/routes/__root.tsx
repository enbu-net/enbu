import { createRootRoute, Outlet } from "@tanstack/react-router";
import { Box, Flex, styled } from "styled-system/jsx";
import { Text } from "../components/ui";
import { UserErrorGate } from "../components/user-error-gate";
import { AccountMenu } from "../features/auth/account-menu";
import { Sidebar } from "../features/repository/sidebar";
import { I18nProvider } from "../lib/i18n";
import { SessionProvider, useSession } from "../lib/session";

export const Route = createRootRoute({
  component: RootWithProviders,
});

function RootWithProviders() {
  return (
    <I18nProvider>
      <UserErrorGate>
        <SessionProvider>
          <RootLayout />
        </SessionProvider>
      </UserErrorGate>
    </I18nProvider>
  );
}

function RootLayout() {
  const { loading } = useSession();
  return (
    <>
      <styled.header
        display="flex"
        h="72px"
        alignItems="center"
        justifyContent="space-between"
        px={{ base: "4", md: "5.5" }}
        bg="bg.surface"
        borderBottomWidth="1px"
        borderColor="border.default"
        position="sticky"
        top="0"
        zIndex="10"
      >
        <Flex align="center" gap="2">
          <Text as="span" fontSize="2xl" aria-hidden="true">
            💃
          </Text>
          <Text fontWeight="extrabold" fontSize="2xl" letterSpacing="tight">
            enbu
          </Text>
        </Flex>
        <AccountMenu />
      </styled.header>
      <Flex minH="calc(100vh - 72px)">
        {!loading && <Sidebar />}
        <Box flex="1" minW="0">
          <Outlet />
        </Box>
      </Flex>
    </>
  );
}
