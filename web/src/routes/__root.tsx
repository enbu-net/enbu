import { createRootRoute, Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { Settings, X } from "lucide-react";
import { Flex, styled } from "styled-system/jsx";
import { Text } from "../components/ui";
import { UserErrorGate } from "../components/user-error-gate";
import { Sidebar } from "../features/repository/sidebar";
import { SessionProvider, useSession } from "../lib/session";
import { m } from "../paraglide/messages";

export const Route = createRootRoute({
  component: RootWithProviders,
});

function RootWithProviders() {
  return (
    <>
      <UserErrorGate>
        <SessionProvider>
          <RootLayout />
        </SessionProvider>
      </UserErrorGate>
    </>
  );
}

function RootLayout() {
  const { loading } = useSession();
  const navigate = useNavigate();
  const settingsOpen =
    useRouterState({ select: (state) => state.location.pathname }) === "/settings";
  return (
    <>
      {/* Past the header and the sidebar to the screen itself. */}
      <styled.a
        href="#main"
        position="absolute"
        top="2"
        left="2"
        zIndex="20"
        px="3"
        py="2"
        borderRadius="md"
        bg="bg.surface"
        color="fg.default"
        fontWeight="semibold"
        boxShadow="dropdown"
        transform="translateY(-200%)"
        _focusVisible={{ transform: "none" }}
        onClick={(event) => {
          // The router owns the URL, so focus the target without navigating.
          event.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        {m.common_skipToContent()}
      </styled.a>
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
        {/* The sidebar, which holds the settings button, is hidden on narrow windows. */}
        <styled.span display={{ base: "inline-flex", md: "none" }} color="fg.muted">
          {/* It also leads back, since the sidebar is not there to do it. */}
          <Link
            to={settingsOpen ? "/" : "/settings"}
            style={{ display: "inline-flex", color: "inherit" }}
            aria-label={settingsOpen ? m.common_close() : m.settings_title()}
            title={settingsOpen ? m.common_close() : m.settings_title()}
          >
            {settingsOpen ? (
              <X size={20} aria-hidden="true" />
            ) : (
              <Settings size={20} aria-hidden="true" />
            )}
          </Link>
        </styled.span>
      </styled.header>
      <Flex minH="calc(100vh - 72px)">
        {!loading && (
          <Sidebar
            settingsOpen={settingsOpen}
            onOpenSettings={() => void navigate({ to: "/settings" })}
            onCloseSettings={() => void navigate({ to: "/" })}
          />
        )}
        <styled.main id="main" tabIndex={-1} flex="1" minW="0" outline="none">
          <Outlet />
        </styled.main>
      </Flex>
    </>
  );
}
