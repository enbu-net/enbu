import { useEffect, useRef, useState } from "react";
import { Box, styled } from "styled-system/jsx";
import { Button, Popover, Separator, Text } from "../../components/ui";
import { LanguageSelector } from "../../components/language-selector";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import { useSession } from "../../lib/session";

export function AccountMenu() {
  const { t } = useI18n();
  const { status, loading, refresh } = useSession();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const [appVersion, setAppVersion] = useState("");

  useEffect(() => {
    backend
      .appVersion()
      .then(setAppVersion)
      .catch(() => {});
  }, []);

  const authenticated = Boolean(status?.authenticated);
  const username = status?.username ?? "";
  const initial = username.slice(0, 1).toUpperCase() || (loading ? "…" : "-");
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <Button
          ref={triggerRef}
          variant="ghost"
          w="38px"
          h="38px"
          p="0"
          borderRadius="full"
          aria-label={t("auth.accountMenu")}
          _hover={{ bg: "bg.muted", borderWidth: "1px", borderColor: "border.default" }}
        >
          <Box position="relative" w="32px" h="32px" flexShrink="0">
            {authenticated && username ? (
              <img
                src={`https://avatars.githubusercontent.com/${username}?size=64`}
                width={32}
                height={32}
                style={{ borderRadius: "50%", position: "absolute", top: 0, left: 0 }}
                onError={(e) => {
                  e.currentTarget.style.display = "none";
                  const fallback = e.currentTarget.nextElementSibling as HTMLElement | null;
                  if (fallback) fallback.style.display = "grid";
                }}
                alt={username}
              />
            ) : null}
            <Box
              w="32px"
              h="32px"
              borderRadius="full"
              bg={authenticated ? "accent.default" : "bg.muted"}
              color={authenticated ? "white" : "fg.muted"}
              fontSize="sm"
              fontWeight="extrabold"
              display={authenticated && username ? "none" : "grid"}
              placeItems="center"
              position="absolute"
              top="0"
              left="0"
            >
              {initial}
            </Box>
          </Box>
        </Button>
      </Popover.Trigger>

      <Popover.Positioner>
        <Popover.Content
          w="248px"
          p="3"
          borderWidth="1px"
          borderColor="border.default"
          borderRadius="lg"
          boxShadow="dropdown"
          bg="bg.surface"
        >
          {/* Account name */}
          <Box pb="2" mb="1" borderBottomWidth="1px" borderColor="border.default">
            {authenticated ? (
              <styled.a
                href={`https://github.com/${username}`}
                target="_blank"
                rel="noopener noreferrer"
                fontWeight="bold"
                fontSize="sm"
                color="fg.default"
                _hover={{ textDecoration: "underline", color: "accent.default" }}
              >
                {username}
              </styled.a>
            ) : (
              <Text fontWeight="bold" fontSize="sm">
                {t("auth.account")}
              </Text>
            )}
          </Box>

          <LanguageSelector justifyContent="space-between" py="10px" />

          {authenticated && (
            <>
              <Separator mb="2" />
              <Button
                size="sm"
                variant="outline"
                w="full"
                borderColor="border.default"
                color="fg.default"
                fontWeight="semibold"
                onClick={async () => {
                  try {
                    await backend.logout();
                  } catch (err) {
                    console.error("logging out failed", err);
                  }
                  await refresh({ force: true });
                }}
              >
                {t("auth.logout")}
              </Button>
            </>
          )}
          {appVersion && (
            <>
              <Separator mt="2" />
              <Text fontSize="2xs" color="fg.subtle" textAlign="right" pt="2">
                {appVersion}
              </Text>
            </>
          )}
        </Popover.Content>
      </Popover.Positioner>
    </Popover.Root>
  );
}
