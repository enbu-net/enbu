import type { ReactNode } from "react";
import { Box } from "styled-system/jsx";
import { Tabs, Text } from "../../components/ui";

export function DashboardTab({
  value,
  icon,
  label,
}: {
  value: string;
  icon: ReactNode;
  label: string;
}) {
  return (
    <Tabs.Trigger
      value={value}
      aria-label={label}
      flex="1"
      minW="0"
      h={{ base: "48px", sm: "42px" }}
      px={{ base: "1.5", sm: "3" }}
      display="flex"
      alignItems="center"
      justifyContent="center"
      gap="2"
      color="fg.muted"
      bg="transparent"
      borderWidth="0"
      borderRadius="0"
      fontSize={{ base: "2xs", sm: "sm" }}
      fontWeight="semibold"
      position="relative"
      _after={{
        content: '""',
        position: "absolute",
        left: "3",
        right: "3",
        bottom: "0",
        h: "3px",
        bg: "transparent",
        borderRadius: "full",
      }}
      _selected={{
        color: "fg.default",
        bg: "transparent",
        _after: { bg: "accent.default" },
      }}
      _hover={{ color: "fg.default", bg: "transparent" }}
    >
      <Box as="span" aria-hidden="true">
        {icon}
      </Box>
      <Text as="span" display={{ base: "none", sm: "inline" }} fontSize="inherit">
        {label}
      </Text>
    </Tabs.Trigger>
  );
}

export function DashboardTabContent({ value, children }: { value: string; children: ReactNode }) {
  return (
    <Tabs.Content
      value={value}
      minH="420px"
      mt="4.5"
      p={{ base: "4", md: "7" }}
      bg="bg.surface"
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="2xl"
      boxShadow="app"
    >
      {children}
    </Tabs.Content>
  );
}
