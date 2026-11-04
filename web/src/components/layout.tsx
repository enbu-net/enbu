import type { ReactNode } from "react";
import { Box, Flex } from "styled-system/jsx";
import { Heading } from "./ui";

export function SectionHeader({
  title,
  children,
}: {
  title: ReactNode;
  children?: ReactNode;
}) {
  return (
    <Flex
      align={{ base: "start", sm: "center" }}
      justify="space-between"
      gap="3"
      mb="6"
      flexWrap="wrap"
    >
      <Heading size="lg" fontWeight="bold">
        {title}
      </Heading>
      {children}
    </Flex>
  );
}

export function PageCenter({ children }: { children: ReactNode }) {
  return (
    <Box minH="calc(100vh - 72px)" display="grid" placeItems="center" px={6} py={12}>
      {children}
    </Box>
  );
}
