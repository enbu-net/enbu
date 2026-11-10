import type { ReactNode } from "react";
import { Flex, styled } from "styled-system/jsx";
import { Heading } from "../../components/ui";

/** A titled block of the settings screen, with an optional action at the right of the title. */
export function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <styled.section aria-label={title}>
      <Flex align="center" justify="space-between" gap="3" mb="3" minH="8">
        <Heading as="h2" size="md" fontWeight="bold">
          {title}
        </Heading>
        {action}
      </Flex>
      {children}
    </styled.section>
  );
}
