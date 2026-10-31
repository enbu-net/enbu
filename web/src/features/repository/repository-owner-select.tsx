import { Building2, Check, ChevronDown, UserRound } from "lucide-react";
import { Box, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Popover, Spinner, Text } from "../../components/ui";
import type { RepositoryOwner } from "../../lib/types";
import { m } from "../../paraglide/messages";

export function RepositoryOwnerSelect({
  owners,
  value,
  loading,
  onChange,
}: {
  owners: RepositoryOwner[];
  value: string;
  loading: boolean;
  onChange: (owner: string) => void;
}) {
  const selected = owners.find((owner) => owner.login === value);
  const SelectedIcon = selected?.organization ? Building2 : UserRound;
  return (
    <Box>
      <styled.label htmlFor="repository-owner" display="block" fontSize="sm" mb={1.5}>
        {m.init_repositoryOwner()}
      </styled.label>
      <Popover.Root positioning={{ placement: "bottom-start", sameWidth: true, gutter: 6 }}>
        <Popover.Trigger asChild>
          <Button
            id="repository-owner"
            type="button"
            variant="outline"
            w="full"
            h="52px"
            px="3"
            justifyContent="space-between"
            borderColor="border.default"
            borderRadius="lg"
            bg="bg.surface"
            boxShadow="xs"
            disabled={loading || owners.length === 0}
            _hover={{ borderColor: "accent.default", bg: "bg.muted" }}
          >
            <HStack gap="3" minW="0">
              <Box
                w="34px"
                h="34px"
                display="grid"
                placeItems="center"
                borderRadius="md"
                bg="accent.subtle"
                color="accent.default"
                flexShrink="0"
              >
                {loading ? <Spinner size="sm" /> : <SelectedIcon size={17} />}
              </Box>
              <VStack gap="0" alignItems="start" minW="0">
                <Text fontWeight="semibold" fontSize="sm" truncate>
                  {selected?.login ?? m.common_loading()}
                </Text>
                {selected && (
                  <Text color="fg.muted" fontSize="xs">
                    {selected.organization ? m.init_organization() : m.init_personalAccount()}
                  </Text>
                )}
              </VStack>
            </HStack>
            <ChevronDown size={16} color="currentColor" />
          </Button>
        </Popover.Trigger>
        <Popover.Positioner>
          <Popover.Content
            p="1.5"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="lg"
            boxShadow="dropdown"
            bg="bg.surface"
          >
            <VStack gap="1" alignItems="stretch">
              {owners.map((owner) => {
                const OwnerIcon = owner.organization ? Building2 : UserRound;
                const active = owner.login === value;
                return (
                  <Popover.CloseTrigger key={owner.login} asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      h="48px"
                      px="2.5"
                      justifyContent="space-between"
                      borderRadius="md"
                      bg={active ? "accent.subtle" : undefined}
                      onClick={() => onChange(owner.login)}
                    >
                      <HStack gap="3">
                        <Box
                          w="30px"
                          h="30px"
                          display="grid"
                          placeItems="center"
                          borderRadius="md"
                          bg={owner.organization ? "accent.subtle" : "bg.muted"}
                          color={owner.organization ? "accent.default" : "fg.muted"}
                        >
                          <OwnerIcon size={15} />
                        </Box>
                        <Box textAlign="left">
                          <Text fontSize="sm" fontWeight="semibold">
                            {owner.login}
                          </Text>
                          <Text fontSize="xs" color="fg.muted">
                            {owner.organization ? m.init_organization() : m.init_personalAccount()}
                          </Text>
                        </Box>
                      </HStack>
                      {active && <Check size={16} />}
                    </Button>
                  </Popover.CloseTrigger>
                );
              })}
            </VStack>
          </Popover.Content>
        </Popover.Positioner>
      </Popover.Root>
    </Box>
  );
}
