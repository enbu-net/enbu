import { type RefObject, useId, useRef } from "react";
import { Check, ChevronDown, Layers3, Plus, X } from "lucide-react";
import { Box, Flex, HStack, VStack, styled } from "styled-system/jsx";
import { Button, Heading, Input, Popover, Text } from "../../components/ui";
import { ModalDialog } from "../../components/modal-dialog";
import type { Environment } from "../../lib/types";
import { m } from "../../paraglide/messages";

export function EnvironmentSelector({
  environments,
  value,
  addTriggerRef,
  onSelect,
  onAdd,
}: {
  environments: Environment[];
  value: string;
  addTriggerRef?: RefObject<HTMLButtonElement | null>;
  onSelect: (environment: string) => void | Promise<void>;
  onAdd: () => void;
}) {
  return (
    <HStack gap="2" flexWrap="wrap">
      <Popover.Root positioning={{ placement: "bottom-start", gutter: 6 }}>
        <Popover.Trigger asChild>
          <Button
            ref={addTriggerRef}
            type="button"
            variant="outline"
            h="auto"
            minH="40px"
            px="3"
            color="fg.default"
            bg="bg.surface"
            borderColor="border.default"
            borderRadius="lg"
            fontSize="lg"
            fontWeight="extrabold"
            aria-label={m.dashboard_currentEnvironment()}
          >
            <Layers3 size={16} />
            {value}
            <ChevronDown size={15} />
          </Button>
        </Popover.Trigger>
        <Popover.Positioner>
          <Popover.Content
            minW="240px"
            p="1.5"
            bg="bg.surface"
            borderWidth="1px"
            borderColor="border.default"
            borderRadius="lg"
            boxShadow="dropdown"
          >
            <VStack alignItems="stretch" gap="1">
              {environments.map((environment) => {
                const selected = environment.name === value;
                return (
                  <Popover.CloseTrigger key={environment.name} asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      w="full"
                      justifyContent="space-between"
                      color="fg.default"
                      bg={selected ? "accent.subtle" : undefined}
                      onClick={() => void onSelect(environment.name)}
                    >
                      <HStack gap="2">
                        <Layers3 size={15} />
                        {environment.name}
                      </HStack>
                      {selected && <Check size={15} color="currentColor" />}
                    </Button>
                  </Popover.CloseTrigger>
                );
              })}
              <Box h="1px" my="1" bg="border.default" />
              <Popover.CloseTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  w="full"
                  justifyContent="start"
                  color="accent.default"
                  onClick={onAdd}
                >
                  <Plus size={15} />
                  {m.dashboard_addEnvironment()}
                </Button>
              </Popover.CloseTrigger>
            </VStack>
          </Popover.Content>
        </Popover.Positioner>
      </Popover.Root>
      <Text as="span" fontSize="xl" fontWeight="extrabold">
        {m.dashboard_secretHeadingSuffix()}
      </Text>
    </HStack>
  );
}

/** Asks for the name of a new environment, or with title and confirmLabel, a new name for one. */
export function EnvironmentNameModal({
  open,
  title,
  confirmLabel,
  value,
  loading,
  triggerRef,
  onValueChange,
  onClose,
  onCreate,
}: {
  open: boolean;
  title?: string;
  confirmLabel?: string;
  value: string;
  loading: boolean;
  triggerRef?: RefObject<HTMLElement | null>;
  onValueChange: (value: string) => void;
  onClose: () => void;
  onCreate: () => void | Promise<void>;
}) {
  const titleId = useId();
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  if (!open) return null;
  return (
    <ModalDialog
      labelledBy={titleId}
      dismissible={!loading}
      initialFocusRef={inputRef}
      returnFocusRef={triggerRef}
      onClose={onClose}
    >
      <Flex justify="space-between" align="start" gap="4" mb="5">
        <Heading id={titleId} size="lg" fontWeight="extrabold">
          {title ?? m.dashboard_createEnvironmentTitle()}
        </Heading>
        <Button
          type="button"
          variant="ghost"
          w="32px"
          h="32px"
          p="0"
          aria-label={m.config_cancel()}
          disabled={loading}
          onClick={onClose}
        >
          <X size={16} aria-hidden="true" />
        </Button>
      </Flex>
      {/* A form, so Enter submits natively, which an IME's confirming Enter does not. */}
      <styled.form
        onSubmit={(event) => {
          event.preventDefault();
          if (value.trim() && !loading) void onCreate();
        }}
      >
        <styled.label htmlFor={inputId} display="block" mb="2" fontSize="sm" fontWeight="semibold">
          {m.dashboard_environmentName()}
        </styled.label>
        <Input
          ref={inputRef}
          id={inputId}
          value={value}
          placeholder={m.dashboard_newEnvironment()}
          disabled={loading}
          onChange={(event) => onValueChange(event.target.value)}
        />
        <HStack justify="end" gap="2" mt="5">
          <Button type="button" variant="ghost" disabled={loading} onClick={onClose}>
            {m.config_cancel()}
          </Button>
          <Button type="submit" colorPalette="accent" loading={loading} disabled={!value.trim()}>
            {confirmLabel ?? m.dashboard_createEnvironment()}
          </Button>
        </HStack>
      </styled.form>
    </ModalDialog>
  );
}
