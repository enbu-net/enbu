import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useState } from "react";
import { FolderOpen, RefreshCw, ShieldCheck } from "lucide-react";
import { Box, Flex, HStack, VStack, styled } from "styled-system/jsx";
import { Alert, Badge, Button, Heading, Spinner, Text } from "../components/ui";
import { backend } from "../lib/backend";
import { formatDisplayError, toDisplayError, type DisplayError } from "../lib/app-error";
import { useI18n } from "../lib/i18n";
import type { OpenWorkspaceResult, ResourceMetadata } from "../lib/types";

export const Route = createFileRoute("/")({ component: HomePage });

export function HomePage() {
  const { locale } = useI18n();
  const [workspace, setWorkspace] = useState<OpenWorkspaceResult | null>(null);
  const [resources, setResources] = useState<ResourceMetadata[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<DisplayError | null>(null);

  const loadResources = useCallback(async (opened: OpenWorkspaceResult) => {
    const head = opened.snapshot.frontier[0];
    if (!head) return;
    const page = await backend.listResources(opened.session_id, head);
    setResources(page.resources);
  }, []);

  const open = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const opened = await backend.browseWorkspace();
      setWorkspace(opened);
      await loadResources(opened);
    } catch (cause) {
      setError(toDisplayError(cause));
    } finally {
      setLoading(false);
    }
  }, [loadResources]);

  return (
    <styled.main maxW="1040px" mx="auto" px={{ base: "4", md: "8" }} py={{ base: "8", md: "12" }}>
      <Flex
        justify="space-between"
        gap="6"
        align={{ base: "start", md: "center" }}
        direction={{ base: "column", md: "row" }}
      >
        <Box>
          <HStack gap="2" color="accent.default" mb="2">
            <ShieldCheck size={18} />
            <Text fontSize="sm" fontWeight="semibold">
              Metadata-only workspace view
            </Text>
          </HStack>
          <Heading size="3xl">Encrypted resources</Heading>
          <Text color="fg.muted" mt="2" maxW="620px">
            The webview receives resource metadata and operation state only. Secret payloads stay
            inside the trusted Go host.
          </Text>
        </Box>
        <Button onClick={() => void open()} disabled={loading}>
          {loading ? (
            <Spinner size="sm" />
          ) : workspace ? (
            <RefreshCw size={17} />
          ) : (
            <FolderOpen size={17} />
          )}
          {workspace ? "Refresh workspace" : "Open workspace"}
        </Button>
      </Flex>

      {error && (
        <Alert.Root mt="6">
          <Alert.Description>{formatDisplayError(error, locale)}</Alert.Description>
        </Alert.Root>
      )}

      {!workspace ? (
        <Box
          mt="10"
          p="10"
          borderWidth="1px"
          borderColor="border.default"
          borderRadius="xl"
          bg="bg.surface"
          textAlign="center"
        >
          <Text color="fg.muted">Choose a workspace with the native directory picker.</Text>
        </Box>
      ) : (
        <VStack alignItems="stretch" gap="4" mt="8">
          <HStack gap="3" flexWrap="wrap">
            <Badge>{workspace.snapshot.resource_count} resources</Badge>
            <Badge>{workspace.snapshot.commit_count} commits</Badge>
            <Text fontFamily="mono" fontSize="xs" color="fg.muted">
              {workspace.snapshot.frontier[0]}
            </Text>
          </HStack>
          {resources.map((resource) => (
            <Box
              key={resource.uid}
              p="5"
              borderWidth="1px"
              borderColor="border.default"
              borderRadius="xl"
              bg="bg.surface"
            >
              <Flex justify="space-between" gap="4" align="start">
                <Box minW="0">
                  <Heading size="lg">{resource.metadata.name || "Unnamed resource"}</Heading>
                  <Text mt="1" color="fg.muted" fontSize="sm">
                    {typeof resource.schema === "string"
                      ? resource.schema
                      : `${resource.schema.group}/${resource.schema.version}/${resource.schema.kind}`}
                  </Text>
                </Box>
                <Badge>{resource.kind}</Badge>
              </Flex>
              <Text mt="4" fontFamily="mono" fontSize="xs" color="fg.muted">
                UID {resource.uid}
              </Text>
            </Box>
          ))}
        </VStack>
      )}
    </styled.main>
  );
}
