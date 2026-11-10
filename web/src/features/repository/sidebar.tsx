import { useCallback, useEffect, useRef, useState } from "react";
import { Plus, Settings, Trash2 } from "lucide-react";
import { Box, Flex, VStack, styled } from "styled-system/jsx";
import { Button, Text } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { ErrorAlert } from "../../components/error-alert";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useSession } from "../../lib/session";
import type { RepoInfo } from "../../lib/types";
import { m } from "../../paraglide/messages";

function pathKey(path = "") {
  return path.replaceAll("\\", "/").toLowerCase();
}

/**
 * Lists the repositories enbu knows on this device and switches between them,
 * with the way to the settings at the bottom. While the settings are open,
 * picking a repository, the current one included, closes them.
 */
export function Sidebar({
  settingsOpen = false,
  onOpenSettings = () => {},
  onCloseSettings = () => {},
}: {
  settingsOpen?: boolean;
  onOpenSettings?: () => void;
  onCloseSettings?: () => void;
}) {
  const { repo, setRepo } = useSession();
  const activePath = repo?.repo?.path ?? "";
  const [repos, setRepos] = useState<RepoInfo[]>([]);
  const [error, setError] = useState<DisplayError | null>(null);
  const [addLoading, setAddLoading] = useState(false);
  const [removingRepository, setRemovingRepository] = useState(false);
  const [repositoryPendingRemoval, setRepositoryPendingRemoval] = useState<RepoInfo | null>(null);
  const removeTriggerRef = useRef<HTMLElement>(null);
  const [contextMenu, setContextMenu] = useState<{
    repo: RepoInfo;
    x: number;
    y: number;
  } | null>(null);

  const loadRepos = useCallback(async () => {
    try {
      const list = await backend.listRepositories();
      const seen = new Set<string>();
      setRepos(
        list.filter((item) => {
          const key = pathKey(item.path);
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        }),
      );
    } catch (err) {
      setError(toDisplayError(err));
    }
  }, []);

  // Selecting or adding a repository changes the active path and the list.
  useEffect(() => {
    void loadRepos();
  }, [loadRepos, activePath]);

  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("pointerdown", close);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("pointerdown", close);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [contextMenu]);

  async function select(path: string) {
    setError(null);
    try {
      if (path !== activePath) setRepo(await backend.selectRepository(path));
      if (settingsOpen) onCloseSettings();
    } catch (err) {
      setError(toDisplayError(err));
    }
  }

  return (
    <styled.nav
      aria-label={m.sidebar_navigation()}
      w="248px"
      h="calc(100vh - 72px)"
      position="sticky"
      top="72px"
      display={{ base: "none", md: "flex" }}
      borderRightWidth="1px"
      borderColor="border.default"
      bg="bg.surface"
      p="3.5"
      flexShrink="0"
      flexDirection="column"
    >
      <Button
        size="sm"
        variant="outline"
        w="full"
        flexShrink="0"
        borderColor="border.default"
        color="fg.default"
        fontWeight="semibold"
        loading={addLoading}
        onClick={async () => {
          setAddLoading(true);
          setError(null);
          try {
            const next = await backend.browseRepository();
            // A cancelled picker selects nothing and changes nothing.
            if (next.selected) setRepo(next);
          } catch (err) {
            setError(toDisplayError(err));
          } finally {
            setAddLoading(false);
          }
        }}
      >
        <Plus size={16} aria-hidden="true" />
        {m.sidebar_addRepository()}
      </Button>
      {error && (
        <Box mt="3">
          <ErrorAlert error={error} onDismiss={() => setError(null)} />
        </Box>
      )}
      {/* Only the list scrolls: adding stays at the top and the settings at the bottom. */}
      <VStack alignItems="stretch" gap="1" mt="3" flex="1" minH="0" overflowY="auto">
        {repos.length === 0 && (
          <Text fontSize="sm" color="fg.muted">
            {m.sidebar_noRepositories()}
          </Text>
        )}
        {repos.map((item) => {
          // The repository in use is also the way back from the settings.
          const isActive = item.path === activePath && !settingsOpen;
          return (
            <Flex
              key={item.path}
              data-repository-path={item.path}
              role={isActive ? undefined : "button"}
              tabIndex={isActive ? -1 : 0}
              aria-current={isActive ? "true" : undefined}
              alignItems="center"
              px="2"
              py="9px"
              borderRadius="lg"
              borderWidth="1px"
              borderColor={isActive ? "accent.border" : "transparent"}
              bg={isActive ? "accent.subtle" : undefined}
              _hover={{ bg: isActive ? "accent.subtle" : "bg.muted" }}
              cursor={isActive ? "default" : "pointer"}
              title={item.path}
              onContextMenu={(event) => {
                event.preventDefault();
                removeTriggerRef.current = event.currentTarget;
                setContextMenu({
                  repo: item,
                  x: Math.max(8, Math.min(event.clientX, window.innerWidth - 180)),
                  y: Math.max(8, Math.min(event.clientY, window.innerHeight - 56)),
                });
              }}
              onClick={() => {
                if (!isActive) void select(item.path ?? "");
              }}
              onKeyDown={(event) => {
                if (isActive) return;
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  void select(item.path ?? "");
                }
              }}
            >
              <Text
                minW="0"
                flex="1"
                fontSize="sm"
                fontWeight={isActive ? "semibold" : "normal"}
                truncate
              >
                {item.owner ? `${item.owner}/${item.repo}` : item.path}
              </Text>
            </Flex>
          );
        })}
      </VStack>
      {contextMenu && (
        <RepositoryContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          removing={removingRepository}
          onRemove={() => {
            setRepositoryPendingRemoval(contextMenu.repo);
            setContextMenu(null);
          }}
        />
      )}
      <ConfirmDeleteDialog
        open={repositoryPendingRemoval != null}
        title={m.sidebar_removeConfirm({
          repository: repositoryPendingRemoval
            ? repositoryPendingRemoval.owner
              ? `${repositoryPendingRemoval.owner}/${repositoryPendingRemoval.repo}`
              : (repositoryPendingRemoval.path ?? "")
            : "",
        })}
        cancelLabel={m.config_cancel()}
        confirmLabel={m.sidebar_remove()}
        loading={removingRepository}
        triggerRef={removeTriggerRef}
        onClose={() => setRepositoryPendingRemoval(null)}
        onConfirm={async () => {
          if (!repositoryPendingRemoval) return;
          const removedPath = repositoryPendingRemoval.path ?? "";
          setRemovingRepository(true);
          setError(null);
          try {
            await backend.removeRepository(removedPath);
            setRepos((current) =>
              current.filter((item) => pathKey(item.path) !== pathKey(removedPath)),
            );
            setRepositoryPendingRemoval(null);
            if (pathKey(removedPath) === pathKey(activePath)) {
              setRepo(await backend.repoStatus());
            }
            await loadRepos();
          } catch (err) {
            setRepositoryPendingRemoval(null);
            setError(toDisplayError(err));
          } finally {
            setRemovingRepository(false);
          }
        }}
      />
      <Button
        mt="3"
        flexShrink="0"
        size="sm"
        variant="ghost"
        w="full"
        justifyContent="start"
        color="fg.default"
        aria-current={settingsOpen ? "page" : undefined}
        bg={settingsOpen ? "accent.subtle" : undefined}
        onClick={onOpenSettings}
      >
        <Settings size={16} aria-hidden="true" />
        {m.settings_title()}
      </Button>
    </styled.nav>
  );
}

export function RepositoryContextMenu({
  x,
  y,
  removing,
  onRemove,
}: {
  x: number;
  y: number;
  removing: boolean;
  onRemove: () => void | Promise<void>;
}) {
  return (
    <Box
      role="menu"
      aria-label={m.sidebar_repositoryOptions()}
      position="fixed"
      style={{ left: x, top: y }}
      zIndex="40"
      minW="168px"
      p="1"
      bg="bg.surface"
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="lg"
      boxShadow="dropdown"
      onPointerDown={(event) => event.stopPropagation()}
    >
      <Button
        role="menuitem"
        type="button"
        variant="ghost"
        w="full"
        justifyContent="start"
        color="status.danger"
        loading={removing}
        onClick={() => void onRemove()}
      >
        <Trash2 size={15} aria-hidden="true" />
        {m.sidebar_remove()}
      </Button>
    </Box>
  );
}
