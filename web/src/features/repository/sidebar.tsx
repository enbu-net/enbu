import {
  type RefObject,
  useCallback,
  useEffect,
  useEffectEvent,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { Plus, Settings, Trash2 } from "lucide-react";
import { Box, VStack, styled } from "styled-system/jsx";
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

  // The menu is a popover, which closes itself on Esc and outside clicks; it
  // sits at the pointer, so it closes when the page under it moves.
  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
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
            if (next.selected) {
              setRepo(next);
              if (settingsOpen) onCloseSettings();
            }
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
            <styled.button
              key={item.path}
              type="button"
              data-repository-path={item.path}
              aria-current={isActive ? "true" : undefined}
              display="flex"
              alignItems="center"
              w="full"
              textAlign="start"
              px="2"
              py="9px"
              borderRadius="lg"
              borderWidth="1px"
              borderColor={isActive ? "accent.border" : "transparent"}
              bg={isActive ? "accent.subtle" : undefined}
              color="fg.default"
              _hover={{ bg: isActive ? "accent.subtle" : "bg.muted" }}
              _focusVisible={{
                outline: "2px solid",
                outlineColor: "accent.default",
                outlineOffset: "2px",
              }}
              cursor={isActive ? "default" : "pointer"}
              title={item.path}
              onContextMenu={(event) => {
                event.preventDefault();
                removeTriggerRef.current = event.currentTarget;
                // The context menu key and Shift+F10 report no pointer position.
                const rect = event.currentTarget.getBoundingClientRect();
                const keyboard = event.clientX === 0 && event.clientY === 0;
                const x = keyboard ? rect.left + 16 : event.clientX;
                const y = keyboard ? rect.bottom : event.clientY;
                setContextMenu({
                  repo: item,
                  x: Math.max(8, Math.min(x, window.innerWidth - 180)),
                  y: Math.max(8, Math.min(y, window.innerHeight - 56)),
                });
              }}
              onClick={() => {
                if (!isActive) void select(item.path ?? "");
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
            </styled.button>
          );
        })}
      </VStack>
      {contextMenu && (
        <RepositoryContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          removing={removingRepository}
          returnFocusRef={removeTriggerRef}
          onDismiss={() => setContextMenu(null)}
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

/**
 * The right-click menu of a repository: a popover at the pointer, so the
 * browser closes it on Esc and outside clicks. It opens from the context menu
 * key and Shift+F10 too, with focus on its first item.
 */
export function RepositoryContextMenu({
  x,
  y,
  removing,
  returnFocusRef,
  onDismiss = () => {},
  onRemove,
}: {
  x: number;
  y: number;
  removing: boolean;
  /** Where focus goes when the menu closes without an action. */
  returnFocusRef?: RefObject<HTMLElement | null>;
  onDismiss?: () => void;
  onRemove: () => void | Promise<void>;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const handleDismiss = useEffectEvent(() => onDismiss());

  useLayoutEffect(() => {
    const menu = ref.current;
    if (!menu) return;
    const state = { shown: true };
    menu.showPopover();
    menu.querySelector("button")?.focus();
    const onToggle = (event: Event) => {
      if ((event as ToggleEvent).newState !== "closed") return;
      state.shown = false;
      if (menu.contains(document.activeElement) || document.activeElement === document.body) {
        returnFocusRef?.current?.focus();
      }
      handleDismiss();
    };
    menu.addEventListener("toggle", onToggle);
    return () => {
      menu.removeEventListener("toggle", onToggle);
      if (state.shown) menu.hidePopover();
    };
  }, [returnFocusRef]);

  return (
    <Box
      ref={ref}
      popover="auto"
      aria-label={m.sidebar_repositoryOptions()}
      position="fixed"
      inset="auto"
      m="0"
      style={{ left: x, top: y }}
      minW="168px"
      p="1"
      color="fg.default"
      bg="bg.surface"
      borderWidth="1px"
      borderColor="border.default"
      borderRadius="lg"
      boxShadow="dropdown"
    >
      <Button
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
