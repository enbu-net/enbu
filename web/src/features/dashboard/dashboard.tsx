import type { ReactNode } from "react";
import { History, KeyRound, Layers3, SlidersHorizontal, Users } from "lucide-react";
import { SiGithub } from "@icons-pack/react-simple-icons";
import { Box, Flex, styled } from "styled-system/jsx";
import { Heading, Tabs } from "../../components/ui";
import { ErrorAlert } from "../../components/error-alert";
import { openURL } from "../../lib/platform";
import { folderName } from "../../lib/paths";
import type { RepoInfo } from "../../lib/types";
import { EnvironmentsTab } from "../environments/environments-tab";
import { HistoryTab } from "../history/history-tab";
import { MembersTab } from "../members/members-tab";
import { SecretsTab } from "../secrets/secrets-tab";
import { ConfigPanel } from "../settings/config-panel";
import { DashboardTab, DashboardTabContent } from "./dashboard-tabs";
import { m } from "../../paraglide/messages";
import { useTransfer, type RunTransfer } from "./use-transfer";
import { useWorkspace, type Workspace } from "./use-workspace";

type TabContext = { repo: RepoInfo; workspace: Workspace; transfer: RunTransfer };

/** A dashboard tab. A new tab is one more entry in tabs. */
type DashboardTabDefinition = {
  value: string;
  label: () => string;
  icon: ReactNode;
  render: (context: TabContext) => ReactNode;
};

const tabs: DashboardTabDefinition[] = [
  {
    value: "secrets",
    label: m.dashboard_secrets,
    icon: <KeyRound size={16} />,
    render: ({ workspace, transfer }) => <SecretsTab workspace={workspace} transfer={transfer} />,
  },
  {
    value: "environments",
    label: m.dashboard_environments,
    icon: <Layers3 size={16} />,
    render: ({ workspace }) => <EnvironmentsTab workspace={workspace} />,
  },
  {
    value: "history",
    label: m.history_title,
    icon: <History size={16} />,
    render: ({ workspace }) => <HistoryTab workspace={workspace} />,
  },
  {
    value: "members",
    label: m.members_title,
    icon: <Users size={16} />,
    render: ({ repo, workspace, transfer }) => (
      <MembersTab
        repoPath={repo.path ?? ""}
        environment={workspace.currentEnvironment}
        transfer={transfer}
      />
    ),
  },
  {
    value: "settings",
    label: m.config_settings,
    icon: <SlidersHorizontal size={16} />,
    render: ({ workspace }) => <ConfigPanel environments={workspace.environments} />,
  },
];

/** The secrets, environments, history, members and settings of a repository enbu manages. */
export function Dashboard({ repo }: { repo: RepoInfo }) {
  const workspace = useWorkspace(repo.path ?? "");
  const transfer = useTransfer();
  const context: TabContext = { repo, workspace, transfer: transfer.run };

  return (
    <Box
      minH="calc(100vh - 72px)"
      px={{ base: "4", md: "7", lg: "12" }}
      py={{ base: "7", lg: "10" }}
      bg="bg.muted"
    >
      <Box maxW="1120px" mx="auto">
        <Flex align={{ base: "start", sm: "center" }} justify="space-between" gap="4" mb="7">
          <RepositoryTitle repo={repo} />
        </Flex>

        {workspace.error && (
          <Box mb="4">
            <ErrorAlert error={workspace.error} onDismiss={() => workspace.setError(null)} />
          </Box>
        )}

        <Tabs.Root defaultValue={tabs[0].value} lazyMount unmountOnExit variant="line">
          <Tabs.List w="full" h="auto" display="flex" gap="0" overflow="hidden">
            {tabs.map((tab) => (
              <DashboardTab key={tab.value} value={tab.value} icon={tab.icon} label={tab.label()} />
            ))}
          </Tabs.List>
          {tabs.map((tab) => (
            <DashboardTabContent key={tab.value} value={tab.value}>
              {tab.render(context)}
            </DashboardTabContent>
          ))}
        </Tabs.Root>
        {transfer.modal}
      </Box>
    </Box>
  );
}

/**
 * The repository's name; it opens the repository on GitHub when it has a
 * GitHub remote.
 */
function RepositoryTitle({ repo }: { repo: RepoInfo }) {
  const name = repo.owner && repo.repo ? `${repo.owner}/${repo.repo}` : "";
  return (
    <Heading
      as="h1"
      color="fg.default"
      fontSize="3xl"
      fontWeight="extrabold"
      letterSpacing="tight"
      title={repo.path}
    >
      {name ? (
        <styled.button
          type="button"
          display="inline-flex"
          alignItems="center"
          gap="2.5"
          cursor="pointer"
          font="inherit"
          color="inherit"
          _hover={{ textDecoration: "underline" }}
          onClick={() => openURL(`https://github.com/${name}`)}
        >
          <SiGithub size={24} aria-hidden="true" />
          {name}
        </styled.button>
      ) : (
        folderName(repo.path)
      )}
    </Heading>
  );
}
