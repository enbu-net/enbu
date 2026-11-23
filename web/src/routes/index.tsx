import { createFileRoute } from "@tanstack/react-router";
import { VStack } from "styled-system/jsx";
import { Spinner, Text } from "../components/ui";
import { PageCenter } from "../components/layout";
import { SignIn } from "../features/auth/sign-in";
import { ErrorAlert } from "../components/error-alert";
import { toDisplayError } from "../lib/app-error";
import { ConfigPanel } from "../features/config/config-panel";
import { Dashboard } from "../features/dashboard/dashboard";
import { RepositorySetup, setupStep } from "../features/repository/repository-setup";
import { Welcome } from "../features/repository/welcome";
import { useSession } from "../lib/session";
import type { EnvInfo } from "../lib/types";
import { m } from "../paraglide/messages";

const repairEnvironments: EnvInfo[] = [];

export const Route = createFileRoute("/")({
  component: HomePage,
});

/**
 * Leads the person through each step enbu needs, in order: choose a
 * repository on the welcome screen, sign in when its storage is on GHCR, set
 * it up, then work in the dashboard.
 */
export function HomePage() {
  const { status, loading, repo, reloadRepo, refresh } = useSession();

  if (loading || !repo) {
    return (
      <PageCenter>
        <VStack gap={3} role="status">
          <Spinner size="xl" color="accent.default" />
          <Text color="fg.muted">{m.common_loading()}</Text>
        </VStack>
      </PageCenter>
    );
  }
  if (!repo.path) return <Welcome />;
  if (repo.config_error) {
    return (
      <PageCenter>
        <VStack w="full" maxW="900px" alignItems="stretch">
          <ErrorAlert error={toDisplayError(repo.config_error)} />
          <ConfigPanel
            key={repo.path}
            environments={repairEnvironments}
            onSaved={async () => {
              await refresh({ force: true, invalidate: true });
              await reloadRepo();
            }}
          />
        </VStack>
      </PageCenter>
    );
  }
  const step = setupStep(repo);
  // An unconfigured workspace must choose storage before we know whether it
  // needs a GitHub account.
  if (step !== "found" && !status?.authenticated && !status?.workspace_configured) {
    return <SignIn />;
  }
  if (step)
    return (
      <RepositorySetup
        key={JSON.stringify([repo.path, step])}
        step={step}
        storageDraft={repo.storage_draft ?? undefined}
      />
    );
  return <Dashboard key={repo.path} repo={repo} />;
}
