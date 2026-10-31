import { createFileRoute } from "@tanstack/react-router";
import { VStack } from "styled-system/jsx";
import { Spinner, Text } from "../components/ui";
import { PageCenter } from "../components/layout";
import { SignIn } from "../features/auth/sign-in";
import { Dashboard } from "../features/dashboard/dashboard";
import {
  RepositorySelect,
  RepositorySetup,
  setupStep,
} from "../features/repository/repository-setup";
import { useSession } from "../lib/session";
import { m } from "../paraglide/messages";

export const Route = createFileRoute("/")({
  component: HomePage,
});

/**
 * Leads the person through each step enbu needs, in order: sign in, choose a
 * repository, set it up, then work in the dashboard.
 */
export function HomePage() {
  const { status, loading, repo } = useSession();

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
  // A workspace stored outside GHCR needs no GitHub sign-in.
  if (!status?.authenticated && !status?.workspace_configured) return <SignIn />;
  if (!repo.selected || !repo.repo) return <RepositorySelect />;
  const step = setupStep(repo.repo);
  if (step) return <RepositorySetup key={step} repo={repo.repo} step={step} />;
  return <Dashboard key={repo.repo.path} repo={repo.repo} />;
}
