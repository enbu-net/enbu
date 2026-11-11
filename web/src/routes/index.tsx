import { createFileRoute } from "@tanstack/react-router";
import { VStack } from "styled-system/jsx";
import { Spinner, Text } from "../components/ui";
import { PageCenter } from "../components/layout";
import { SignIn } from "../features/auth/sign-in";
import { Dashboard } from "../features/dashboard/dashboard";
import { RepositorySetup, setupStep } from "../features/repository/repository-setup";
import { Welcome } from "../features/repository/welcome";
import { useSession } from "../lib/session";
import { m } from "../paraglide/messages";

export const Route = createFileRoute("/")({
  component: HomePage,
});

/**
 * Leads the person through each step enbu needs, in order: choose a
 * repository on the welcome screen, sign in when its storage is on GHCR, set
 * it up, then work in the dashboard.
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
  if (!repo.path) return <Welcome />;
  // A workspace stored outside GHCR needs no GitHub sign-in.
  if (!status?.authenticated && !status?.workspace_configured) return <SignIn />;
  const step = setupStep(repo);
  if (step) return <RepositorySetup key={step} step={step} />;
  return <Dashboard key={repo.path} repo={repo} />;
}
