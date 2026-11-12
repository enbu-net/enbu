import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { SettingsPage } from "../features/settings/settings-page";
export const Route = createFileRoute("/settings")({ component: SettingsRoute });
function SettingsRoute() {
  const navigate = useNavigate();
  return <SettingsPage onAddAccount={() => void navigate({ to: "/add-account" })} />;
}
