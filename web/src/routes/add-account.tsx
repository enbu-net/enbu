import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback } from "react";
import { AddAccount } from "../features/auth/add-account";
export const Route = createFileRoute("/add-account")({ component: AddAccountRoute });
function AddAccountRoute() {
  const navigate = useNavigate();
  const done = useCallback(() => {
    void navigate({ to: "/settings" });
  }, [navigate]);
  return <AddAccount onDone={done} />;
}
