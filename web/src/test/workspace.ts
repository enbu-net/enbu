import { vi } from "vite-plus/test";
import type { Workspace } from "../features/dashboard/use-workspace";
import type { Environment } from "../lib/types";

/** A loaded workspace whose refresh is a mock. */
export function testWorkspace(environments: Environment[]): Workspace {
  return {
    environments,
    currentEnvironment: environments.find((env) => env.current)?.name ?? "",
    secrets: null,
    conflicts: null,
    loading: false,
    error: null,
    setError: vi.fn(),
    refresh: vi.fn(async () => {}),
  };
}
