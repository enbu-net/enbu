import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import {
  container,
  queryButton,
  queryInput,
  renderAndSettle,
  settle,
  setupDom,
  typeInto,
} from "../../test/dom";
import { testWorkspace } from "../../test/workspace";
import { EnvironmentsTab } from "./environments-tab";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);
const environments = [
  { name: "default", current: true },
  { name: "staging", current: false },
];

describe("EnvironmentsTab", () => {
  it("renames an environment and reloads the workspace", async () => {
    const workspace = testWorkspace(environments);
    await renderAndSettle(<EnvironmentsTab workspace={workspace} />);

    await act(async () => queryButton("Rename: staging")?.click());
    typeInto(queryInput("staging"), "preview");
    const dialog = container.querySelector('[role="dialog"]')!;
    await act(async () => queryButton("Rename", dialog)?.click());
    await settle();

    expect(mocked.renameEnvironment).toHaveBeenCalledWith("staging", "preview");
    expect(workspace.refresh).toHaveBeenCalled();
  });

  it("keeps the current environment from being deleted", async () => {
    await renderAndSettle(<EnvironmentsTab workspace={testWorkspace(environments)} />);
    expect(queryButton("Delete: default")?.disabled).toBe(true);
    expect(queryButton("Delete: staging")?.disabled).toBe(false);
  });

  it("deletes without purging and offers to purge the kept revisions", async () => {
    mocked.deleteEnvironment.mockResolvedValueOnce({ purged: 0, incarnation: "inc-1" });
    mocked.purgeIncarnation.mockResolvedValueOnce(3);
    await renderAndSettle(<EnvironmentsTab workspace={testWorkspace(environments)} />);

    await act(async () => queryButton("Delete: staging")?.click());
    await act(async () => queryButton("Delete: Delete staging?")?.click());
    await settle();
    expect(mocked.deleteEnvironment).toHaveBeenCalledWith("staging", false);
    expect(container.textContent).toContain("Its stored revisions remain");

    await act(async () => queryButton("Delete stored revisions")?.click());
    await settle();
    expect(mocked.purgeIncarnation).toHaveBeenCalledWith("inc-1");
    expect(container.textContent).toContain("Deleted 3 stored revision(s).");
  });

  it("purges with the deletion when asked", async () => {
    mocked.deleteEnvironment.mockResolvedValueOnce({ purged: 2 });
    await renderAndSettle(<EnvironmentsTab workspace={testWorkspace(environments)} />);

    await act(async () => queryButton("Delete: staging")?.click());
    await act(async () => container.querySelector<HTMLInputElement>("#purge-environment")?.click());
    await act(async () => queryButton("Delete: Delete staging?")?.click());
    await settle();

    expect(mocked.deleteEnvironment).toHaveBeenCalledWith("staging", true);
    expect(container.textContent).toContain("Deleted 2 stored revision(s).");
  });

  it("purges an earlier incarnation and keeps the field when it fails", async () => {
    mocked.purgeIncarnation.mockRejectedValueOnce(createAppError("access_denied"));
    await renderAndSettle(<EnvironmentsTab workspace={testWorkspace(environments)} />);

    typeInto(container.querySelector<HTMLInputElement>('input[aria-label="Incarnation"]'), "inc-2");
    await act(async () => queryButton("Delete revisions")?.click());
    await settle();

    expect(mocked.purgeIncarnation).toHaveBeenCalledWith("inc-2");
    expect(queryInput("inc-2")).not.toBeNull();
    expect(container.textContent).toContain("Access was denied.");
  });
});
