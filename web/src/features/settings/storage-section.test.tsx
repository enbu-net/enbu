import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import {
  container,
  queryButton,
  root,
  settle,
  setupDom,
  typeInto,
  withSession,
} from "../../test/dom";
import { StorageSection } from "./storage-section";
vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));
setupDom();
const mocked = vi.mocked(backend);
async function render() {
  mocked.ReadConfig.mockResolvedValueOnce(
    'version = "v1alpha2"\n[storage]\nurl = "oci://ghcr.io/octo/app-enbu"\n',
  );
  const reloadRepo = vi.fn(async () => {});
  act(() =>
    root.render(
      withSession(<StorageSection />, {
        repo: { path: "/app", initialized: true, has_remote: false, storage_configured: true },
        reloadRepo,
      }),
    ),
  );
  await settle();
  return reloadRepo;
}
describe("StorageSection", () => {
  it("requires paused writes and migrates with S3 options", async () => {
    const reload = await render();
    const input = container.querySelector<HTMLInputElement>('input:not([type="checkbox"])')!;
    await act(async () => typeInto(input, "s3://bucket/team"));
    expect(queryButton("Migrate storage")?.disabled).toBe(true);
    const region = container.querySelector<HTMLInputElement>('input[aria-label="S3 region"]')!;
    await act(async () => typeInto(region, "eu-west-1"));
    const boxes = container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]');
    act(() => boxes[boxes.length - 1]?.click());
    await act(async () => queryButton("Migrate storage")?.click());
    await settle();
    expect(mocked.ChangeStorage).toHaveBeenCalledWith({
      url: "s3://bucket/team",
      region: "eu-west-1",
      endpoint: "",
      path_style: false,
      plain_http: false,
    });
    expect(reload).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain("Share the updated enbu.toml");
  });
  it("keeps the form and shows a localized failure when migration fails", async () => {
    const reload = await render();
    mocked.ChangeStorage.mockRejectedValueOnce(createAppError("access_denied"));
    await act(async () =>
      typeInto(
        container.querySelector<HTMLInputElement>('input:not([type="checkbox"])')!,
        "oci://registry.example/team",
      ),
    );
    const boxes = container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]');
    act(() => boxes[boxes.length - 1]?.click());
    await act(async () => queryButton("Migrate storage")?.click());
    await settle();
    expect(container.textContent).toContain("Access was denied.");
    expect(reload).not.toHaveBeenCalled();
    expect(queryButton("Migrate storage")?.disabled).toBe(false);
  });
});
