import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import { type InitResult, type RepoInfo, type StorageConfig } from "../../lib/types";
import {
  container,
  queryButton,
  root,
  settle,
  setupDom,
  typeInto,
  withSession,
} from "../../test/dom";
import { RepositorySetup, setupStep } from "./repository-setup";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));
vi.mock("../../lib/platform", () => ({
  openURL: vi.fn(),
  onProgress: () => () => {},
}));

setupDom();

const mocked = vi.mocked(backend);

function repoInfo(overrides: Partial<RepoInfo> = {}): RepoInfo {
  return {
    path: "/home/octo/app",
    initialized: false,
    has_remote: false,
    storage_configured: false,
    ...overrides,
  };
}

describe("setupStep", () => {
  it("founds a workspace in any folder, with or without Git", () => {
    expect(setupStep(repoInfo())).toBe("found");
    expect(setupStep(repoInfo({ has_remote: true }))).toBe("found");
    expect(setupStep(repoInfo({ initialized: true }))).toBeNull();
  });

  it("joins the workspace enbu.toml already names", () => {
    expect(setupStep(repoInfo({ storage_configured: true }))).toBe("join");
    expect(setupStep(repoInfo({ storage_configured: true, initialized: true }))).toBeNull();
  });
});

describe("RepositorySetup", () => {
  it("founds a workspace in suggested GHCR storage without a Git remote", async () => {
    mocked.SuggestStorage.mockResolvedValueOnce("oci://ghcr.io/octo/app-enbu");
    mocked.Initialize.mockResolvedValueOnce(
      initResult({ founded: true, storage: "oci://ghcr.io/octo/app-enbu" }),
    );
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="found" />, { reloadRepo })));
    await settle();
    expect(container.querySelector<HTMLInputElement>("#init-storage")?.value).toBe(
      "oci://ghcr.io/octo/app-enbu",
    );

    await act(async () => queryButton("Found workspace")?.click());
    await settle();
    expect(mocked.Initialize).toHaveBeenCalledWith(storage("oci://ghcr.io/octo/app-enbu"), false);
    expect(container.textContent).toContain("Inherit access from repository");
    expect(container.textContent).toContain("app-enbu");
    expect(reloadRepo).not.toHaveBeenCalled();

    await act(async () => queryButton("Continue")?.click());
    await settle();
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("allows custom storage when the GHCR suggestion is unavailable", async () => {
    mocked.Initialize.mockResolvedValueOnce(initResult());
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="found" />, { reloadRepo })));
    await settle();
    expect(container.textContent).toContain("Could not suggest a GHCR location");
    expect(queryButton("Found workspace")?.disabled).toBe(true);

    const input = container.querySelector<HTMLInputElement>("#init-storage")!;
    await act(async () => typeInto(input, "s3://bucket/team"));
    await act(async () => typeInto(queryLabelled("S3 region"), "eu-west-1"));
    await act(async () => queryCheckbox("Use path-style S3 addressing").click());
    await act(async () => queryButton("Found workspace")?.click());
    await settle();
    expect(mocked.Initialize).toHaveBeenCalledWith(
      { ...storage("s3://bucket/team"), region: "eu-west-1", path_style: true },
      false,
    );
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("passes plain HTTP for an OCI registry", async () => {
    mocked.Initialize.mockResolvedValueOnce(initResult());
    act(() => root.render(withSession(<RepositorySetup step="found" />)));
    await settle();
    const input = container.querySelector<HTMLInputElement>("#init-storage")!;
    await act(async () => typeInto(input, "oci://localhost:5000/team"));
    expect(queryLabelled("S3 region", false)).toBeNull();
    await act(async () => queryCheckbox("Use HTTP for a local OCI registry").click());
    await act(async () => queryButton("Found workspace")?.click());
    await settle();
    expect(mocked.Initialize).toHaveBeenCalledWith(
      { ...storage("oci://localhost:5000/team"), plain_http: true },
      false,
    );
  });

  it("does not ask for a GitHub remote the repository already has", async () => {
    const repo = repoInfo({ has_remote: true });
    act(() => root.render(withSession(<RepositorySetup step="found" />, { repo })));
    await settle();
    expect(queryButton("Open the step-by-step guide")).toBeNull();
    expect(container.textContent).toContain("Could not suggest a GHCR location");
  });

  it("joins the workspace in enbu.toml and reloads", async () => {
    mocked.Initialize.mockResolvedValueOnce(initResult());
    const reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<RepositorySetup step="join" />, { reloadRepo })));
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(mocked.Initialize).toHaveBeenCalledWith(storage(""), false);
    expect(reloadRepo).toHaveBeenCalledTimes(1);
  });

  it("shows the fingerprint to compare while waiting for approval", async () => {
    mocked.Initialize.mockResolvedValueOnce(initResult({ pending: true }));
    act(() => root.render(withSession(<RepositorySetup step="join" />)));
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(container.textContent).toContain("Waiting for approval");
    expect(container.textContent).toContain("aaaa-bbbb");
  });

  it("offers to trust a changed root only after trust_root_changed", async () => {
    mocked.Initialize.mockRejectedValueOnce(
      createAppError("trust_root_changed", { configured: "c-new" }),
    ).mockResolvedValueOnce(initResult({ replaced_genesis: "c-old" }));
    act(() => root.render(withSession(<RepositorySetup step="join" />)));
    expect(queryButton("Trust the new root")).toBeNull();
    await act(async () => queryButton("Set up")?.click());
    await settle();
    expect(container.textContent).toContain("c-new");

    await act(async () => queryButton("Trust the new root")?.click());
    await settle();
    expect(mocked.Initialize).toHaveBeenLastCalledWith(storage(""), true);
    expect(container.textContent).toContain("c-old");
    // This device was already a member, so it did not found the workspace.
    expect(container.textContent).not.toContain("Workspace founded");
  });
});

function storage(url: string): StorageConfig {
  return { url, region: "", endpoint: "", path_style: false, plain_http: false };
}

function queryLabelled(label: string, required = true) {
  const input = container.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
  if (required && !input) throw new Error(`no input ${label}`);
  return input!;
}

function queryCheckbox(label: string) {
  const option = Array.from(container.querySelectorAll("label")).find((el) =>
    el.textContent?.includes(label),
  );
  return option!.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
}

function initResult(overrides: Partial<InitResult> = {}): InitResult {
  return {
    public_key: "age1test",
    username: "octo",
    environment: "default",
    workspace_id: "w",
    control_genesis: "",
    key_created: false,
    mode: "join",
    has_secrets: false,
    can_decrypt: null,
    device_id: "d".repeat(64),
    fingerprint: "aaaa-bbbb",
    pending: false,
    storage: "oci://registry.example/team",
    founded: false,
    ...overrides,
  };
}
