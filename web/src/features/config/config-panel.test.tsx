import { writeClipboard } from "../../lib/platform";
import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { parse as parseToml } from "smol-toml";
import { backend } from "../../lib/backend";
import { container, queryButton, root, settle, setupDom, typeInto } from "../../test/dom";
import { ConfigPanel } from "./config-panel";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

vi.mock("../../lib/platform", () => ({ writeClipboard: vi.fn(async () => {}) }));

setupDom();

const mocked = vi.mocked(backend);

const config = `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"
incarnation = "22222222-2222-4222-8222-222222222222"
`;

async function renderPanel() {
  await act(async () => {
    root.render(
      <>
        <ConfigPanel environments={[{ name: "dev", current: true }]} />
      </>,
    );
  });
  await settle();
}

describe("ConfigPanel", () => {
  it("shows and copies the encrypted storage location without editing config", async () => {
    mocked.ReadConfig.mockResolvedValueOnce(
      config + '\n[storage]\nurl = "oci://ghcr.io/octo/team-enbu"\n',
    );
    await renderPanel();
    expect(container.textContent).toContain("Encrypted data location");
    expect(container.textContent).toContain("oci://ghcr.io/octo/team-enbu");
    await act(async () => queryButton("Copy storage URL")?.click());
    expect(writeClipboard).toHaveBeenCalledWith("oci://ghcr.io/octo/team-enbu");
    expect(container.textContent).toContain("Storage URL copied");
    expect(queryButton("Save")?.disabled).toBe(true);
    expect(mocked.WriteConfig).not.toHaveBeenCalled();
  });
  it("shows the custom S3 endpoint and region alongside the bucket location", async () => {
    mocked.ReadConfig.mockResolvedValueOnce(
      config +
        '\n[storage]\nurl = "s3://bucket/team"\nendpoint = "https://objects.example"\nregion = "eu-west-1"\n',
    );
    await renderPanel();
    for (const value of ["s3://bucket/team", "https://objects.example", "eu-west-1"])
      expect(container.textContent).toContain(value);
  });
  it("keeps where an environment is stored when its output file changes", async () => {
    mocked.ReadConfig.mockResolvedValueOnce(config);
    await renderPanel();

    const output = container.querySelector<HTMLInputElement>("#config-output-dev");
    expect(output?.value).toBe(".env.dev");
    expect(queryButton("Save")?.disabled).toBe(true);
    typeInto(output, ".env.local");
    await act(async () => queryButton("Save")?.click());
    await settle();

    const saved = parseToml(String(mocked.WriteConfig.mock.lastCall?.[0])) as {
      env: Record<string, { output: string; incarnation?: string }>;
    };
    expect(saved.env.dev).toEqual({
      output: ".env.local",
      incarnation: "22222222-2222-4222-8222-222222222222",
    });
    expect(queryButton("Save")?.disabled).toBe(true);
  });

  it("shows a refused save as a display error", async () => {
    mocked.ReadConfig.mockResolvedValueOnce(config);
    mocked.WriteConfig.mockRejectedValueOnce(new Error("config_protected raw"));
    await renderPanel();

    typeInto(container.querySelector<HTMLInputElement>("#config-output-dev"), ".env.x");
    await act(async () => queryButton("Save")?.click());
    await settle();

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("raw");
  });
});
