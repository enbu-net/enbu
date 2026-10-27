import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { parse as parseToml } from "smol-toml";
import { backend } from "../../lib/backend";
import { I18nProvider } from "../../lib/i18n";
import { container, queryButton, root, settle, setupDom, typeInto } from "../../test/dom";
import { ConfigPanel } from "./config-panel";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

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
      <I18nProvider>
        <ConfigPanel environments={[{ name: "dev", current: true }]} />
      </I18nProvider>,
    );
  });
  await settle();
}

describe("ConfigPanel", () => {
  it("keeps where an environment is stored when its output file changes", async () => {
    mocked.readConfig.mockResolvedValueOnce(config);
    await renderPanel();

    const output = container.querySelector<HTMLInputElement>("#config-output-dev");
    expect(output?.value).toBe(".env.dev");
    expect(queryButton("Save")?.disabled).toBe(true);
    typeInto(output, ".env.local");
    await act(async () => queryButton("Save")?.click());
    await settle();

    const saved = parseToml(String(mocked.writeConfig.mock.lastCall?.[0])) as {
      env: Record<string, { output: string; incarnation?: string }>;
    };
    expect(saved.env.dev).toEqual({
      output: ".env.local",
      incarnation: "22222222-2222-4222-8222-222222222222",
    });
    expect(queryButton("Save")?.disabled).toBe(true);
  });

  it("shows a refused save as a display error", async () => {
    mocked.readConfig.mockResolvedValueOnce(config);
    mocked.writeConfig.mockRejectedValueOnce(new Error("config_protected raw"));
    await renderPanel();

    typeInto(container.querySelector<HTMLInputElement>("#config-output-dev"), ".env.x");
    await act(async () => queryButton("Save")?.click());
    await settle();

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("raw");
  });
});
