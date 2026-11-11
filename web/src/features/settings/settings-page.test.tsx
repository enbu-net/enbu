import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { defaultSettings, getSettings, loadSettings } from "../../lib/settings";
import { localStorageKey } from "../../paraglide/runtime";
import {
  container,
  queryButton,
  root,
  settle,
  setupDom,
  typeInto,
  withSession,
} from "../../test/dom";
import {
  parseSettingsDocument,
  SettingsPage,
  settingsDocument,
  settingsSchema,
} from "./settings-page";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

// Monaco does not run in jsdom; a textarea stands in for the JSON editor.
vi.mock("./settings-json-editor", () => ({
  SettingsJsonEditor: ({
    value,
    onChange,
    onSave,
  }: {
    value: string;
    onChange: (value: string) => void;
    onSave: () => void;
  }) => (
    <div>
      <textarea
        aria-label="settings.json"
        defaultValue={value}
        onInput={(event) => onChange((event.target as HTMLTextAreaElement).value)}
      />
      <button type="button" onClick={onSave}>
        Save
      </button>
    </div>
  ),
}));

setupDom();

beforeEach(() => {
  localStorage.setItem(localStorageKey, "en");
  loadSettings();
});

async function renderPage() {
  await act(async () => {
    root.render(<>{withSession(<SettingsPage />)}</>);
  });
  await settle();
}

function typeJson(text: string) {
  const area = container.querySelector<HTMLTextAreaElement>("textarea");
  act(() => {
    if (!area) return;
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(area, text);
    area.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

describe("settings document", () => {
  it("round-trips the settings with the language", () => {
    const text = settingsDocument({ ...defaultSettings, fontSize: 16 }, "ja");
    expect(JSON.parse(text)).toEqual({
      theme: "system",
      language: "ja",
      fontSize: 16,
      clipboardClearSeconds: 30,
    });
    expect(parseSettingsDocument(text, "en")).toEqual({
      ...defaultSettings,
      fontSize: 16,
      language: "ja",
    });
  });

  it("keeps the current language when the key is missing and refuses others", () => {
    expect(parseSettingsDocument("{}", "en").language).toBe("en");
    expect(() => parseSettingsDocument('{"language":"fr"}', "en")).toThrow();
    expect(() => parseSettingsDocument("{", "en")).toThrow();
    expect(() => parseSettingsDocument('{"fontsize":12}', "en")).toThrow();
  });

  it("describes every setting in the schema", () => {
    const schema = settingsSchema() as { properties: Record<string, unknown> };
    expect(Object.keys(schema.properties).sort()).toEqual(
      ["clipboardClearSeconds", "fontSize", "language", "theme"].sort(),
    );
  });
});

describe("SettingsPage", () => {
  it("shows the sections and the app version", async () => {
    vi.mocked(backend).appVersion.mockResolvedValueOnce("v1.2.3");
    await renderPage();
    for (const title of ["Accounts", "Display", "Security", "About"]) {
      expect(container.querySelector(`section[aria-label="${title}"]`)).not.toBeNull();
    }
    expect(container.textContent).toContain("v1.2.3");
  });

  it("saves a font size within range as it is typed", async () => {
    await renderPage();
    const input = container.querySelector<HTMLInputElement>("#font-size");
    typeInto(input, "18");
    expect(getSettings().fontSize).toBe(18);
    typeInto(input, "40");
    expect(getSettings().fontSize).toBe(18);
  });

  it("edits the same settings as JSON and goes back to the form", async () => {
    await renderPage();
    await act(async () => queryButton("Open as JSON")?.click());
    const area = container.querySelector<HTMLTextAreaElement>("textarea");
    expect(JSON.parse(area?.value ?? "").clipboardClearSeconds).toBe(30);

    typeJson('{ "theme": "dark", "clipboardClearSeconds": 0 }');
    await act(async () => queryButton("Open as form")?.click());
    expect(getSettings()).toEqual({ ...defaultSettings, theme: "dark", clipboardClearSeconds: 0 });
    expect(container.querySelector<HTMLInputElement>("#clipboard-clear")?.value).toBe("0");
  });

  it("stays in the JSON view with an error when the JSON is invalid", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    await renderPage();
    await act(async () => queryButton("Open as JSON")?.click());
    typeJson('{ "fontSize": 99 }');
    await act(async () => queryButton("Save")?.click());
    expect(getSettings().fontSize).toBe(14);
    await act(async () => queryButton("Open as form")?.click());
    expect(container.querySelector("textarea")).not.toBeNull();
    log.mockRestore();
  });
});
