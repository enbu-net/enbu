import { describe, expect, it } from "vite-plus/test";
import { parse as parseToml } from "smol-toml";
import { parseConfigDraft, serializeConfigDraft } from "./config-draft";

describe("enbu config editor", () => {
  it("hydrates missing environment output defaults for the GUI", () => {
    expect(
      parseConfigDraft('version = "v1alpha2"\ndefault_env = "development"\n', [
        { name: "development", current: true },
        { name: "production", current: false },
      ]),
    ).toEqual({
      version: "v1alpha2",
      default_env: "development",
      env: {
        development: { output: ".env.development" },
        production: { output: ".env.production" },
      },
    });
  });

  it("serializes GUI edits as valid canonical TOML", () => {
    const text = serializeConfigDraft({
      version: "v1alpha2",
      default_env: "staging",
      env: { staging: { output: ".env.staging" } },
    });
    expect(text).toBe(
      'version = "v1alpha2"\ndefault_env = "staging"\n\n[env.staging]\noutput = ".env.staging"\n',
    );
    expect(text).not.toContain("[env]\n");
    expect(parseConfigDraft(text, [])).toMatchObject({ default_env: "staging" });
  });

  it("rejects invalid TOML before entering the GUI", () => {
    expect(() => parseConfigDraft('version = "v1alpha2', [])).toThrow();
  });
  it("keeps the trust root and where each environment is stored when the form saves", () => {
    const text =
      'version = "v1alpha2"\nworkspace_id = "11111111-1111-4111-8111-111111111111"\ncontrol_genesis = "sha256:abc"\ndefault_env = "dev"\n[env.dev]\noutput = ".env.dev"\nincarnation = "22222222-2222-4222-8222-222222222222"\n[env.legacy]\noutput = ".env.legacy"\n';
    const draft = parseConfigDraft(text, []);
    draft.default_env = "legacy";
    const saved = parseToml(serializeConfigDraft(draft)) as {
      control_genesis?: string;
      env: Record<string, { incarnation?: string }>;
    };
    expect(saved.control_genesis).toBe("sha256:abc");
    expect(saved.env.dev?.incarnation).toBe("22222222-2222-4222-8222-222222222222");
    expect(saved.env.legacy).not.toHaveProperty("incarnation");
  });

  it("preserves workspace identity and S3 configuration while editing environments", () => {
    const text =
      'version = "v1alpha2"\nworkspace_id = "11111111-1111-4111-8111-111111111111"\ndefault_env = "default"\n[storage]\nurl = "s3://bucket/prefix"\nregion = "us-east-1"\nendpoint = "http://localhost:9000"\npath_style = true\n[env.default]\noutput = ".env"\n';
    const draft = parseConfigDraft(text, []);
    draft.env.default.output = ".env.changed";
    const roundtrip = parseConfigDraft(serializeConfigDraft(draft), []);
    expect(roundtrip.workspace_id).toBe(draft.workspace_id);
    expect(roundtrip.storage).toEqual(draft.storage);
    expect(roundtrip.env.default.output).toBe(".env.changed");
  });
});
