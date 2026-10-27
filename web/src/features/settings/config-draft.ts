import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { Environment } from "../../lib/types";

export type EnbuConfigDraft = {
  version: string;
  default_env: string;
  workspace_id?: string;
  /** The trust root. The form never edits it, and saving must keep it. */
  control_genesis?: string;
  storage?: ReturnType<typeof parseToml>;
  /** incarnation says where an environment's secrets are stored; it is kept as read. */
  env: Record<string, { output: string; incarnation?: string }>;
};

export function parseConfigDraft(content: string, environments: Environment[]): EnbuConfigDraft {
  const parsed = parseToml(content) as Record<string, unknown>;
  const parsedEnv =
    parsed.env && typeof parsed.env === "object" ? (parsed.env as Record<string, unknown>) : {};
  const env: EnbuConfigDraft["env"] = {};
  const names = new Set([...Object.keys(parsedEnv), ...environments.map((item) => item.name)]);
  for (const name of names) {
    const value = parsedEnv[name];
    const output =
      value &&
      typeof value === "object" &&
      typeof (value as { output?: unknown }).output === "string"
        ? String((value as { output: string }).output)
        : name === "default"
          ? ".env"
          : `.env.${name}`;
    const incarnation =
      value &&
      typeof value === "object" &&
      typeof (value as { incarnation?: unknown }).incarnation === "string"
        ? String((value as { incarnation: string }).incarnation)
        : undefined;
    env[name] = incarnation ? { output, incarnation } : { output };
  }
  const fallback =
    environments.find((item) => item.current)?.name ?? environments[0]?.name ?? "default";
  return {
    version: typeof parsed.version === "string" ? parsed.version : "v1alpha2",
    default_env: typeof parsed.default_env === "string" ? parsed.default_env : fallback,
    workspace_id: typeof parsed.workspace_id === "string" ? parsed.workspace_id : undefined,
    control_genesis:
      typeof parsed.control_genesis === "string" ? parsed.control_genesis : undefined,
    storage:
      parsed.storage && typeof parsed.storage === "object"
        ? (parsed.storage as ReturnType<typeof parseToml>)
        : undefined,
    env,
  };
}

export function serializeConfigDraft(config: EnbuConfigDraft): string {
  const header = stringifyToml({
    version: config.version,
    default_env: config.default_env,
    ...(config.workspace_id ? { workspace_id: config.workspace_id } : {}),
    ...(config.control_genesis ? { control_genesis: config.control_genesis } : {}),
  }).trimEnd();
  const environments = Object.entries(config.env)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, environment]) => {
      const key = /^[A-Za-z0-9_-]+$/.test(name) ? name : JSON.stringify(name);
      const fields = environment.incarnation
        ? { output: environment.output, incarnation: environment.incarnation }
        : { output: environment.output };
      return `[env.${key}]\n${stringifyToml(fields).trimEnd()}`;
    });
  const storage = config.storage ? [stringifyToml({ storage: config.storage }).trimEnd()] : [];
  return [header, ...storage, ...environments].join("\n\n") + "\n";
}
