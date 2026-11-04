import type { AppErrorPayload } from "./rpc";

/**
 * Messages between the webview and the extension host. web/src/lib/vscode.ts
 * is the other side.
 */
export type WebviewMessage =
  | { type: "call"; id: number; method: string; params: unknown[] }
  | { type: "openExternal"; url: string };

export type HostMessage =
  | { type: "result"; id: number; result: unknown }
  | { type: "error"; id: number; error: AppErrorPayload }
  | { type: "event"; name: string; data: unknown };

/**
 * Checks a message from the webview. Calls must name a method enbu serves, and
 * links must be http or https. Anything else is dropped.
 */
export function parseWebviewMessage(
  data: unknown,
  methods: ReadonlySet<string>,
): WebviewMessage | undefined {
  if (!data || typeof data !== "object") return undefined;
  const message = data as Record<string, unknown>;
  switch (message.type) {
    case "call": {
      const { id, method, params } = message;
      if (typeof id !== "number" || !Number.isSafeInteger(id)) return undefined;
      if (typeof method !== "string" || !methods.has(method)) return undefined;
      if (!Array.isArray(params)) return undefined;
      return { type: "call", id, method, params: params as unknown[] };
    }
    case "openExternal": {
      const { url } = message;
      if (typeof url !== "string" || !isWebURL(url)) return undefined;
      return { type: "openExternal", url };
    }
    default:
      return undefined;
  }
}

export function isWebURL(url: string): boolean {
  try {
    const { protocol } = new URL(url);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

/** The payload the UI shows for a failure that carries no AppError. */
export const internalError: AppErrorPayload = {
  code: "internal",
  message: "internal error",
  params: {},
};
