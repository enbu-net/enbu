/**
 * Messages between the UI in a VS Code webview (lib/vscode.ts) and the VS Code
 * extension host (vscode/src/panel.ts), which relays calls to
 * `enbu rpc --stdio` and its events back. Both sides import these types from
 * here.
 *
 * Messages from the webview to the extension host:
 *   { type: "call", id, method, params }   a desktop service method, by its Go name
 *   { type: "openExternal", url }          open a link in the OS browser
 * Messages from the extension host to the webview:
 *   { type: "result", id, result }
 *   { type: "error", id, error }           error is the AppError payload
 *   { type: "event", name, data }          a backend event, such as enbu:progress
 */

/** The AppError payload a failed backend call carries. */
export type AppErrorPayload = {
  code: string;
  message?: string;
  params?: Record<string, string>;
};

export type WebviewMessage =
  | { type: "call"; id: number; method: string; params: unknown[] }
  | { type: "openExternal"; url: string };

export type HostMessage =
  | { type: "result"; id: number; result: unknown }
  | { type: "error"; id: number; error: AppErrorPayload }
  | { type: "event"; name: string; data: unknown };
