import { Create } from "@wailsio/runtime";
import {
  Diff,
  ImportResult,
  KeyUpdateResult,
} from "../bindings/github.com/enbu-net/enbu/app/models";
import { PublicInfo } from "../bindings/github.com/enbu-net/enbu/pkg/identity/models";
import * as Desktop from "../bindings/github.com/enbu-net/enbu/desktop/models";
import type { ServiceClient, ServiceMethod } from "./backend";
import type { AppErrorPayload } from "./app-error";

/**
 * The UI inside a VS Code webview. The extension host relays each call to
 * `enbu rpc --stdio`, which serves the desktop app's Go service, and relays its
 * events back. The webview never talks to enbu itself.
 *
 * Messages from the webview to the extension host:
 *   { type: "call", id, method, params }   a desktop service method, by its Go name
 *   { type: "openExternal", url }          open a link in the OS browser
 * Messages from the extension host to the webview:
 *   { type: "result", id, result }
 *   { type: "error", id, error }           error is the AppError payload
 *   { type: "event", name, data }          a backend event, such as enbu:progress
 */
export type WebviewMessage =
  | { type: "call"; id: number; method: ServiceMethod; params: unknown[] }
  | { type: "openExternal"; url: string };

export type HostMessage =
  | { type: "result"; id: number; result: unknown }
  | { type: "error"; id: number; error: AppErrorPayload }
  | { type: "event"; name: string; data: unknown };

export interface VsCodeApi {
  postMessage(message: WebviewMessage): void;
}

declare function acquireVsCodeApi(): VsCodeApi;

/** Whether the UI runs in a VS Code webview. */
export const inVsCode = typeof acquireVsCodeApi === "function";

type Pending = { resolve: (value: unknown) => void; reject: (reason: unknown) => void };

export class VsCodeBridge {
  readonly #api: VsCodeApi;
  readonly #pending = new Map<number, Pending>();
  readonly #listeners = new Map<string, Set<(data: unknown) => void>>();
  #nextID = 0;

  constructor(api: VsCodeApi, target: Pick<Window, "addEventListener">) {
    this.#api = api;
    target.addEventListener("message", (event) => this.#receive((event as MessageEvent).data));
  }

  /** Calls a desktop service method. A failure rejects with the AppError payload as its cause. */
  call(method: ServiceMethod, params: unknown[]): Promise<unknown> {
    const id = ++this.#nextID;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#api.postMessage({ type: "call", id, method, params });
    });
  }

  /** Subscribes to a backend event; returns the unsubscribe function. */
  on(name: string, listener: (data: unknown) => void): () => void {
    let listeners = this.#listeners.get(name);
    if (!listeners) {
      listeners = new Set();
      this.#listeners.set(name, listeners);
    }
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  openExternal(url: string): void {
    this.#api.postMessage({ type: "openExternal", url });
  }

  #receive(data: unknown): void {
    if (!data || typeof data !== "object") return;
    const message = data as HostMessage;
    switch (message.type) {
      case "result":
      case "error": {
        const pending = this.#pending.get(message.id);
        if (!pending) return;
        this.#pending.delete(message.id);
        if (message.type === "result") {
          pending.resolve(message.result);
        } else {
          pending.reject(new Error("enbu call failed", { cause: message.error }));
        }
        return;
      }
      case "event":
        for (const listener of this.#listeners.get(message.name) ?? []) listener(message.data);
        return;
    }
  }
}

export const vscodeBridge: VsCodeBridge | undefined = inVsCode
  ? new VsCodeBridge(acquireVsCodeApi(), window)
  : undefined;

/**
 * A webview's assets come from another origin than the page, and a worker
 * script must have the page's origin. For a cross-origin script this returns a
 * bootstrap that loads it from inside a worker, which may load other origins;
 * otherwise undefined.
 */
export function crossOriginWorkerSource(
  url: string | URL,
  type: WorkerType | undefined,
  baseURI: string,
  origin: string,
): string | undefined {
  const target = new URL(String(url), baseURI);
  // URL.origin is "null" for schemes such as vscode-webview:, so compare by hand.
  const targetOrigin = `${target.protocol}//${target.host}`;
  if (target.protocol === "blob:" || target.protocol === "data:" || targetOrigin === origin) {
    return undefined;
  }
  const href = JSON.stringify(target.href);
  return type === "module" ? `import ${href};` : `importScripts(${href});`;
}

/** Makes `new Worker(url)` work for the UI's own worker scripts in a webview. */
export function installCrossOriginWorkers(scope: typeof globalThis): void {
  const Base = scope.Worker;
  if (!Base) return;
  scope.Worker = class extends Base {
    constructor(url: string | URL, options?: WorkerOptions) {
      const source = crossOriginWorkerSource(
        url,
        options?.type,
        scope.document.baseURI,
        scope.location.origin,
      );
      super(
        source === undefined
          ? url
          : URL.createObjectURL(new Blob([source], { type: "text/javascript" })),
        options,
      );
    }
  };
}

if (inVsCode) installCrossOriginWorkers(globalThis);

type Result<K extends ServiceMethod> = Awaited<ReturnType<ServiceClient[K]>>;

/**
 * The generated Wails bindings build each result with the model's createFrom,
 * which fills defaults and turns Go's null for an empty list into []. Results
 * from the extension host are plain JSON, so they go through the same
 * functions. Methods that return nothing or a string need none.
 */
const results: { [K in ServiceMethod]?: (source: unknown) => Result<K> } = {
  GetAuthStatus: (source) => Desktop.AuthStatus.createFrom(source),
  StartOAuthLogin: (source) => Desktop.OAuthStart.createFrom(source),
  GetOAuthLoginStatus: (source) => Desktop.OAuthStatus.createFrom(source),
  BrowseRepository: (source) => Desktop.RepoInfo.createFrom(source),
  SelectRepository: (source) => Desktop.RepoInfo.createFrom(source),
  GetRepoStatus: (source) => Desktop.RepoInfo.createFrom(source),
  ListRepositories: Create.Array((source) => Desktop.RepoInfo.createFrom(source)),
  Initialize: (source) => Desktop.InitResult.createFrom(source),
  ListEnvironments: Create.Array((source) => Desktop.Environment.createFrom(source)),
  DeleteEnvironment: (source) => Desktop.EnvironmentDeletion.createFrom(source),
  ListSecrets: (source) => Desktop.SecretsResponse.createFrom(source),
  PullSecrets: (source) => Desktop.PullResult.createFrom(source),
  ListConflicts: (source) => Desktop.ConflictSet.createFrom(source),
  ImportSecrets: (source) => ImportResult.createFrom(source),
  ListHistory: Create.Array((source) => Desktop.HistoryEntry.createFrom(source)),
  DiffHistory: Create.Nullable((source) => Diff.createFrom(source)),
  ListMembers: Create.Array((source) => Desktop.Member.createFrom(source)),
  ListJoinRequests: Create.Array((source) => Desktop.JoinRequest.createFrom(source)),
  GetIdentity: (source) => PublicInfo.createFrom(source),
  DiagnoseIdentity: (source) => Desktop.IdentityDiagnosis.createFrom(source),
  UpgradeIdentity: (source) => KeyUpdateResult.createFrom(source),
};

/** The desktop service, called through the extension host instead of Wails. */
export function vscodeService(bridge: VsCodeBridge): ServiceClient {
  return new Proxy({} as ServiceClient, {
    get(_, method: string) {
      return async (...params: unknown[]) => {
        const result = await bridge.call(method as ServiceMethod, params);
        const build = results[method as ServiceMethod] as
          | ((source: unknown) => unknown)
          | undefined;
        return build ? build(result) : result;
      };
    },
  });
}
