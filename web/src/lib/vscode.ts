import type { HostMessage, WebviewMessage } from "./webview-protocol";

export type { HostMessage, WebviewMessage } from "./webview-protocol";

/**
 * The UI inside a VS Code webview. The extension host relays each call to
 * `enbu rpc --stdio`, which serves the desktop app's Go service, and relays its
 * events back. The webview never talks to enbu itself. The messages are in
 * webview-protocol.ts.
 */
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
  call(method: string, params: unknown[]): Promise<unknown> {
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
