import type { Readable, Writable } from "node:stream";
import { createInterface } from "node:readline";

/**
 * A JSON-RPC 2.0 client for `enbu rpc --stdio`, one JSON message per line.
 * See desktop/rpc for the server side.
 *
 * Params and results carry secret values. Nothing here logs them.
 */

/** The AppError payload the server puts in error.data. */
export interface AppErrorPayload {
  code: string;
  message?: string;
  params?: Record<string, string>;
}

/** A failed call. data is the AppError payload when the method itself failed. */
export class RpcError extends Error {
  readonly code: number;
  readonly data: AppErrorPayload | undefined;

  constructor(code: number, message: string, data?: AppErrorPayload) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.data = data;
  }
}

/** What the server asks of the client. */
export interface ClientHandlers {
  /** Shows a folder dialog; resolves to "" when the user cancels. */
  pickDirectory(): Promise<string>;
  openExternal(url: string): Promise<void>;
  event(name: string, data: unknown): void;
}

export interface InitializeResult {
  protocol_version: number;
  app_version: string;
  methods: string[];
  events: string[];
}

interface Message {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

type Pending = { resolve: (value: unknown) => void; reject: (reason: unknown) => void };

const codeMethodNotFound = -32601;
const codeApplication = -32000;

export class RpcClient {
  readonly #output: Writable;
  readonly #handlers: ClientHandlers;
  readonly #pending = new Map<number, Pending>();
  #nextID = 0;
  #closed = false;

  constructor(input: Readable, output: Writable, handlers: ClientHandlers) {
    this.#output = output;
    this.#handlers = handlers;
    const lines = createInterface({ input, crlfDelay: Infinity });
    lines.on("line", (line) => this.#receive(line));
    lines.on("close", () => this.dispose());
  }

  /** Calls a server method with positional params. */
  request(method: string, params: unknown[] = []): Promise<unknown> {
    if (this.#closed) return Promise.reject(new RpcError(codeApplication, "enbu is not running"));
    const id = ++this.#nextID;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#send({ jsonrpc: "2.0", id, method, params });
    });
  }

  /** Rejects the calls in flight; later calls fail at once. */
  dispose(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const pending of this.#pending.values()) {
      pending.reject(new RpcError(codeApplication, "enbu exited"));
    }
    this.#pending.clear();
  }

  #send(message: Message): void {
    if (this.#closed) return;
    this.#output.write(`${JSON.stringify(message)}\n`);
  }

  #receive(line: string): void {
    if (line.trim() === "") return;
    let message: Message;
    try {
      message = JSON.parse(line) as Message;
    } catch {
      return;
    }
    if (!message || typeof message !== "object") return;
    if (typeof message.method === "string") {
      this.#serve(message.id, message.method, message.params);
      return;
    }
    if (typeof message.id !== "number") return;
    const pending = this.#pending.get(message.id);
    if (!pending) return;
    this.#pending.delete(message.id);
    if (message.error) {
      const { code, message: text, data } = message.error;
      pending.reject(new RpcError(code, text, appErrorPayload(data)));
    } else {
      pending.resolve(message.result ?? null);
    }
  }

  /** Answers a request or notification from the server. */
  #serve(id: Message["id"], method: string, params: unknown): void {
    const args = Array.isArray(params) ? params : [];
    let work: Promise<unknown>;
    switch (method) {
      case "event": {
        const { name, data } = (params ?? {}) as { name?: unknown; data?: unknown };
        if (typeof name === "string") this.#handlers.event(name, data);
        return;
      }
      case "pickDirectory":
        work = this.#handlers.pickDirectory();
        break;
      case "openExternal":
        work =
          typeof args[0] === "string"
            ? this.#handlers.openExternal(args[0])
            : Promise.reject(new Error("url required"));
        break;
      default:
        if (id !== undefined && id !== null) {
          this.#send({
            jsonrpc: "2.0",
            id,
            error: { code: codeMethodNotFound, message: "method not found" },
          });
        }
        return;
    }
    if (id === undefined || id === null) return;
    work.then(
      (result) => this.#send({ jsonrpc: "2.0", id, result: result ?? null }),
      () =>
        this.#send({
          jsonrpc: "2.0",
          id,
          error: { code: codeApplication, message: `${method} failed` },
        }),
    );
  }
}

function appErrorPayload(data: unknown): AppErrorPayload | undefined {
  if (!data || typeof data !== "object") return undefined;
  const { code } = data as Partial<AppErrorPayload>;
  if (typeof code !== "string" || code === "") return undefined;
  return data as AppErrorPayload;
}

/** Sends the handshake and checks that the server speaks this protocol. */
export async function initialize(client: RpcClient): Promise<InitializeResult> {
  const result = (await client.request("initialize")) as InitializeResult | null;
  if (result?.protocol_version !== protocolVersion) {
    throw new RpcError(
      codeApplication,
      `unsupported enbu protocol version ${String(result?.protocol_version)}`,
    );
  }
  return result;
}

/** The protocol version of desktop/rpc this extension speaks. */
export const protocolVersion = 1;
