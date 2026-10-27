import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { initialize, RpcClient, type ClientHandlers, type InitializeResult } from "./rpc";

/**
 * Picks the enbu binary to run: the enbu.path setting, then the binary bundled
 * for this platform under bin/<platform>-<arch>/, then enbu on PATH.
 */
export function resolveBinary(
  setting: string,
  extensionPath: string,
  platform: NodeJS.Platform,
  arch: string,
  exists: (path: string) => boolean = existsSync,
): string {
  if (setting.trim() !== "") return setting.trim();
  const name = platform === "win32" ? "enbu.exe" : "enbu";
  const bundled = join(extensionPath, "bin", `${platform}-${arch}`, name);
  return exists(bundled) ? bundled : "enbu";
}

/** A running `enbu rpc --stdio` and the client talking to it. */
export interface Sidecar {
  readonly client: RpcClient;
  readonly info: InitializeResult;
  readonly process: ChildProcess;
  /** Stops enbu. The calls in flight fail. */
  dispose(): void;
}

export interface SidecarOptions {
  binary: string;
  /**
   * enbu's working directory. Windows looks up a bare "enbu" there first, so
   * it must not be a folder a repository controls.
   */
  cwd: string;
  handlers: ClientHandlers;
  /** Receives enbu's stderr, which holds its logs but never secret values. */
  log: (text: string) => void;
  /** Called when enbu exits on its own after the handshake, not through dispose. */
  onExit: (code: number | null) => void;
}

/** Starts enbu and completes the handshake. */
export async function startSidecar(options: SidecarOptions): Promise<Sidecar> {
  const child = spawn(options.binary, ["rpc", "--stdio"], {
    cwd: options.cwd,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const { stdin, stdout, stderr } = child;
  if (!stdin || !stdout || !stderr) throw new Error("enbu has no stdio");

  let disposed = false;
  let started = false;
  const client = new RpcClient(stdout, stdin, options.handlers);
  stderr.setEncoding("utf8");
  stderr.on("data", (chunk: string) => options.log(chunk));
  // A write after enbu exits fails with EPIPE; the exit handler reports it.
  stdin.on("error", () => client.dispose());

  const spawned = new Promise<void>((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
  child.once("exit", (code) => {
    client.dispose();
    // An exit before the handshake completes rejects startSidecar instead.
    if (started && !disposed) options.onExit(code);
  });

  const dispose = () => {
    disposed = true;
    client.dispose();
    stdin.end();
    child.kill();
  };

  try {
    await spawned;
    const info = await initialize(client);
    started = true;
    return { client, info, process: child, dispose };
  } catch (err) {
    dispose();
    throw err;
  }
}
