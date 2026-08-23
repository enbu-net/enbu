/// <reference lib="webworker" />

import { WASI } from "@bjorn3/browser_wasi_shim";
import { collectPollEvents } from "./poll-events";

type TtyClientLike = {
  onRead(length: number): number[];
  onWrite(data: number[]): void;
  onWaitForReadable(timeout: number): boolean;
};

const scope = self;
let ttyClient: TtyClientLike | undefined;

scope.onmessage = (
  event: MessageEvent<SharedArrayBuffer | { type: string; imageURL?: string }>,
) => {
  if (event.data instanceof SharedArrayBuffer) {
    ttyClient = new TtyClient(event.data);
    return;
  }

  if (event.data.type !== "init" || !event.data.imageURL) return;
  if (!ttyClient) {
    console.error("TUI preview PTY was not initialized");
    scope.postMessage({ type: "error" });
    return;
  }

  void run(event.data.imageURL, ttyClient).catch((error: unknown) => {
    console.error("TUI preview worker failed", error);
    scope.postMessage({ type: "error" });
  });
};

class TtyClient implements TtyClientLike {
  private readonly control: Int32Array;
  private readonly data: Int32Array;

  constructor(shared: SharedArrayBuffer) {
    this.control = new Int32Array(shared, 0, 1);
    this.data = new Int32Array(shared, 4);
  }

  onRead(length: number): number[] {
    this.request({ ttyRequestType: "read", length });
    return Array.from(this.data.slice(1, this.data[0] + 1));
  }

  onWrite(data: number[]): void {
    this.request({ ttyRequestType: "write", buf: data });
  }

  onWaitForReadable(timeout: number): boolean {
    this.request({ ttyRequestType: "poll", timeout });
    return this.data[0] === 1;
  }

  private request(message: object): void {
    this.control[0] = 0;
    scope.postMessage(message);
    Atomics.wait(this.control, 0, 0);
  }
}

async function run(imageURL: string, client: TtyClientLike): Promise<void> {
  const response = await fetch(imageURL, { credentials: "same-origin" });
  if (!response.ok) throw new Error(`Failed to load TUI WASI module (${response.status})`);

  if (!response.body) throw new Error("The TUI WASI response did not include a body");
  const decompressed = response.body.pipeThrough(new DecompressionStream("gzip"));
  const wasm = await new Response(decompressed).arrayBuffer();
  const wasi = new WASI([], ["TERM=xterm-256color", "COLORTERM=truecolor"], []);
  patchTerminalIO(wasi, client);
  patchSocketStubs(wasi);

  const instance = await WebAssembly.instantiate(wasm, {
    wasi_snapshot_preview1: wasi.wasiImport,
  });
  scope.postMessage({ type: "ready" });
  wasi.start(
    instance.instance as unknown as {
      exports: { memory: WebAssembly.Memory; _start(): unknown };
    },
  );
}

function patchSocketStubs(wasi: WASI): void {
  const errnoNotSupported = 58;
  for (const name of ["sock_accept", "sock_recv", "sock_send", "sock_shutdown"]) {
    wasi.wasiImport[name] = () => errnoNotSupported;
  }
}

function patchTerminalIO(wasi: WASI, client: TtyClientLike): void {
  const originalRead = wasi.wasiImport.fd_read;
  wasi.wasiImport.fd_read = (
    fd: number,
    iovsPointer: number,
    iovsLength: number,
    readPointer: number,
  ) => {
    if (fd !== 0) return originalRead(fd, iovsPointer, iovsLength, readPointer);

    const view = new DataView(wasi.inst.exports.memory.buffer);
    const bytes = new Uint8Array(wasi.inst.exports.memory.buffer);
    const iovecs = readIovecs(view, iovsPointer, iovsLength);
    let total = 0;
    for (const iovec of iovecs) {
      if (iovec.buf_len === 0) continue;
      const data = client.onRead(iovec.buf_len);
      bytes.set(data, iovec.buf);
      total += data.length;
    }
    view.setUint32(readPointer, total, true);
    return 0;
  };

  const originalWrite = wasi.wasiImport.fd_write;
  wasi.wasiImport.fd_write = (
    fd: number,
    iovsPointer: number,
    iovsLength: number,
    writtenPointer: number,
  ) => {
    if (fd !== 1 && fd !== 2) return originalWrite(fd, iovsPointer, iovsLength, writtenPointer);

    const view = new DataView(wasi.inst.exports.memory.buffer);
    const bytes = new Uint8Array(wasi.inst.exports.memory.buffer);
    const iovecs = readIovecs(view, iovsPointer, iovsLength);
    let total = 0;
    for (const iovec of iovecs) {
      if (iovec.buf_len === 0) continue;
      const data = Array.from(bytes.slice(iovec.buf, iovec.buf + iovec.buf_len));
      client.onWrite(data);
      total += data.length;
    }
    view.setUint32(writtenPointer, total, true);
    return 0;
  };

  wasi.wasiImport.poll_oneoff = (
    subscriptionsPointer: number,
    eventsPointer: number,
    subscriptionCount: number,
    eventCountPointer: number,
  ) =>
    pollOneoff(
      wasi,
      client,
      subscriptionsPointer,
      eventsPointer,
      subscriptionCount,
      eventCountPointer,
    );
}

function readIovecs(
  view: DataView,
  pointer: number,
  length: number,
): Array<{ buf: number; buf_len: number }> {
  return Array.from({ length }, (_, index) => {
    const offset = pointer + index * 8;
    return {
      buf: view.getUint32(offset, true),
      buf_len: view.getUint32(offset + 4, true),
    };
  });
}

function pollOneoff(
  wasi: WASI,
  client: TtyClientLike,
  subscriptionsPointer: number,
  eventsPointer: number,
  subscriptionCount: number,
  eventCountPointer: number,
): number {
  const errnoInvalid = 28;
  if (subscriptionCount === 0) return errnoInvalid;

  const view = new DataView(wasi.inst.exports.memory.buffer);
  let stdinUserdata: bigint | undefined;
  let clockUserdata: bigint | undefined;
  let timeoutNanoseconds = Number.MAX_SAFE_INTEGER;

  for (let index = 0; index < subscriptionCount; index += 1) {
    const pointer = subscriptionsPointer + index * 48;
    const userdata = view.getBigUint64(pointer, true);
    const eventType = view.getUint8(pointer + 8);
    if (eventType === 1) {
      const fd = view.getUint32(pointer + 16, true);
      if (fd !== 0) return errnoInvalid;
      stdinUserdata = userdata;
    } else if (eventType === 0) {
      clockUserdata = userdata;
      timeoutNanoseconds = Number(view.getBigUint64(pointer + 24, true));
    } else {
      return errnoInvalid;
    }
  }

  const timeoutSeconds =
    timeoutNanoseconds === Number.MAX_SAFE_INTEGER ? -1 : timeoutNanoseconds / 1_000_000_000;
  const readable =
    (stdinUserdata !== undefined || clockUserdata !== undefined) &&
    client.onWaitForReadable(timeoutSeconds);
  const events = collectPollEvents(stdinUserdata, clockUserdata, readable);

  for (const [index, event] of events.entries()) {
    const pointer = eventsPointer + index * 32;
    view.setBigUint64(pointer, event.userdata, true);
    view.setUint16(pointer + 8, 0, true);
    view.setUint8(pointer + 10, event.type);
  }
  view.setUint32(eventCountPointer, events.length, true);
  return 0;
}

export {};
