import { describe, expect, it, vi } from "vite-plus/test";
import { TtyServer } from "./tty-server";

class FakeSlave {
  writable = true;
  readonly writes: number[][] = [];
  private readonly readableListeners = new Set<() => void>();
  private readonly writableListeners = new Set<() => void>();
  private readonly input: number[] = [];

  onReadable(listener: () => void) {
    this.readableListeners.add(listener);
    return { dispose: () => this.readableListeners.delete(listener) };
  }

  onWritable(listener: () => void) {
    this.writableListeners.add(listener);
    return { dispose: () => this.writableListeners.delete(listener) };
  }

  read() {
    return this.input.splice(0);
  }

  write(data: number[]) {
    this.writes.push(data);
  }

  feed(data: number[]) {
    this.input.push(...data);
    for (const listener of this.readableListeners) listener();
  }
}

class FakeWorker {
  readonly posted: unknown[] = [];
  private readonly listeners = new Set<(event: MessageEvent<unknown>) => void>();

  addEventListener(_type: "message", listener: (event: MessageEvent<unknown>) => void) {
    this.listeners.add(listener);
  }

  removeEventListener(_type: "message", listener: (event: MessageEvent<unknown>) => void) {
    this.listeners.delete(listener);
  }

  postMessage(message: unknown) {
    this.posted.push(message);
  }

  request(message: unknown) {
    for (const listener of this.listeners) {
      listener({ data: message } as MessageEvent<unknown>);
    }
  }
}

describe("TtyServer", () => {
  it("bridges worker reads and writes through the PTY slave", () => {
    const slave = new FakeSlave();
    const worker = new FakeWorker();
    const server = new TtyServer(slave);
    server.start(worker);

    const shared = worker.posted[0] as SharedArrayBuffer;
    const control = new Int32Array(shared, 0, 1);
    const data = new Int32Array(shared, 4);

    control[0] = 0;
    worker.request({ ttyRequestType: "write", buf: [65, 66] });
    expect(slave.writes).toEqual([[65, 66]]);
    expect(control[0]).toBe(1);

    control[0] = 0;
    worker.request({ ttyRequestType: "read", length: 2 });
    slave.feed([67, 68, 69]);
    expect(Array.from(data.slice(0, 3))).toEqual([2, 67, 68]);
    expect(control[0]).toBe(1);

    server.dispose();
  });

  it("completes a zero-timeout poll without input", () => {
    const slave = new FakeSlave();
    const worker = new FakeWorker();
    const server = new TtyServer(slave);
    server.start(worker);

    const shared = worker.posted[0] as SharedArrayBuffer;
    const control = new Int32Array(shared, 0, 1);
    const data = new Int32Array(shared, 4);
    control[0] = 0;

    worker.request({ ttyRequestType: "poll", timeout: 0 });

    expect(data[0]).toBe(2);
    expect(control[0]).toBe(1);
    server.dispose();
  });

  it("cancels a pending poll when stopped", () => {
    vi.useFakeTimers();
    const slave = new FakeSlave();
    const worker = new FakeWorker();
    const server = new TtyServer(slave);
    server.start(worker);

    worker.request({ ttyRequestType: "poll", timeout: 1 });
    server.stop();
    vi.runAllTimers();

    const shared = worker.posted[0] as SharedArrayBuffer;
    expect(new Int32Array(shared, 0, 1)[0]).toBe(0);
    vi.useRealTimers();
    server.dispose();
  });
});
