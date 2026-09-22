import { describe, expect, it, vi } from "vite-plus/test";
import { TtyServer } from "./tty-server";

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
  it("bridges worker reads and writes without a PTY", () => {
    const worker = new FakeWorker();
    const writes: Uint8Array[] = [];
    const server = new TtyServer((data) => writes.push(data));
    server.start(worker);

    const shared = worker.posted[0] as SharedArrayBuffer;
    const control = new Int32Array(shared, 0, 1);
    const data = new Int32Array(shared, 4);

    control[0] = 0;
    worker.request({ ttyRequestType: "write", buf: Uint8Array.of(65, 66) });
    expect(writes).toEqual([Uint8Array.of(65, 66)]);
    expect(control[0]).toBe(0);

    worker.request({ ttyRequestType: "read", length: 2 });
    server.input(Uint8Array.of(67, 68, 69));
    expect(Array.from(data.slice(0, 3))).toEqual([2, 67, 68]);
    expect(control[0]).toBe(1);

    server.dispose();
  });

  it("completes a zero-timeout poll without input", () => {
    const worker = new FakeWorker();
    const server = new TtyServer(vi.fn());
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
    const worker = new FakeWorker();
    const server = new TtyServer(vi.fn());
    server.start(worker);

    worker.request({ ttyRequestType: "poll", timeout: 1 });
    server.stop();
    vi.runAllTimers();

    const shared = worker.posted[0] as SharedArrayBuffer;
    expect(new Int32Array(shared, 0, 1)[0]).toBe(0);
    vi.useRealTimers();
    server.dispose();
  });

  it("wakes a pending poll when terminal text arrives", () => {
    const worker = new FakeWorker();
    const server = new TtyServer(vi.fn());
    server.start(worker);

    const shared = worker.posted[0] as SharedArrayBuffer;
    const control = new Int32Array(shared, 0, 1);
    const data = new Int32Array(shared, 4);
    worker.request({ ttyRequestType: "poll", timeout: -1 });
    server.input("\x1b[A");

    expect(control[0]).toBe(1);
    expect(data[0]).toBe(1);
    control[0] = 0;
    worker.request({ ttyRequestType: "read", length: 3 });
    expect(Array.from(data.slice(0, 4))).toEqual([3, 27, 91, 65]);
    server.dispose();
  });
});
