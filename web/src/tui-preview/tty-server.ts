type Disposable = { dispose(): void };

type Slave = {
  readonly writable: boolean;
  onReadable(listener: () => void): Disposable;
  onWritable(listener: () => void): Disposable;
  read(length?: number): number[];
  write(data: number[]): void;
};

type WorkerLike = {
  addEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
  removeEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
  postMessage(message: unknown): void;
};

type TtyRequest =
  | { ttyRequestType: "read"; length: number }
  | { ttyRequestType: "write"; buf: number[] }
  | { ttyRequestType: "poll"; timeout: number };

const sharedBufferBytes = 260;

export class TtyServer {
  private readonly slave: Slave;
  private readonly shared = new SharedArrayBuffer(sharedBufferBytes);
  private readonly control = new Int32Array(this.shared, 0, 1);
  private readonly data = new Int32Array(this.shared, 4);
  private readonly disposables: Disposable[];
  private readonly fromWorker: number[] = [];
  private readonly toWorker: number[] = [];
  private state: "idle" | "read" | "poll" = "idle";
  private readLength = 0;
  private timeout: ReturnType<typeof setTimeout> | undefined;
  private stopWorker: (() => void) | undefined;

  constructor(slave: Slave) {
    this.slave = slave;
    this.disposables = [
      slave.onWritable(() => this.flushWrite()),
      slave.onReadable(() => {
        this.toWorker.push(...slave.read());
        if (this.state === "read") this.flushRead(this.readLength);
        if (this.state === "poll") this.finishPoll(true);
      }),
    ];
  }

  start(worker: WorkerLike): void {
    this.stop();
    const onMessage = (event: MessageEvent<unknown>) => {
      if (!isTtyRequest(event.data)) return;
      this.handle(event.data);
    };
    worker.addEventListener("message", onMessage);
    this.stopWorker = () => worker.removeEventListener("message", onMessage);
    worker.postMessage(this.shared);
  }

  stop(): void {
    this.stopWorker?.();
    this.stopWorker = undefined;
    this.clearTimeout();
    this.state = "idle";
  }

  dispose(): void {
    this.stop();
    for (const disposable of this.disposables) disposable.dispose();
  }

  private handle(request: TtyRequest): void {
    switch (request.ttyRequestType) {
      case "read":
        this.state = "read";
        this.readLength = request.length;
        if (this.toWorker.length > 0) this.flushRead(request.length);
        break;
      case "write":
        this.fromWorker.push(...request.buf);
        this.flushWrite();
        break;
      case "poll":
        this.state = "poll";
        if (this.toWorker.length > 0) {
          this.finishPoll(true);
        } else if (request.timeout === 0) {
          this.finishPoll(false);
        } else if (request.timeout > 0) {
          this.timeout = setTimeout(() => this.finishPoll(false), request.timeout * 1000);
        }
        break;
    }
  }

  private flushRead(length: number): void {
    const count = Math.min(length, this.toWorker.length, this.data.length - 1);
    const chunk = this.toWorker.splice(0, count);
    this.data[0] = chunk.length;
    this.data.set(chunk, 1);
    this.ack();
  }

  private flushWrite(): void {
    if (!this.slave.writable || this.fromWorker.length === 0) return;
    this.slave.write(this.fromWorker.splice(0));
    this.ack();
  }

  private finishPoll(readable: boolean): void {
    this.clearTimeout();
    this.data[0] = readable ? 1 : 2;
    this.ack();
  }

  private ack(): void {
    this.state = "idle";
    Atomics.store(this.control, 0, 1);
    Atomics.notify(this.control, 0);
  }

  private clearTimeout(): void {
    if (this.timeout !== undefined) clearTimeout(this.timeout);
    this.timeout = undefined;
  }
}

function isTtyRequest(value: unknown): value is TtyRequest {
  if (typeof value !== "object" || value === null || !("ttyRequestType" in value)) {
    return false;
  }
  const type = value.ttyRequestType;
  return type === "read" || type === "write" || type === "poll";
}
