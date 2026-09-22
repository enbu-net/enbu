type WorkerLike = {
  addEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
  removeEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
  postMessage(message: unknown): void;
};

type TtyRequest =
  | { ttyRequestType: "read"; length: number }
  | { ttyRequestType: "write"; buf: Uint8Array | number[] }
  | { ttyRequestType: "poll"; timeout: number };

const sharedBufferBytes = 260;
const encoder = new TextEncoder();

/**
 * Bridges raw terminal input and output to WASI. Output never participates in
 * the SharedArrayBuffer handshake: blocking the worker for every fd_write was
 * both unnecessary and the dominant interaction cost.
 */
export class TtyServer {
  private readonly writeOutput: (data: Uint8Array) => void;
  private readonly shared = new SharedArrayBuffer(sharedBufferBytes);
  private readonly control = new Int32Array(this.shared, 0, 1);
  private readonly data = new Int32Array(this.shared, 4);
  private readonly toWorker: number[] = [];
  private state: "idle" | "read" | "poll" = "idle";
  private readLength = 0;
  private timeout: ReturnType<typeof setTimeout> | undefined;
  private stopWorker: (() => void) | undefined;

  constructor(writeOutput: (data: Uint8Array) => void) {
    this.writeOutput = writeOutput;
  }

  input(value: string | Uint8Array): void {
    const bytes = typeof value === "string" ? encoder.encode(value) : value;
    for (const byte of bytes) this.toWorker.push(byte);
    if (this.state === "read") this.flushRead(this.readLength);
    if (this.state === "poll") this.finishPoll(true);
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
  }

  private handle(request: TtyRequest): void {
    switch (request.ttyRequestType) {
      case "read":
        this.state = "read";
        this.readLength = request.length;
        if (this.toWorker.length > 0) this.flushRead(request.length);
        break;
      case "write":
        this.writeOutput(Uint8Array.from(request.buf));
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
