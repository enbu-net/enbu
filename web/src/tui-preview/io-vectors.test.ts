import { describe, expect, it, vi } from "vite-plus/test";
import {
  collectIovecs,
  fillIovecs,
  iovecCapacity,
  readIovecsOnce,
  writeIovecsOnce,
} from "./io-vectors";

describe("WASI I/O vectors", () => {
  const iovecs = [
    { buf: 2, buf_len: 2 },
    { buf: 7, buf_len: 3 },
  ];

  it("collects all write vectors into one request", () => {
    const bytes = new Uint8Array([0, 0, 65, 66, 0, 0, 0, 67, 68, 69]);

    expect(iovecCapacity(iovecs)).toBe(5);
    expect(collectIovecs(bytes, iovecs)).toEqual([65, 66, 67, 68, 69]);
  });

  it("distributes one read response without waiting per vector", () => {
    const bytes = new Uint8Array(12);

    expect(fillIovecs(bytes, iovecs, [65, 66, 67])).toBe(3);
    expect(Array.from(bytes)).toEqual([0, 0, 65, 66, 0, 0, 0, 67, 0, 0, 0, 0]);
  });

  it("handles empty vector lists", () => {
    expect(iovecCapacity([])).toBe(0);
    expect(collectIovecs(new Uint8Array(), [])).toEqual([]);
    expect(fillIovecs(new Uint8Array(), [], [])).toBe(0);
  });

  it("uses one bridge request for every WASI read or write", () => {
    const bytes = new Uint8Array([0, 0, 65, 66, 0, 0, 0, 67, 68, 69]);
    const read = vi.fn(() => [70, 71, 72]);
    const write = vi.fn();

    expect(readIovecsOnce(bytes, iovecs, read)).toBe(3);
    expect(read).toHaveBeenCalledExactlyOnceWith(5);
    expect(writeIovecsOnce(bytes, iovecs, write)).toBe(5);
    expect(write).toHaveBeenCalledExactlyOnceWith([70, 71, 72, 68, 69]);
  });
});
