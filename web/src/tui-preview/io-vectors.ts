export type Iovec = { buf: number; buf_len: number };

export function iovecCapacity(iovecs: Iovec[]): number {
  return iovecs.reduce((total, iovec) => total + iovec.buf_len, 0);
}

export function collectIovecs(bytes: Uint8Array, iovecs: Iovec[]): number[] {
  const output = new Uint8Array(iovecCapacity(iovecs));
  let offset = 0;
  for (const iovec of iovecs) {
    const chunk = bytes.subarray(iovec.buf, iovec.buf + iovec.buf_len);
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return Array.from(output.subarray(0, offset));
}

export function fillIovecs(bytes: Uint8Array, iovecs: Iovec[], data: number[]): number {
  let offset = 0;
  for (const iovec of iovecs) {
    if (offset >= data.length) break;
    const length = Math.min(iovec.buf_len, data.length - offset);
    bytes.set(data.slice(offset, offset + length), iovec.buf);
    offset += length;
  }
  return offset;
}

export function readIovecsOnce(
  bytes: Uint8Array,
  iovecs: Iovec[],
  read: (length: number) => number[],
): number {
  const capacity = iovecCapacity(iovecs);
  if (capacity === 0) return 0;
  return fillIovecs(bytes, iovecs, read(capacity));
}

export function writeIovecsOnce(
  bytes: Uint8Array,
  iovecs: Iovec[],
  write: (data: number[]) => void,
): number {
  const data = collectIovecs(bytes, iovecs);
  if (data.length > 0) write(data);
  return data.length;
}
