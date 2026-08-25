export class OutputBuffer {
  private chunks: number[][] = [];
  private length = 0;

  append(data: number[]): void {
    if (data.length === 0) return;
    this.chunks.push(data);
    this.length += data.length;
  }

  drain(): Uint8Array | undefined {
    if (this.length === 0) return undefined;
    const output = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      output.set(chunk, offset);
      offset += chunk.length;
    }
    this.chunks = [];
    this.length = 0;
    return output;
  }
}
