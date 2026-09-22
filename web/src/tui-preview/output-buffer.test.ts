import { describe, expect, it } from "vite-plus/test";
import { OutputBuffer } from "./output-buffer";

describe("OutputBuffer", () => {
  it("emits a complete terminal frame as one byte array", () => {
    const output = new OutputBuffer();
    output.append([27, 91, 72]);
    output.append([]);
    output.append([65, 66]);

    expect(output.drain()).toEqual(Uint8Array.of(27, 91, 72, 65, 66));
    expect(output.drain()).toBeUndefined();
  });
});
