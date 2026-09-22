import { describe, expect, it } from "vite-plus/test";
import { runtimeEnvironment } from "./runtime-environment";

describe("runtimeEnvironment", () => {
  it("passes the browser terminal dimensions to WASI", () => {
    expect(runtimeEnvironment(96, 28)).toEqual([
      "TERM=xterm-256color",
      "COLORTERM=truecolor",
      "COLUMNS=96",
      "LINES=28",
    ]);
  });
});
