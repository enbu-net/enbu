import { describe, expect, it } from "vite-plus/test";
import { isWebURL, parseWebviewMessage } from "./protocol";

const methods = new Set(["ListSecrets", "GetAppVersion"]);

describe("parseWebviewMessage", () => {
  it("accepts calls to methods enbu serves", () => {
    expect(
      parseWebviewMessage({ type: "call", id: 1, method: "ListSecrets", params: ["dev"] }, methods),
    ).toEqual({ type: "call", id: 1, method: "ListSecrets", params: ["dev"] });
  });

  it.each([
    ["an unknown method", { type: "call", id: 1, method: "initialize", params: [] }],
    ["a method from the prototype", { type: "call", id: 1, method: "constructor", params: [] }],
    ["a missing id", { type: "call", method: "ListSecrets", params: [] }],
    ["a fractional id", { type: "call", id: 1.5, method: "ListSecrets", params: [] }],
    ["params that are not a list", { type: "call", id: 1, method: "ListSecrets", params: "dev" }],
    ["an unknown type", { type: "eval", code: "1" }],
    ["a non-object", "call"],
    ["null", null],
  ])("drops %s", (_, message) => {
    expect(parseWebviewMessage(message, methods)).toBeUndefined();
  });

  it("accepts web links and drops every other scheme", () => {
    expect(
      parseWebviewMessage({ type: "openExternal", url: "https://github.com/login" }, methods),
    ).toEqual({
      type: "openExternal",
      url: "https://github.com/login",
    });
    for (const url of [
      "file:///etc/passwd",
      "command:workbench.action.terminal.new",
      "vscode://x",
      "javascript:alert(1)",
      "not a url",
    ]) {
      expect(parseWebviewMessage({ type: "openExternal", url }, methods)).toBeUndefined();
    }
  });
});

describe("isWebURL", () => {
  it("accepts http and https only", () => {
    expect(isWebURL("http://localhost:8080/cb")).toBe(true);
    expect(isWebURL("https://github.com")).toBe(true);
    expect(isWebURL("ftp://example.com")).toBe(false);
  });
});
