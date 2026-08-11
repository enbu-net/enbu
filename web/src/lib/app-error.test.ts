import { describe, expect, it } from "vite-plus/test";
import {
  AppError,
  displayError,
  formatDisplayError,
  toDisplayError,
  unwrapBindingResult,
} from "./app-error";

describe("display errors", () => {
  it("localizes a known code and expands params at display time", () => {
    const error = toDisplayError(
      new AppError({
        code: "conflict",
        message: "must not be displayed",
        params: {},
      }),
    );

    expect(formatDisplayError(error, "ja")).toContain("workspace");
    expect(formatDisplayError(error, "en")).toContain("changed concurrently");
  });

  it("never displays the payload message for an unknown code", () => {
    const error = toDisplayError(
      new AppError({ code: "future_code", message: "token=secret", params: {} }),
    );

    expect(formatDisplayError(error, "ja")).toBe("予期しないエラーが発生しました。");
    expect(formatDisplayError(error, "en")).toBe("An unexpected error occurred.");
  });

  it("maps ordinary errors and malformed payloads to internal", () => {
    expect(formatDisplayError(toDisplayError(new Error("token=secret")), "ja")).toBe(
      "予期しないエラーが発生しました。",
    );
    expect(formatDisplayError(toDisplayError({ code: 42 }), "en")).toBe(
      "An unexpected error occurred.",
    );
  });

  it("keeps translation reactive to the selected locale", () => {
    const error = displayError("access_denied");
    expect(formatDisplayError(error, "ja")).toBe("アクセスが拒否されました。");
    expect(formatDisplayError(error, "en")).toBe("Access was denied.");
  });

  it("preserves replacement-token characters in params", () => {
    const error = displayError("invalid_argument", { key: "$&$'$`" });

    expect(formatDisplayError(error, "en")).toBe("The input is invalid.");
  });

  it("unwraps binding errors without localizing them early", () => {
    expect(() =>
      unwrapBindingResult({
        error: { code: "conflict", message: "raw", params: {} },
      }),
    ).toThrow(AppError);
  });
});
