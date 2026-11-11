import { describe, expect, it, vi } from "vite-plus/test";
import { AppError, toDisplayError } from "./app-error";

// Importing the real Wails runtime starts timers that outlive jsdom (see
// platform.test.ts).
vi.useFakeTimers();
const { serviceBackend, toAppError } = await import("./backend");
vi.clearAllTimers();
vi.useRealTimers();

/** A rejection shaped like the runtime's: the AppError payload is the cause. */
function rejection(code: string, params: Record<string, string> = {}) {
  return Object.assign(new Error(code), { cause: { code, message: code, params } });
}

describe("toAppError", () => {
  it("keeps the payload the desktop service marshalled", () => {
    const err = toAppError(rejection("secret_conflict", { keys: "A" }));
    expect(err).toBeInstanceOf(AppError);
    expect(err.payload).toMatchObject({ code: "secret_conflict", params: { keys: "A" } });
  });

  it("turns anything else into internal without exposing its message", () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(toAppError(new Error("binding missing")).payload.code).toBe("internal");
    expect(toAppError("boom").payload.code).toBe("internal");
    expect(log).toHaveBeenCalledTimes(2);
    log.mockRestore();
  });

  it("passes an AppError through", () => {
    const err = new AppError({ code: "conflict" });
    expect(toAppError(err)).toBe(err);
  });
});

describe("serviceBackend", () => {
  // Stand-ins for the generated bindings, which call into the Wails runtime.
  function service(methods: Record<string, (...args: never[]) => Promise<unknown>>) {
    return serviceBackend(methods as unknown as Parameters<typeof serviceBackend>[0]);
  }

  it("calls every method of the service with its arguments and result", async () => {
    const AddSecret = vi.fn(async () => {});
    const GetAppVersion = vi.fn(async () => "1.2.3");
    const backend = service({ AddSecret, GetAppVersion });
    await backend.AddSecret("default", "TOKEN", "secret");
    expect(AddSecret).toHaveBeenCalledWith("default", "TOKEN", "secret");
    await expect(backend.GetAppVersion()).resolves.toBe("1.2.3");
  });

  it("rejects with the AppError the desktop service returned", async () => {
    const backend = service({
      ApproveMember: async () => {
        throw rejection("access_denied");
      },
    });
    const err = await backend.ApproveMember("d2").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect(toDisplayError(err).code).toBe("access_denied");
  });
});
