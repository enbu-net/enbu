import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { AppError, toDisplayError } from "./app-error";

// The generated bindings call into the Wails runtime; the adapter is tested
// against stand-ins with the same names.
const desktop = vi.hoisted(() => ({}) as Record<string, ReturnType<typeof vi.fn>>);
vi.mock("../bindings/github.com/enbu-net/enbu/desktop/wails", () => ({
  DesktopService: new Proxy(desktop, {
    get: (target, name: string) => (target[name] ??= vi.fn(async () => undefined)),
  }),
}));

const { desktopBackend: backend, toAppError } = await import("./backend");

/** A rejection shaped like the runtime's: the AppError payload is the cause. */
function rejection(code: string, params: Record<string, string> = {}) {
  return Object.assign(new Error(code), { cause: { code, message: code, params } });
}

beforeEach(() => {
  for (const name of Object.keys(desktop)) delete desktop[name];
});

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

describe("desktop backend", () => {
  it("passes arguments in the desktop service's order", async () => {
    await backend.addSecret("TOKEN", "secret", "default");
    await backend.editSecret("TOKEN", "new", "default");
    await backend.deleteSecret("TOKEN", "default");
    await backend.pullSecrets("default", true);
    await backend.syncSecrets();
    await backend.renameEnvironment("staging", "prod");
    await backend.resolveConflicts("prod", ["h1"], [{ key: "KEY", value: "", delete: true }]);
    await backend.gitCreateRemote("C:/repo", "octo-org", "example", true);

    expect(desktop.AddSecret).toHaveBeenCalledWith("default", "TOKEN", "secret");
    expect(desktop.EditSecret).toHaveBeenCalledWith("default", "TOKEN", "new");
    expect(desktop.DeleteSecret).toHaveBeenCalledWith("default", "TOKEN");
    expect(desktop.PullSecrets).toHaveBeenCalledWith("default", true);
    expect(desktop.SyncSecrets).toHaveBeenCalledWith("");
    expect(desktop.RenameEnvironment).toHaveBeenCalledWith("staging", "prod");
    expect(desktop.ResolveConflicts).toHaveBeenCalledWith(
      "prod",
      ["h1"],
      [{ key: "KEY", value: "", delete: true }],
    );
    expect(desktop.GitCreateRemote).toHaveBeenCalledWith("C:/repo", "octo-org", "example", true);
  });

  it("reports a repository as selected only when it has a path", async () => {
    desktop.GetRepoStatus = vi.fn(async () => ({ path: "", initialized: false }));
    await expect(backend.repoStatus()).resolves.toEqual({ selected: false });

    const repo = { path: "/repo", initialized: true, has_git: true };
    desktop.SelectRepository = vi.fn(async () => repo);
    await expect(backend.selectRepository("/repo")).resolves.toEqual({ selected: true, repo });
  });

  it("rejects with the AppError the desktop service returned", async () => {
    desktop.ApproveMember = vi.fn(async () => {
      throw rejection("access_denied");
    });
    const err = await backend.approveMember("d2").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect(toDisplayError(err).code).toBe("access_denied");
  });

  it("turns a failed sign-in's payload into a display error", async () => {
    desktop.GetOAuthLoginStatus = vi.fn(async () => ({
      state: "denied",
      error: { code: "access_denied", message: "raw", params: {} },
    }));
    const status = await backend.oauthStatus("s1");
    expect(status.state).toBe("denied");
    expect(status.error?.code).toBe("access_denied");
  });
});
