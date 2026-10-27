import { describe, expect, it, vi } from "vite-plus/test";
import { AppError, toDisplayError } from "./app-error";
import { createServiceBackend } from "./backend";
import { VsCodeBridge, vscodeService, type HostMessage, type WebviewMessage } from "./vscode";

/** A bridge whose extension host is the test: it sees what the webview posts and answers. */
function setup() {
  const posted: WebviewMessage[] = [];
  const target = new EventTarget();
  const bridge = new VsCodeBridge({ postMessage: (message) => posted.push(message) }, target);
  const reply = (message: HostMessage) =>
    target.dispatchEvent(new MessageEvent("message", { data: message }));
  return { bridge, posted, reply, target };
}

describe("VsCodeBridge", () => {
  it("posts calls with fresh ids and resolves each with its own result", async () => {
    const { bridge, posted, reply } = setup();
    const first = bridge.call("ListSecrets", ["dev"]);
    const second = bridge.call("GetAppVersion", []);
    expect(posted).toEqual([
      { type: "call", id: 1, method: "ListSecrets", params: ["dev"] },
      { type: "call", id: 2, method: "GetAppVersion", params: [] },
    ]);

    reply({ type: "result", id: 2, result: "1.2.3" });
    reply({ type: "result", id: 1, result: { environment: "dev", secrets: [] } });
    await expect(second).resolves.toBe("1.2.3");
    await expect(first).resolves.toEqual({ environment: "dev", secrets: [] });
  });

  it("rejects with the AppError payload as the cause", async () => {
    const { bridge, reply } = setup();
    const call = bridge.call("ApproveMember", ["d2"]);
    reply({ type: "error", id: 1, error: { code: "access_denied", message: "raw", params: {} } });
    const err = await call.catch((e: unknown) => e);
    expect((err as Error).cause).toMatchObject({ code: "access_denied" });
  });

  it("ignores messages that are not for a pending call", async () => {
    const { bridge, reply, target } = setup();
    const call = bridge.call("GetAppVersion", []);
    reply({ type: "result", id: 99, result: "stray" });
    target.dispatchEvent(new MessageEvent("message", { data: "not an object" }));
    reply({ type: "result", id: 1, result: "1.2.3" });
    await expect(call).resolves.toBe("1.2.3");
  });

  it("delivers events to the listeners of that name until they unsubscribe", () => {
    const { bridge, reply } = setup();
    const progress = vi.fn();
    const other = vi.fn();
    const off = bridge.on("enbu:progress", progress);
    bridge.on("enbu:conflict_retry", other);

    reply({ type: "event", name: "enbu:progress", data: { op: "add" } });
    off();
    reply({ type: "event", name: "enbu:progress", data: { op: "sync" } });

    expect(progress).toHaveBeenCalledOnce();
    expect(progress).toHaveBeenCalledWith({ op: "add" });
    expect(other).not.toHaveBeenCalled();
  });

  it("asks the extension host to open links", () => {
    const { bridge, posted } = setup();
    bridge.openExternal("https://github.com/enbu-net/enbu");
    expect(posted).toEqual([{ type: "openExternal", url: "https://github.com/enbu-net/enbu" }]);
  });
});

describe("VS Code backend", () => {
  /** Answers every call with the given results, by method name. */
  function backendWith(results: Record<string, unknown>) {
    const { bridge, posted, reply } = setup();
    const call = bridge.call.bind(bridge);
    vi.spyOn(bridge, "call").mockImplementation((method, params) => {
      const pending = call(method, params);
      const { id } = posted.at(-1) as { id: number };
      reply({ type: "result", id, result: results[method] ?? null });
      return pending;
    });
    return { backend: createServiceBackend(vscodeService(bridge)), posted };
  }

  it("calls the desktop service methods with the same arguments as the desktop app", async () => {
    const { backend, posted } = backendWith({
      PullSecrets: {},
      GitCreateRemote: { path: "/repo" },
    });
    await backend.addSecret("TOKEN", "secret", "default");
    await backend.pullSecrets("default", true);
    await backend.gitCreateRemote("/repo", "octo-org", "example", true);
    expect(posted).toEqual([
      { type: "call", id: 1, method: "AddSecret", params: ["default", "TOKEN", "secret"] },
      { type: "call", id: 2, method: "PullSecrets", params: ["default", true] },
      {
        type: "call",
        id: 3,
        method: "GitCreateRemote",
        params: ["/repo", "octo-org", "example", true],
      },
    ]);
  });

  it("builds results like the generated bindings, so Go's null lists become empty", async () => {
    const { backend } = backendWith({
      ListEnvironments: null,
      ListSecrets: { environment: "dev", secrets: null },
      ListMembers: [{ device_id: "d1" }],
    });
    await expect(backend.listEnvironments()).resolves.toEqual([]);
    await expect(backend.listSecrets("dev")).resolves.toMatchObject({
      environment: "dev",
      secrets: [],
    });
    const members = await backend.listMembers();
    expect(members).toHaveLength(1);
    expect(members[0]).toMatchObject({ device_id: "d1" });
  });

  it("reports a repository as selected only when it has a path", async () => {
    const { backend } = backendWith({ GetRepoStatus: { path: "" } });
    await expect(backend.repoStatus()).resolves.toEqual({ selected: false });
  });

  it("rejects with the AppError the service returned", async () => {
    const { bridge, reply } = setup();
    const backend = createServiceBackend(vscodeService(bridge));
    const call = backend.syncSecrets("dev");
    reply({ type: "error", id: 1, error: { code: "secret_conflict", message: "raw", params: {} } });
    const err = await call.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AppError);
    expect(toDisplayError(err).code).toBe("secret_conflict");
  });
});
