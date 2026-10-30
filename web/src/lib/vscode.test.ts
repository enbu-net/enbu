import { describe, expect, it, vi } from "vite-plus/test";
import { AppError, toDisplayError } from "./app-error";
import { createServiceBackend } from "./backend";
import {
  crossOriginWorkerSource,
  installCrossOriginWorkers,
  VsCodeBridge,
  vscodeService,
  type HostMessage,
  type WebviewMessage,
} from "./vscode";

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

describe("crossOriginWorkerSource", () => {
  const base = "https://file+.vscode-resource.vscode-cdn.net/ext/media/web/";
  const origin = "vscode-webview://abc";

  it("loads a cross-origin module worker through an import", () => {
    expect(crossOriginWorkerSource("./assets/taplo.worker.js", "module", base, origin)).toBe(
      `import "${base}assets/taplo.worker.js";`,
    );
  });

  it("loads a cross-origin classic worker through importScripts", () => {
    expect(
      crossOriginWorkerSource(new URL("assets/editor.worker.js", base), undefined, base, origin),
    ).toBe(`importScripts("${base}assets/editor.worker.js");`);
  });

  it("leaves same-origin, blob and data workers alone", () => {
    expect(
      crossOriginWorkerSource("/w.js", "module", "vscode-webview://abc/index.html", origin),
    ).toBeUndefined();
    expect(
      crossOriginWorkerSource("blob:vscode-webview://abc/1", "module", base, origin),
    ).toBeUndefined();
    expect(
      crossOriginWorkerSource("data:text/javascript,1", undefined, base, origin),
    ).toBeUndefined();
  });

  it("quotes the URL as a string literal", () => {
    expect(crossOriginWorkerSource('https://x.test/a"b.js', "module", base, origin)).toBe(
      'import "https://x.test/a%22b.js";',
    );
  });
});

describe("installCrossOriginWorkers", () => {
  it("starts cross-origin workers from a blob bootstrap and others as given", () => {
    const started: { url: string | URL; options?: WorkerOptions }[] = [];
    class FakeWorker {
      constructor(url: string | URL, options?: WorkerOptions) {
        started.push({ url, options });
      }
    }
    const scope = {
      Worker: FakeWorker,
      document: { baseURI: "https://cdn.test/web/" },
      location: { origin: "vscode-webview://abc" },
    } as unknown as typeof globalThis;
    const createObjectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:x/1");

    installCrossOriginWorkers(scope);
    new scope.Worker("./assets/w.js", { type: "module" });
    new scope.Worker("blob:vscode-webview://abc/2");

    expect(started).toEqual([
      { url: "blob:x/1", options: { type: "module" } },
      { url: "blob:vscode-webview://abc/2", options: undefined },
    ]);
    expect(createObjectURL).toHaveBeenCalledOnce();
    createObjectURL.mockRestore();
  });
});
