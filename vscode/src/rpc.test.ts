import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vite-plus/test";
import { initialize, RpcClient, RpcError, type ClientHandlers } from "./rpc";

/** A client whose server is the test: it reads what the client writes and answers. */
function setup(handlers: Partial<ClientHandlers> = {}) {
  const fromServer = new PassThrough();
  const toServer = new PassThrough();
  const client = new RpcClient(fromServer, toServer, {
    pickDirectory: () => Promise.resolve(""),
    openExternal: () => Promise.resolve(),
    event: () => {},
    ...handlers,
  });
  const sent: unknown[] = [];
  let buffer = "";
  toServer.setEncoding("utf8");
  toServer.on("data", (chunk: string) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) sent.push(JSON.parse(line));
  });
  const send = (message: unknown) => fromServer.write(`${JSON.stringify(message)}\n`);
  const next = async () => {
    await vi.waitFor(() => expect(sent.length).toBeGreaterThan(0));
    return sent.shift() as Record<string, unknown>;
  };
  return { client, send, next, fromServer };
}

describe("RpcClient", () => {
  it("sends positional params and resolves each call with its own result", async () => {
    const { client, send, next } = setup();
    const first = client.request("ListSecrets", ["dev"]);
    const second = client.request("GetAppVersion");
    expect(await next()).toEqual({ jsonrpc: "2.0", id: 1, method: "ListSecrets", params: ["dev"] });
    expect(await next()).toEqual({ jsonrpc: "2.0", id: 2, method: "GetAppVersion", params: [] });

    send({ jsonrpc: "2.0", id: 2, result: "1.2.3" });
    send({ jsonrpc: "2.0", id: 1, result: { environment: "dev" } });
    await expect(second).resolves.toBe("1.2.3");
    await expect(first).resolves.toEqual({ environment: "dev" });
  });

  it("resolves a call without a result to null", async () => {
    const { client, send, next } = setup();
    const call = client.request("AddSecret", ["dev", "K", "v"]);
    await next();
    send({ jsonrpc: "2.0", id: 1 });
    await expect(call).resolves.toBeNull();
  });

  it("rejects with the AppError payload of an application error", async () => {
    const { client, send, next } = setup();
    const call = client.request("ApproveMember", ["d2"]);
    await next();
    send({
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32000, message: "raw", data: { code: "access_denied", message: "raw" } },
    });
    const err = (await call.catch((e: unknown) => e)) as RpcError;
    expect(err).toBeInstanceOf(RpcError);
    expect(err.code).toBe(-32000);
    expect(err.data).toEqual({ code: "access_denied", message: "raw" });
  });

  it("leaves data unset for a protocol error", async () => {
    const { client, send, next } = setup();
    const call = client.request("Nope");
    await next();
    send({
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32601, message: "method not found", data: "x" },
    });
    const err = (await call.catch((e: unknown) => e)) as RpcError;
    expect(err.code).toBe(-32601);
    expect(err.data).toBeUndefined();
  });

  it("ignores lines that are not JSON-RPC messages for it", async () => {
    const { client, send, next, fromServer } = setup();
    const call = client.request("GetAppVersion");
    await next();
    fromServer.write("not json\n\n");
    send({ jsonrpc: "2.0", id: 99, result: "stray" });
    send({ jsonrpc: "2.0", id: 1, result: "1.2.3" });
    await expect(call).resolves.toBe("1.2.3");
  });

  it("delivers event notifications", async () => {
    const event = vi.fn();
    const { send } = setup({ event });
    send({
      jsonrpc: "2.0",
      method: "event",
      params: { name: "enbu:progress", data: { op: "sync" } },
    });
    await vi.waitFor(() => expect(event).toHaveBeenCalledWith("enbu:progress", { op: "sync" }));
  });

  it("answers pickDirectory with the chosen folder", async () => {
    const { send, next } = setup({ pickDirectory: () => Promise.resolve("/repo") });
    send({ jsonrpc: "2.0", id: "s1", method: "pickDirectory" });
    expect(await next()).toEqual({ jsonrpc: "2.0", id: "s1", result: "/repo" });
  });

  it("answers openExternal, and reports a failure without its cause", async () => {
    const openExternal = vi
      .fn<(url: string) => Promise<void>>()
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("secret detail"));
    const { send, next } = setup({ openExternal });
    send({ jsonrpc: "2.0", id: "s1", method: "openExternal", params: ["https://github.com"] });
    expect(await next()).toEqual({ jsonrpc: "2.0", id: "s1", result: null });
    send({ jsonrpc: "2.0", id: "s2", method: "openExternal", params: ["https://github.com"] });
    expect(await next()).toEqual({
      jsonrpc: "2.0",
      id: "s2",
      error: { code: -32000, message: "openExternal failed" },
    });
    expect(openExternal).toHaveBeenCalledWith("https://github.com");
  });

  it("answers an unknown server request with method not found", async () => {
    const { send, next } = setup();
    send({ jsonrpc: "2.0", id: "s1", method: "format" });
    expect(await next()).toMatchObject({ id: "s1", error: { code: -32601 } });
  });

  it("rejects calls in flight and later calls once the server goes away", async () => {
    const { client, next, fromServer } = setup();
    const call = client.request("SyncSecrets", ["dev"]);
    await next();
    fromServer.end();
    await expect(call).rejects.toBeInstanceOf(RpcError);
    await expect(client.request("GetAppVersion")).rejects.toBeInstanceOf(RpcError);
  });
});

describe("initialize", () => {
  it("accepts the protocol version this extension speaks", async () => {
    const { client, send, next } = setup();
    const result = initialize(client);
    expect(await next()).toMatchObject({ method: "initialize" });
    const info = {
      protocol_version: 1,
      app_version: "1.0.0",
      methods: ["GetAppVersion"],
      events: [],
    };
    send({ jsonrpc: "2.0", id: 1, result: info });
    await expect(result).resolves.toEqual(info);
  });

  it("refuses another protocol version", async () => {
    const { client, send, next } = setup();
    const result = initialize(client);
    await next();
    send({ jsonrpc: "2.0", id: 1, result: { protocol_version: 2 } });
    await expect(result).rejects.toThrow("unsupported enbu protocol version 2");
  });
});
