import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vite-plus/test";
import { resolveBinary, startSidecar } from "./sidecar";

describe("resolveBinary", () => {
  const none = () => false;
  const all = () => true;

  it("prefers the enbu.path setting", () => {
    expect(resolveBinary(" /opt/enbu/bin/enbu ", "/ext", "darwin", "arm64", all)).toBe(
      "/opt/enbu/bin/enbu",
    );
  });

  it("uses the binary bundled for this platform", () => {
    expect(resolveBinary("", "/ext", "linux", "x64", all)).toBe(
      join("/ext", "bin", "linux-x64", "enbu"),
    );
    expect(resolveBinary("", "/ext", "win32", "arm64", all)).toBe(
      join("/ext", "bin", "win32-arm64", "enbu.exe"),
    );
  });

  it("falls back to enbu on PATH", () => {
    expect(resolveBinary("", "/ext", "linux", "x64", none)).toBe("enbu");
  });
});

// A stand-in for `enbu rpc --stdio`: answers initialize, echoes GetAppVersion,
// and exits on "Exit".
const fake = `#!/usr/bin/env node
if (process.argv.slice(2).join(" ") !== "rpc --stdio") process.exit(2);
const { protocol } = JSON.parse(process.env.FAKE_ENBU ?? "{}");
process.stderr.write("fake enbu started\\n");
require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {
  const msg = JSON.parse(line);
  const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");
  if (msg.method === "initialize") reply({ protocol_version: protocol ?? 1, app_version: "9.9.9", methods: ["GetAppVersion"], events: [] });
  if (msg.method === "GetAppVersion") reply("9.9.9");
  if (msg.method === "Exit") process.exit(3);
});
`;

describe.skipIf(process.platform === "win32")("startSidecar", () => {
  const dir = mkdtempSync(join(tmpdir(), "enbu-vscode-"));
  const binary = join(dir, "enbu");
  writeFileSync(binary, fake);
  chmodSync(binary, 0o755);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  const handlers = {
    pickDirectory: () => Promise.resolve(""),
    openExternal: () => Promise.resolve(),
    event: () => {},
  };

  it("starts enbu, completes the handshake, and relays calls", async () => {
    const log = vi.fn();
    const onExit = vi.fn();
    const sidecar = await startSidecar({ binary, cwd: dir, handlers, log, onExit });
    try {
      expect(sidecar.info.app_version).toBe("9.9.9");
      await expect(sidecar.client.request("GetAppVersion")).resolves.toBe("9.9.9");
      await vi.waitFor(() => expect(log).toHaveBeenCalledWith("fake enbu started\n"));
    } finally {
      sidecar.dispose();
    }
    await new Promise((resolve) => sidecar.process.once("exit", resolve));
    expect(onExit).not.toHaveBeenCalled();
  });

  it("reports when enbu exits on its own", async () => {
    const onExit = vi.fn();
    const sidecar = await startSidecar({ binary, cwd: dir, handlers, log: () => {}, onExit });
    await expect(sidecar.client.request("Exit")).rejects.toThrow("enbu exited");
    await vi.waitFor(() => expect(onExit).toHaveBeenCalledWith(3));
  });

  it("fails when the binary does not exist", async () => {
    await expect(
      startSidecar({
        binary: join(dir, "missing"),
        cwd: dir,
        handlers,
        log: () => {},
        onExit: () => {},
      }),
    ).rejects.toThrow();
  });

  it("fails and stops enbu when it speaks another protocol version", async () => {
    vi.stubEnv("FAKE_ENBU", JSON.stringify({ protocol: 2 }));
    try {
      await expect(
        startSidecar({ binary, cwd: dir, handlers, log: () => {}, onExit: () => {} }),
      ).rejects.toThrow("unsupported enbu protocol version 2");
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
