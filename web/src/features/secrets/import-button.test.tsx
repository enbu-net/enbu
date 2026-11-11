import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import {
  container,
  openDialog,
  queryButton,
  renderAndSettle,
  settle,
  setupDom,
} from "../../test/dom";
import { ImportButton } from "./import-button";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

async function choose(content: string | Uint8Array<ArrayBuffer>) {
  const input = container.querySelector<HTMLInputElement>('[data-testid="import-file"]')!;
  const file = new File([content], ".env", { type: "text/plain" });
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
  await settle();
}

function utf16(text: string, bigEndian: boolean): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(2 + 2 * text.length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0xfeff, !bigEndian);
  for (let i = 0; i < text.length; i++) view.setUint16(2 + 2 * i, text.charCodeAt(i), !bigEndian);
  return bytes;
}

describe("ImportButton", () => {
  it("imports Japanese values from UTF-8 and from UTF-16 files", async () => {
    const onImported = vi.fn();
    await renderAndSettle(<ImportButton env="default" onImported={onImported} onError={vi.fn()} />);
    for (const content of [
      "GREETING=こんにちは\n",
      utf16("GREETING=こんにちは\n", false),
      utf16("GREETING=こんにちは\n", true),
    ]) {
      await choose(content);
      expect(mocked.ImportSecrets).toHaveBeenLastCalledWith(
        "default",
        "GREETING=こんにちは\n",
        false,
      );
    }
  });

  it("refuses a file that is not UTF-8 instead of importing garbled values", async () => {
    const onError = vi.fn();
    mocked.ImportSecrets.mockClear();
    await renderAndSettle(<ImportButton env="default" onImported={vi.fn()} onError={onError} />);
    // こんにちは in Shift_JIS.
    await choose(
      new Uint8Array([0x41, 0x3d, 0x82, 0xb1, 0x82, 0xf1, 0x82, 0xc9, 0x82, 0xbf, 0x82, 0xcd]),
    );
    expect(mocked.ImportSecrets).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: "invalid_argument" }));
  });

  it("imports the chosen file into the environment", async () => {
    const onImported = vi.fn();
    await renderAndSettle(<ImportButton env="staging" onImported={onImported} onError={vi.fn()} />);
    await choose("A=1\n");

    expect(mocked.ImportSecrets).toHaveBeenCalledWith("staging", "A=1\n", false);
    expect(onImported).toHaveBeenCalled();
  });

  it("asks before replacing secrets that hold another value", async () => {
    mocked.ImportSecrets.mockRejectedValueOnce(
      createAppError("import_conflict", { count: "2", keys: "A, B" }),
    );
    const onImported = vi.fn();
    await renderAndSettle(<ImportButton env="default" onImported={onImported} onError={vi.fn()} />);
    await choose("A=2\nB=3\n");

    const dialog = openDialog()!;
    expect(dialog.textContent).toContain("A, B");
    await act(async () => queryButton("Replace", dialog)?.click());
    await settle();

    expect(mocked.ImportSecrets).toHaveBeenLastCalledWith("default", "A=2\nB=3\n", true);
    expect(onImported).toHaveBeenCalled();
    expect(openDialog()).toBeNull();
  });

  it("reports other failures", async () => {
    mocked.ImportSecrets.mockRejectedValueOnce(createAppError("invalid_argument"));
    const onError = vi.fn();
    await renderAndSettle(<ImportButton env="default" onImported={vi.fn()} onError={onError} />);
    await choose("not dotenv");

    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: "invalid_argument" }));
  });

  it("reports a file it cannot read", async () => {
    const onError = vi.fn();
    await renderAndSettle(<ImportButton env="default" onImported={vi.fn()} onError={onError} />);
    const input = container.querySelector<HTMLInputElement>('[data-testid="import-file"]')!;
    const file = new File([""], ".env");
    file.arrayBuffer = () => Promise.reject(new Error("gone"));
    Object.defineProperty(input, "files", { configurable: true, value: [file] });
    await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
    await settle();

    expect(mocked.ImportSecrets).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: "internal" }));
  });

  it("overwrites in the environment the conflict was found in", async () => {
    mocked.ImportSecrets.mockRejectedValueOnce(
      createAppError("secret_already_exists", { key: "A" }),
    );
    const props = { onImported: vi.fn(), onError: vi.fn() };
    await renderAndSettle(<ImportButton env="staging" {...props} />);
    await choose("A=2\n");
    await renderAndSettle(<ImportButton env="production" {...props} />);

    const dialog = openDialog()!;
    await act(async () => queryButton("Replace", dialog)?.click());
    await settle();
    expect(mocked.ImportSecrets).toHaveBeenLastCalledWith("staging", "A=2\n", true);
  });
});
