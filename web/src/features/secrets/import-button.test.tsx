import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { createAppError } from "../../lib/app-error";
import { container, queryButton, renderAndSettle, settle, setupDom } from "../../test/dom";
import { ImportButton } from "./import-button";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

async function choose(content: string) {
  const input = container.querySelector<HTMLInputElement>('[data-testid="import-file"]')!;
  const file = new File([content], ".env", { type: "text/plain" });
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
  await settle();
}

describe("ImportButton", () => {
  it("imports the chosen file into the environment", async () => {
    const onImported = vi.fn();
    await renderAndSettle(<ImportButton env="staging" onImported={onImported} onError={vi.fn()} />);
    await choose("A=1\n");

    expect(mocked.importSecrets).toHaveBeenCalledWith("A=1\n", false, "staging");
    expect(onImported).toHaveBeenCalled();
  });

  it("asks before replacing secrets that hold another value", async () => {
    mocked.importSecrets.mockRejectedValueOnce(
      createAppError("secret_already_exists", { keys: "A,B" }),
    );
    const onImported = vi.fn();
    await renderAndSettle(<ImportButton env="default" onImported={onImported} onError={vi.fn()} />);
    await choose("A=2\nB=3\n");

    const dialog = container.querySelector('[role="dialog"]')!;
    expect(dialog.textContent).toContain("A, B");
    await act(async () => queryButton("Replace", dialog)?.click());
    await settle();

    expect(mocked.importSecrets).toHaveBeenLastCalledWith("A=2\nB=3\n", true, "default");
    expect(onImported).toHaveBeenCalled();
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("reports other failures", async () => {
    mocked.importSecrets.mockRejectedValueOnce(createAppError("invalid_argument"));
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
    file.text = () => Promise.reject(new Error("gone"));
    Object.defineProperty(input, "files", { configurable: true, value: [file] });
    await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
    await settle();

    expect(mocked.importSecrets).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ code: "internal" }));
  });
});
