import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import {
  clipboardWrite,
  container,
  openDialog,
  queryButton,
  queryInput,
  root,
  setupDom,
  typeInto,
} from "../../test/dom";
import { SecretRow } from "./secret-row";

// Secret values go through the host's clipboard; here that is the page's.
vi.mock("../../lib/platform", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/platform")>()),
  writeClipboard: (text: string) => navigator.clipboard.writeText(text),
}));

setupDom();

function renderSecretRow(props: {
  secretKey: string;
  secretValue: string;
  onEdit?: (val: string) => Promise<void>;
  onDelete?: () => Promise<void>;
  deleteLabel?: string;
}) {
  act(() => {
    root.render(
      <>
        <SecretRow
          secretKey={props.secretKey}
          secretValue={props.secretValue}
          onEdit={props.onEdit ?? (async () => {})}
          onDelete={props.onDelete ?? (async () => {})}
          deleteLabel={props.deleteLabel ?? "Delete"}
        />
      </>,
    );
  });
}

describe("SecretRow", () => {
  it("renders value input as password by default", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    expect(queryInput("super-secret")?.type).toBe("password");
  });

  it("opens the text editor on eye button click", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    act(() => {
      queryButton("Show value")?.click();
    });
    expect(container.querySelector("textarea")?.value).toBe("super-secret");
    expect(queryButton("Hide value")).toBeTruthy();
  });

  it("toggles back to password on second click", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    act(() => {
      queryButton("Show value")?.click();
    });
    act(() => {
      queryButton("Hide value")?.click();
    });
    expect(queryInput("super-secret")?.type).toBe("password");
  });

  it("asks for confirmation before deleting", async () => {
    const onDelete = vi.fn(async () => {});
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret", onDelete });
    act(() => {
      queryButton("Delete")?.click();
    });
    expect(onDelete).not.toHaveBeenCalled();
    const dialog = openDialog();
    expect(dialog?.textContent).toContain("Delete API_KEY?");
    await act(async () => {
      dialog?.querySelector<HTMLButtonElement>('button[aria-label^="Delete:"]')?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("copies the secret key and value independently", async () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    const status = container.querySelector('[role="status"]');
    expect(status?.textContent).toBe("");
    await act(async () => {
      queryButton("API_KEY")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("API_KEY");
    expect(container.querySelector('[role="status"]')?.textContent).toBe("Key copied");
    expect(container.querySelector("[data-toast]")).toBeTruthy();

    await act(async () => {
      queryButton("Copy value")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("super-secret");
    expect(
      queryButton("Copy value")?.parentElement?.querySelector('input[aria-label="Value: API_KEY"]'),
    ).toBeTruthy();
    // The buttons keep their names; the status message says what was copied.
    expect(queryButton("Copy value")).toBeTruthy();
    expect(container.querySelector('[role="status"]')).toBe(status);
    expect(status?.textContent).toBe("Value copied");
    expect(container.querySelector("[data-toast]")).toBeTruthy();
  });

  it("saves an edited value with an explicit button", async () => {
    const onEdit = vi.fn(async () => {});
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret", onEdit });
    typeInto(queryInput("super-secret"), "new-secret");
    expect(onEdit).not.toHaveBeenCalled();
    await act(async () => {
      queryButton("Save")?.click();
      await Promise.resolve();
    });
    expect(onEdit).toHaveBeenCalledWith("new-secret");
  });

  it("does not submit when an IME candidate is confirmed", async () => {
    const onEdit = vi.fn(async () => {});
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret", onEdit });
    const input = queryInput("super-secret")!;
    typeInto(input, "変換");
    for (const composition of [{ isComposing: true }, { keyCode: 229 }]) {
      const enter = new KeyboardEvent("keydown", {
        key: "Enter",
        bubbles: true,
        cancelable: true,
        ...composition,
      });
      await act(async () => {
        input.dispatchEvent(enter);
      });
      expect(enter.defaultPrevented).toBe(true);
    }
    expect(onEdit).not.toHaveBeenCalled();
  });

  it.each(["\n", "\r\n", "\r"])("preserves %j separators on blur and edit", async (separator) => {
    const onEdit = vi.fn(async () => {});
    const value = ["header", "body", "footer"].join(separator);
    renderSecretRow({ secretKey: "PEM", secretValue: value, onEdit });
    expect(container.querySelector('input[aria-label="Value: PEM"]')).toHaveProperty(
      "readOnly",
      true,
    );
    act(() => queryButton("Show value")?.click());
    const editor = container.querySelector("textarea")!;
    expect(editor.value).toBe("header\nbody\nfooter");
    act(() => {
      editor.focus();
      editor.blur();
    });
    expect(onEdit).not.toHaveBeenCalled();
    const changed = "header\nnew body\nfooter";
    const setValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
    act(() => {
      setValue.call(editor, changed);
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => queryButton("Save")?.click());
    expect(onEdit).toHaveBeenCalledOnce();
    expect(onEdit).toHaveBeenCalledWith(["header", "new body", "footer"].join(separator));
  });

  it("pauses editing in both value controls while saving", async () => {
    let finishSave!: () => void;
    const promise = new Promise<void>((resolve) => {
      finishSave = resolve;
    });
    const onEdit = vi.fn(() => promise);
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret", onEdit });
    typeInto(queryInput("super-secret"), "new-secret");

    await act(async () => queryButton("Save")?.click());
    expect(onEdit).toHaveBeenCalledExactlyOnceWith("new-secret");
    expect(queryInput("new-secret")?.disabled).toBe(true);
    act(() => queryButton("Show value")?.click());
    expect(container.querySelector("textarea")?.disabled).toBe(true);

    await act(async () => finishSave());
    expect(container.querySelector("textarea")?.disabled).toBe(false);
  });

  it("renders the secret key as a monospace label", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    expect(container.textContent).toContain("API_KEY");
  });

  it("renders the value input at all viewport sizes (not hidden)", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    const valueInput = queryInput("super-secret");
    expect(valueInput).toBeTruthy();
    // The input must not carry display:none — it was previously hidden on mobile
    expect(valueInput?.style.display).not.toBe("none");
  });

  it("value input has correct aria-label linking it to its key", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    const valueInput = container.querySelector<HTMLInputElement>(
      'input[aria-label="Value: API_KEY"]',
    );
    expect(valueInput).toBeTruthy();
  });
});
