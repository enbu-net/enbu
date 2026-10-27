import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { I18nProvider } from "../../lib/i18n";
import { clipboardWrite, container, queryButton, queryInput, root, setupDom } from "../../test/dom";
import { SecretRow } from "./secret-row";

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
      <I18nProvider>
        <SecretRow
          secretKey={props.secretKey}
          secretValue={props.secretValue}
          onEdit={props.onEdit ?? (async () => {})}
          onDelete={props.onDelete ?? (async () => {})}
          deleteLabel={props.deleteLabel ?? "Delete"}
        />
      </I18nProvider>,
    );
  });
}

describe("SecretRow", () => {
  it("renders value input as password by default", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    expect(queryInput("super-secret")?.type).toBe("password");
  });

  it("toggles to text type on eye button click", () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    act(() => {
      queryButton("Show value")?.click();
    });
    expect(queryInput("super-secret")?.type).toBe("text");
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
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain("Delete API_KEY?");
    await act(async () => {
      dialog?.querySelector<HTMLButtonElement>('button[aria-label^="Delete:"]')?.click();
      await Promise.resolve();
    });
    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("copies the secret key and value independently", async () => {
    renderSecretRow({ secretKey: "API_KEY", secretValue: "super-secret" });
    await act(async () => {
      queryButton("Copy key")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("API_KEY");
    expect(queryButton("Key copied")).toBeTruthy();

    await act(async () => {
      queryButton("Copy value")?.click();
      await Promise.resolve();
    });
    expect(clipboardWrite).toHaveBeenCalledWith("super-secret");
    expect(queryButton("Value copied")).toBeTruthy();
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
