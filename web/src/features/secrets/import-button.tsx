import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { Button } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { displayError, toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { ImportResult } from "../../lib/types";
import { m } from "../../paraglide/messages";

/**
 * Reads a dotenv file as text: UTF-8, or UTF-16 with a byte order mark, which
 * Windows PowerShell 5.1 writes. Anything else, such as Shift_JIS, fails with
 * a TypeError instead of turning into replacement characters in a secret.
 */
export async function readDotenvFile(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const encoding =
    bytes[0] === 0xff && bytes[1] === 0xfe
      ? "utf-16le"
      : bytes[0] === 0xfe && bytes[1] === 0xff
        ? "utf-16be"
        : "utf-8";
  return new TextDecoder(encoding, { fatal: true }).decode(bytes);
}

/**
 * Imports a .env file the person chooses, as `enbu import FILE` does. Secrets
 * that already hold another value are replaced only after a confirmation, the
 * GUI's --overwrite.
 */
export function ImportButton({
  env,
  onImported,
  onError,
}: {
  env: string;
  onImported: (result: ImportResult) => void | Promise<void>;
  onError: (error: DisplayError) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  // The chosen file's content, its environment and the keys it would change,
  // while confirming; the overwrite goes where the conflict was found.
  const [pending, setPending] = useState<{ dotenv: string; env: string; keys: string } | null>(
    null,
  );

  async function run(dotenv: string, overwrite: boolean, target: string) {
    setLoading(true);
    try {
      await onImported(await backend.ImportSecrets(target, dotenv, overwrite));
      setPending(null);
    } catch (err) {
      const display = toDisplayError(err);
      if (
        (display.code === "secret_already_exists" || display.code === "import_conflict") &&
        !overwrite
      ) {
        setPending({
          dotenv,
          env: target,
          keys:
            display.code === "import_conflict"
              ? (display.params.keys ?? "")
              : (display.params.key ?? ""),
        });
      } else {
        setPending(null);
        onError(display);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <input
        ref={input}
        type="file"
        accept=".env,text/plain"
        hidden
        data-testid="import-file"
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = "";
          if (file) {
            const target = env;
            readDotenvFile(file).then(
              (dotenv) => run(dotenv, false, target),
              (err: unknown) =>
                onError(
                  err instanceof TypeError ? displayError("invalid_argument") : toDisplayError(err),
                ),
            );
          }
        }}
      />
      <Button
        size="sm"
        variant="outline"
        loading={loading && pending === null}
        title={m.import_description()}
        onClick={() => input.current?.click()}
      >
        <Upload size={14} />
        {m.import_action()}
      </Button>
      <ConfirmDeleteDialog
        open={pending !== null}
        title={m.import_overwriteTitle()}
        description={m.import_overwriteDescription({ keys: pending?.keys ?? "" })}
        cancelLabel={m.config_cancel()}
        confirmLabel={m.import_overwrite()}
        loading={loading}
        onClose={() => setPending(null)}
        onConfirm={() => (pending ? run(pending.dotenv, true, pending.env) : undefined)}
      />
    </>
  );
}
