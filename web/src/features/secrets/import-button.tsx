import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { Button } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { ImportResult } from "../../lib/types";
import { m } from "../../paraglide/messages";

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
  // The chosen file's content and the keys it would change, while confirming.
  const [pending, setPending] = useState<{ dotenv: string; keys: string } | null>(null);

  async function run(dotenv: string, overwrite: boolean) {
    setLoading(true);
    try {
      await onImported(await backend.importSecrets(dotenv, overwrite, env));
      setPending(null);
    } catch (err) {
      const display = toDisplayError(err);
      if (display.code === "secret_already_exists" && !overwrite) {
        setPending({ dotenv, keys: (display.params.keys ?? "").split(",").join(", ") });
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
            file.text().then(
              (dotenv) => run(dotenv, false),
              (err: unknown) => onError(toDisplayError(err)),
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
        onConfirm={() => (pending ? run(pending.dotenv, true) : undefined)}
      />
    </>
  );
}
