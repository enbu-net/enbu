import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { Button } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import { useI18n } from "../../lib/i18n";
import type { ImportResult } from "../../lib/types";

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
  const { t } = useI18n();
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
      await onImported(await backend.importSecrets(dotenv, overwrite, target));
      setPending(null);
    } catch (err) {
      const display = toDisplayError(err);
      if (display.code === "secret_already_exists" && !overwrite) {
        setPending({
          dotenv,
          env: target,
          keys: (display.params.keys ?? "").split(",").join(", "),
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
            file.text().then(
              (dotenv) => run(dotenv, false, target),
              (err: unknown) => onError(toDisplayError(err)),
            );
          }
        }}
      />
      <Button
        size="sm"
        variant="outline"
        loading={loading && pending === null}
        title={t("import.description")}
        onClick={() => input.current?.click()}
      >
        <Upload size={14} />
        {t("import.action")}
      </Button>
      <ConfirmDeleteDialog
        open={pending !== null}
        title={t("import.overwriteTitle")}
        description={t("import.overwriteDescription", { keys: pending?.keys ?? "" })}
        cancelLabel={t("config.cancel")}
        confirmLabel={t("import.overwrite")}
        loading={loading}
        onClose={() => setPending(null)}
        onConfirm={() => (pending ? run(pending.dotenv, true, pending.env) : undefined)}
      />
    </>
  );
}
