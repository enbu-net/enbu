import { useEffect, useRef, useState } from "react";
import { Upload } from "lucide-react";
import { Button } from "../../components/ui";
import { ConfirmDeleteDialog } from "../../components/confirm-delete-dialog";
import { displayError, toDisplayError, type DisplayError } from "../../lib/app-error";
import { backend } from "../../lib/backend";
import type { ImportResult, ImportTarget } from "../../lib/types";
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
 * that already hold another value are replaced only after confirmation, the
 * GUI's --overwrite.
 */
type ImportButtonProps = {
  repoPath: string;
  target: ImportTarget;
  onImported: (result: ImportResult) => void | Promise<void>;
  onError: (error: DisplayError) => void;
};

export function ImportButton(props: ImportButtonProps) {
  const { repoPath, target } = props;
  const { workspace_id, environment, incarnation } = target;
  return (
    <WorkspaceImportButton
      key={JSON.stringify([repoPath, workspace_id, environment, incarnation])}
      {...props}
    />
  );
}

function WorkspaceImportButton({ repoPath, target, onImported, onError }: ImportButtonProps) {
  const input = useRef<HTMLInputElement>(null);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState<{ dotenv: string; keys: string } | null>(null);

  async function run(dotenv: string, overwrite: boolean) {
    if (!mounted.current) return;
    setLoading(true);
    try {
      const result = await backend.ImportSecrets(repoPath, target, dotenv, overwrite);
      if (!mounted.current) return;
      await onImported(result);
      setPending(null);
    } catch (err) {
      if (!mounted.current) return;
      const display = toDisplayError(err);
      if (
        (display.code === "secret_already_exists" || display.code === "import_conflict") &&
        !overwrite
      ) {
        setPending({
          dotenv,
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
      if (mounted.current) setLoading(false);
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
            readDotenvFile(file).then(
              (dotenv) => run(dotenv, false),
              (err: unknown) => {
                if (mounted.current) {
                  onError(
                    err instanceof TypeError
                      ? displayError("invalid_argument")
                      : toDisplayError(err),
                  );
                }
              },
            );
          }
        }}
      />
      <Button
        size="sm"
        variant="outline"
        disabled={!repoPath || !target.workspace_id || !target.environment}
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
