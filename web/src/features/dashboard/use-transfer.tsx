import { useCallback, useState, type ReactNode } from "react";
import { TransferModal } from "../../components/transfer-modal";
import { toDisplayError, type DisplayError } from "../../lib/app-error";

export type TransferOperation = "add" | "pull" | "sync" | "delete";

export type RunTransfer = (op: TransferOperation, task: () => Promise<void>) => Promise<void>;

// How long the finished steps, or the error, stay on screen.
const DONE_DELAY_MS = 600;
const ERROR_DELAY_MS = 2200;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Shows the steps of an operation that talks to storage while it runs. run
 * rethrows the operation's error, so the caller still reports it.
 */
export function useTransfer(): { run: RunTransfer; modal: ReactNode } {
  const [state, setState] = useState<{
    op: TransferOperation | null;
    error: DisplayError | null;
  }>({ op: null, error: null });

  const run = useCallback(async (op: TransferOperation, task: () => Promise<void>) => {
    setState({ op, error: null });
    try {
      await task();
      await wait(DONE_DELAY_MS);
    } catch (err) {
      setState({ op, error: toDisplayError(err) });
      await wait(ERROR_DELAY_MS);
      throw err;
    } finally {
      setState({ op: null, error: null });
    }
  }, []);

  const modal = (
    <TransferModal
      open={state.op !== null}
      operation={state.op}
      error={state.error}
      onClose={() => setState({ op: null, error: null })}
    />
  );
  return { run, modal };
}
