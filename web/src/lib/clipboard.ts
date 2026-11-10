import { readClipboard, writeClipboard } from "./platform";
import { getSettings } from "./settings";

let pending: ReturnType<typeof setTimeout> | undefined;

/**
 * Copies a secret value and, after the clipboardClearSeconds setting, clears
 * it from the clipboard unless something else was copied since. Where the
 * clipboard cannot be read back, it is cleared anyway: a secret left behind
 * costs more than a lost clipboard entry. A newer copy replaces the pending
 * clear.
 */
export async function copySecret(
  value: string,
  seconds: number = getSettings().clipboardClearSeconds,
): Promise<void> {
  await navigator.clipboard.writeText(value);
  clearTimeout(pending);
  pending = undefined;
  if (seconds <= 0) return;
  pending = setTimeout(() => {
    pending = undefined;
    void clearIfUnchanged(value);
  }, seconds * 1000);
}

async function clearIfUnchanged(value: string) {
  let current: string | undefined;
  try {
    current = await readClipboard();
  } catch {
    current = undefined;
  }
  if (current !== undefined && current !== value) return;
  try {
    await writeClipboard("");
  } catch (err) {
    console.error("clearing the clipboard failed", err);
  }
}
