import type { Terminal } from "ghostty-web";

const navigationSequences: Readonly<Record<string, string>> = {
  ArrowUp: "\x1b[A",
  ArrowDown: "\x1b[B",
  ArrowRight: "\x1b[C",
  ArrowLeft: "\x1b[D",
  Home: "\x1b[H",
  End: "\x1b[F",
  PageUp: "\x1b[5~",
  PageDown: "\x1b[6~",
};

/**
 * Ghostty's enhanced key encoder and Bubble Tea can negotiate different arrow
 * encodings. The preview only needs the portable VT sequences, so intercept
 * navigation keys before that negotiation and feed an unambiguous sequence.
 */
export function attachNavigationKeyReporting(terminal: Terminal): void {
  terminal.attachCustomKeyEventHandler((event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return false;
    const sequence = navigationSequences[event.key];
    if (!sequence) return false;
    terminal.input(sequence, true);
    return true;
  });
}

export function resolveRuntimeURL(pageURL: string): string {
  return new URL("../tui/out.wasm.gz", pageURL).href;
}
