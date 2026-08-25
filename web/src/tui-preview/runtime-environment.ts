export function runtimeEnvironment(cols: number, rows: number): string[] {
  return ["TERM=xterm-256color", "COLORTERM=truecolor", `COLUMNS=${cols}`, `LINES=${rows}`];
}
