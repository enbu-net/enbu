import type { Terminal } from "ghostty-web";

type MousePosition = { column: number; row: number };

function modifierCode(event: MouseEvent): number {
  return (event.shiftKey ? 4 : 0) + (event.altKey ? 8 : 0) + (event.ctrlKey ? 16 : 0);
}

function buttonCode(button: number): number {
  if (button === 1) return 1;
  if (button === 2) return 2;
  return 0;
}

export function encodeMouseEvent(
  event: MouseEvent,
  position: MousePosition,
  action: "press" | "release" | "move",
): string {
  let code = buttonCode(event.button);
  if (action === "move") {
    if (event.buttons === 0) code = 3;
    else if ((event.buttons & 2) !== 0) code = 2;
    else if ((event.buttons & 4) !== 0) code = 1;
    code += 32;
  }
  code += modifierCode(event);
  return `\x1b[<${code};${position.column};${position.row}${action === "release" ? "m" : "M"}`;
}

export function encodeWheelEvent(event: WheelEvent, position: MousePosition): string {
  const code = (event.deltaY < 0 ? 64 : 65) + modifierCode(event);
  return `\x1b[<${code};${position.column};${position.row}M`;
}

function terminalPosition(
  event: MouseEvent,
  canvas: HTMLCanvasElement,
  terminal: Terminal,
): MousePosition | undefined {
  const bounds = canvas.getBoundingClientRect();
  if (bounds.width === 0 || bounds.height === 0) return undefined;
  const column = Math.floor(((event.clientX - bounds.left) / bounds.width) * terminal.cols) + 1;
  const row = Math.floor(((event.clientY - bounds.top) / bounds.height) * terminal.rows) + 1;
  if (column < 1 || column > terminal.cols || row < 1 || row > terminal.rows) return undefined;
  return { column, row };
}

/**
 * ghostty-web parses terminal mouse modes but does not yet forward DOM mouse
 * events as escape sequences. Bridge its canvas to the PTY using SGR encoding.
 */
export function attachMouseReporting(terminal: Terminal, host: HTMLElement): () => void {
  const canvas = host.querySelector("canvas");
  if (!(canvas instanceof HTMLCanvasElement)) {
    throw new Error("Ghostty did not create a terminal canvas");
  }

  let lastMoveCell = "";
  const send = (event: MouseEvent, action: "press" | "release" | "move") => {
    if (!terminal.hasMouseTracking()) return;
    const position = terminalPosition(event, canvas, terminal);
    if (!position) return;
    if (action === "move") {
      const cell = `${position.column}:${position.row}`;
      if (cell === lastMoveCell) return;
      lastMoveCell = cell;
    } else {
      lastMoveCell = "";
    }
    event.preventDefault();
    terminal.input(encodeMouseEvent(event, position, action), true);
  };
  const onMouseDown = (event: MouseEvent) => send(event, "press");
  const onMouseUp = (event: MouseEvent) => send(event, "release");
  const onMouseMove = (event: MouseEvent) => send(event, "move");
  const onWheel = (event: WheelEvent) => {
    if (!terminal.hasMouseTracking()) return;
    if (event.deltaY === 0) return;
    const position = terminalPosition(event, canvas, terminal);
    if (!position) return;
    event.preventDefault();
    terminal.input(encodeWheelEvent(event, position), true);
  };

  canvas.addEventListener("mousedown", onMouseDown, { capture: true });
  canvas.addEventListener("mouseup", onMouseUp, { capture: true });
  canvas.addEventListener("mousemove", onMouseMove, { capture: true });
  canvas.addEventListener("wheel", onWheel, { capture: true, passive: false });

  return () => {
    canvas.removeEventListener("mousedown", onMouseDown, { capture: true });
    canvas.removeEventListener("mouseup", onMouseUp, { capture: true });
    canvas.removeEventListener("mousemove", onMouseMove, { capture: true });
    canvas.removeEventListener("wheel", onWheel, { capture: true });
  };
}
