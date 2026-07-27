import { FitAddon, Terminal, init } from "ghostty-web";
import * as xtermPty from "xterm-pty";
import { attachMouseReporting } from "./mouse-adapter";
import { type RegisterCleanup, SessionController } from "./session-controller";
import { createPtyTerminal, resolveRuntimeURL } from "./terminal-adapter";
import { TtyServer } from "./tty-server";
import "./style.css";

const { Termios, openpty } = xtermPty;
const terminalFlags = (
  xtermPty as unknown as {
    Flags: Record<
      | "ECHO"
      | "ECHONL"
      | "ICANON"
      | "ICRNL"
      | "IEXTEN"
      | "IGNCR"
      | "INLCR"
      | "ISIG"
      | "ISTRIP"
      | "IXON"
      | "OPOST",
      number
    >;
  }
).Flags;

function requiredElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`TUI preview is missing ${selector}`);
  return element;
}

const terminalElement = requiredElement<HTMLElement>("#terminal");
const statusElement = requiredElement<HTMLElement>("#status");
const errorElement = requiredElement<HTMLElement>("#error");
const restartButton = requiredElement<HTMLButtonElement>("#restart");

const sessions = new SessionController();
let startPromise: Promise<void> | undefined;

function reportError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  statusElement.textContent = "Failed to start";
  errorElement.textContent = `The browser VM could not start.\n${message}`;
  errorElement.hidden = false;
}

async function startSession(register: RegisterCleanup): Promise<void> {
  terminalElement.replaceChildren();
  errorElement.hidden = true;
  statusElement.textContent = "Loading Ghostty…";

  if (!crossOriginIsolated) {
    throw new Error(
      "Cross-origin isolation is unavailable. Reload the preview once and try again.",
    );
  }

  await init();

  const terminal = new Terminal({
    cols: 100,
    rows: 30,
    cursorBlink: true,
    fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
    fontSize: 14,
    theme: {
      background: "#0d1117",
      foreground: "#e6edf3",
      cursor: "#58a6ff",
      selectionBackground: "#264f78",
    },
  });
  register(() => terminal.dispose());
  const fit = new FitAddon();
  register(() => fit.dispose());
  terminal.loadAddon(fit);
  terminal.open(terminalElement);
  // RunDemo requests all-motion + SGR mouse reporting. Prime ghostty-web's
  // input gate as well so early mode sequences emitted while the VM boots are
  // not missed.
  terminal.write("\x1b[?1003h\x1b[?1006h");
  terminal.attachCustomWheelEventHandler(() => terminal.hasMouseTracking());
  const detachMouseReporting = attachMouseReporting(terminal, terminalElement);
  register(detachMouseReporting);
  fit.fit();
  fit.observeResize();

  const { master, slave } = openpty();
  register(() => master.dispose());
  const settings = slave.ioctl("TCGETS");
  slave.ioctl(
    "TCSETS",
    new Termios(
      settings.iflag &
        ~(
          terminalFlags.ISTRIP |
          terminalFlags.INLCR |
          terminalFlags.IGNCR |
          terminalFlags.ICRNL |
          terminalFlags.IXON
        ),
      settings.oflag & ~terminalFlags.OPOST,
      settings.cflag,
      settings.lflag &
        ~(
          terminalFlags.ECHO |
          terminalFlags.ECHONL |
          terminalFlags.ICANON |
          terminalFlags.ISIG |
          terminalFlags.IEXTEN
        ),
      settings.cc,
    ),
  );
  (
    master as unknown as {
      activate(terminal: ReturnType<typeof createPtyTerminal>): void;
    }
  ).activate(createPtyTerminal(terminal));

  statusElement.textContent = "Booting enbu…";
  const worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
  register(() => worker.terminate());

  let ready = false;
  const workerReady = new Promise<void>((resolve, reject) => {
    const onError = (event: ErrorEvent) => {
      if (ready) reportError(event.message);
      else reject(new Error(event.message));
    };
    const onMessage = (event: MessageEvent<unknown>) => {
      if (typeof event.data !== "object" || event.data === null) return;
      const message = event.data as { type?: string; error?: string };
      if (message.type === "ready") {
        ready = true;
        resolve();
      }
      if (message.type === "error") {
        const error = new Error(message.error ?? "Unknown worker error");
        if (ready) reportError(error);
        else reject(error);
      }
    };
    worker.addEventListener("error", onError);
    worker.addEventListener("message", onMessage);
    register(() => {
      worker.removeEventListener("error", onError);
      worker.removeEventListener("message", onMessage);
    });
  });

  const tty = new TtyServer(slave);
  tty.start(worker);
  register(() => tty.stop());
  worker.postMessage({ type: "init", imageURL: resolveRuntimeURL(window.location.href) });
  await workerReady;
  terminal.focus();
  statusElement.textContent = terminal.hasMouseTracking()
    ? "Interactive · keyboard and mouse enabled"
    : "Interactive · keyboard enabled · mouse unavailable";
}

function restart(): Promise<void> {
  if (startPromise) return startPromise;
  restartButton.disabled = true;
  startPromise = sessions
    .restart(startSession)
    .then(() => {})
    .catch(reportError)
    .finally(() => {
      startPromise = undefined;
      restartButton.disabled = false;
    });
  return startPromise;
}

restartButton.addEventListener("click", () => void restart());
void restart();
