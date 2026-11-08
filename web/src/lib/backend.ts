import { Service } from "../bindings/github.com/enbu-net/enbu/desktop";
import { AppError, createAppError } from "./app-error";
import { host } from "./host";
import { mockBackend } from "./mock-backend";
// In a VS Code webview the bindings reach the service through the extension host.
import "./platform";

type DesktopService = typeof Service;

/**
 * Everything the UI asks of enbu: the methods of the Go desktop.Service, by
 * their Go names and with their Go parameters. The desktop app calls them
 * through the generated Wails bindings, a VS Code webview through the same
 * bindings over the extension host (see platform.ts), and the browser preview
 * calls an in-memory mock. A new operation is a method of desktop.Service, the
 * regenerated bindings (`task gui/bindings`), and one in the mock.
 */
export type Backend = {
  [K in keyof DesktopService]: (
    ...args: Parameters<DesktopService[K]>
  ) => Promise<Awaited<ReturnType<DesktopService[K]>>>;
};

/** The desktop service's methods, by their Go names. */
export type ServiceMethod = keyof Backend;

/**
 * A failed call rejects with the error's AppError payload as its cause (see
 * desktop.ErrorPayload). Anything else, such as a binding missing in an
 * outdated build, becomes an internal error; the details go to the console.
 */
export function toAppError(err: unknown): AppError {
  if (err instanceof AppError) return err;
  const cause = (err as { cause?: unknown } | null)?.cause;
  if (
    cause &&
    typeof cause === "object" &&
    typeof (cause as { code?: unknown }).code === "string"
  ) {
    return new AppError(cause as AppError["payload"]);
  }
  console.error("desktop call failed", err);
  return createAppError("internal");
}

/** The generated bindings, rejecting with an AppError. */
export function serviceBackend(service: DesktopService): Backend {
  return Object.fromEntries(
    Object.entries(service).map(([name, method]) => [
      name,
      async (...args: unknown[]) => {
        try {
          return await (method as (...args: unknown[]) => PromiseLike<unknown>)(...args);
        } catch (err) {
          throw toAppError(err);
        }
      },
    ]),
  ) as Backend;
}

export const backend: Backend = host === "preview" ? mockBackend : serviceBackend(Service);
