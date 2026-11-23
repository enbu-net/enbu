/** A worker factory for Monaco's labels: the JSON language, or anything else. */
export function monacoWorkers(
  editorWorker: new () => Worker,
  jsonWorker: new () => Worker,
): { getWorker: (id: string, label: string) => Worker } {
  return {
    getWorker: (_id, label) => (label === "json" ? new jsonWorker() : new editorWorker()),
  };
}

/**
 * Loads Monaco and installs the one MonacoEnvironment every editor shares.
 * The environment is global and Monaco asks it again whenever it restarts a
 * worker, so an editor that installed its own would hand the JSON language
 * the plain editor worker (`Missing requestHandler or method: resetSchema`).
 */
export async function loadMonaco() {
  const [monaco, editorWorker, jsonWorker] = await Promise.all([
    import("monaco-editor"),
    import("monaco-editor/editor/editor.worker?worker"),
    import("monaco-editor/languages/features/json/json.worker?worker"),
  ]);
  (
    globalThis as typeof globalThis & {
      MonacoEnvironment: ReturnType<typeof monacoWorkers>;
    }
  ).MonacoEnvironment = monacoWorkers(editorWorker.default, jsonWorker.default);
  return monaco;
}
