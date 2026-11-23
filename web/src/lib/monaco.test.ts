import { describe, expect, it } from "vite-plus/test";
import { monacoWorkers } from "./monaco";

class EditorWorker {}
class JsonWorker {}

describe("monacoWorkers", () => {
  it("gives the JSON language its worker and every other label the editor worker", () => {
    const environment = monacoWorkers(
      EditorWorker as unknown as new () => Worker,
      JsonWorker as unknown as new () => Worker,
    );
    expect(environment.getWorker("1", "json")).toBeInstanceOf(JsonWorker);
    expect(environment.getWorker("2", "editorWorkerService")).toBeInstanceOf(EditorWorker);
    expect(environment.getWorker("3", "toml")).toBeInstanceOf(EditorWorker);
  });
});
