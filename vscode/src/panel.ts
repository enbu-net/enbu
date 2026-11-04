import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import { internalError, isWebURL, parseWebviewMessage, type HostMessage } from "./protocol";
import { RpcError } from "./rpc";
import { resolveBinary, startSidecar, type Sidecar } from "./sidecar";
import { renderHtml } from "./webview";

/**
 * The enbu panel: the desktop app's UI in a webview, served by its own
 * `enbu rpc --stdio`. The webview only talks to the extension host, which
 * relays calls to enbu and enbu's events back.
 */
export class EnbuPanel {
  static #current: EnbuPanel | undefined;

  readonly #panel: vscode.WebviewPanel;
  readonly #output: vscode.OutputChannel;
  #sidecar: Sidecar | undefined;
  #disposed = false;

  /** Shows the panel, starting enbu the first time. */
  static async show(context: vscode.ExtensionContext, output: vscode.OutputChannel): Promise<void> {
    if (EnbuPanel.#current) {
      EnbuPanel.#current.#panel.reveal();
      return;
    }
    const root = vscode.Uri.joinPath(context.extensionUri, "media", "web");
    const panel = vscode.window.createWebviewPanel("enbu", "enbu", vscode.ViewColumn.Active, {
      enableScripts: true,
      // The UI keeps its screen in memory; hiding the tab must not reset it.
      retainContextWhenHidden: true,
      localResourceRoots: [root],
    });
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, "media", "icon.png");
    const current = new EnbuPanel(panel, output);
    EnbuPanel.#current = current;
    await current.#start(context, root);
  }

  private constructor(panel: vscode.WebviewPanel, output: vscode.OutputChannel) {
    this.#panel = panel;
    this.#output = output;
    panel.onDidDispose(() => this.#dispose());
  }

  async #start(context: vscode.ExtensionContext, root: vscode.Uri): Promise<void> {
    const binary = resolveBinary(
      vscode.workspace.getConfiguration("enbu").get<string>("path", ""),
      context.extensionPath,
      process.platform,
      process.arch,
    );
    const folder = vscode.workspace.workspaceFolders?.find((f) => f.uri.scheme === "file");
    let sidecar: Sidecar;
    try {
      sidecar = await startSidecar({
        binary,
        cwd: context.extensionPath,
        handlers: {
          pickDirectory: () => this.#pickDirectory(),
          openExternal: (url) => this.#openExternal(url),
          event: (name, data) => this.#post({ type: "event", name, data }),
        },
        log: (text) => this.#output.append(text),
        onExit: (code) => this.#exited(code),
      });
    } catch {
      // Closing the panel while enbu starts is not a failure to report.
      if (this.#disposed) return;
      this.#panel.dispose();
      void vscode.window.showErrorMessage(
        `Could not start enbu (${binary}). Install enbu, or set enbu.path to the enbu binary.`,
      );
      return;
    }
    if (this.#disposed) {
      sidecar.dispose();
      return;
    }
    this.#sidecar = sidecar;
    this.#output.appendLine(`enbu ${sidecar.info.app_version} (${binary})`);

    // Open the workspace folder's repository, as choosing it in the desktop
    // app would. A folder that is not a repository leaves the start screen.
    if (folder) {
      await sidecar.client.request("SelectRepository", [folder.uri.fsPath]).catch(() => undefined);
    }

    const methods = new Set(sidecar.info.methods);
    this.#panel.webview.onDidReceiveMessage((data: unknown) => {
      const message = parseWebviewMessage(data, methods);
      if (message?.type === "call") {
        sidecar.client.request(message.method, message.params).then(
          (result) => this.#post({ type: "result", id: message.id, result }),
          (err: unknown) =>
            this.#post({
              type: "error",
              id: message.id,
              error: err instanceof RpcError && err.data ? err.data : internalError,
            }),
        );
      } else if (message?.type === "openExternal") {
        void this.#openExternal(message.url);
      }
    });

    const index = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(root, "index.html"));
    if (this.#disposed) return;
    const webview = this.#panel.webview;
    this.#panel.webview.html = renderHtml(new TextDecoder().decode(index), {
      baseUri: webview.asWebviewUri(root).toString(),
      cspSource: webview.cspSource,
      nonce: randomBytes(16).toString("base64"),
    });
  }

  async #pickDirectory(): Promise<string> {
    const picked = await vscode.window.showOpenDialog({
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: "Select repository",
    });
    return picked?.[0]?.fsPath ?? "";
  }

  async #openExternal(url: string): Promise<void> {
    if (!isWebURL(url)) throw new Error("not a web URL");
    await vscode.env.openExternal(vscode.Uri.parse(url, true));
  }

  #post(message: HostMessage): void {
    if (this.#disposed) return;
    void this.#panel.webview.postMessage(message);
  }

  #exited(code: number | null): void {
    if (this.#disposed) return;
    this.#panel.dispose();
    void vscode.window.showErrorMessage(
      `enbu stopped (exit code ${String(code)}). See the enbu output for details, and open enbu again.`,
    );
  }

  #dispose(): void {
    this.#disposed = true;
    this.#sidecar?.dispose();
    this.#sidecar = undefined;
    if (EnbuPanel.#current === this) EnbuPanel.#current = undefined;
  }
}
