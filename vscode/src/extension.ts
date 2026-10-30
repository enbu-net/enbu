import * as vscode from "vscode";
import { EnbuPanel } from "./panel";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("enbu");
  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("enbu.open", async () => {
      const refusal = refusalReason();
      if (refusal) {
        void vscode.window.showErrorMessage(refusal);
        return;
      }
      await EnbuPanel.show(context, output);
    }),
  );
}

export function deactivate(): void {}

/**
 * enbu decrypts with this device's identity, so it runs only where the editor
 * runs: not in a remote window, where the extension host is another machine,
 * and only in a trusted workspace.
 */
function refusalReason(): string | undefined {
  if (vscode.env.remoteName) {
    return "enbu works on local folders only. Open the folder locally to use enbu.";
  }
  if (!vscode.workspace.isTrusted) {
    return "enbu needs a trusted workspace.";
  }
  return undefined;
}
