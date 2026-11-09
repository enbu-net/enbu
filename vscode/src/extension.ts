import * as vscode from "vscode";
import { EnbuPanel } from "./panel";
import { refusalReason } from "./refusal";

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("enbu");
  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("enbu.open", async () => {
      const refusal = refusalReason(vscode.env.remoteName, vscode.workspace.isTrusted);
      if (refusal) {
        void vscode.window.showErrorMessage(refusal);
        return;
      }
      await EnbuPanel.show(context, output);
    }),
  );
}

export function deactivate(): void {}
