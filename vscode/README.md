# enbu for VS Code

Manage the team's encrypted `.env` secrets from VS Code, in the same UI as the
enbu desktop app. Run **enbu: Open enbu** from the Command Palette.

The extension runs `enbu rpc --stdio` on this machine and shows the desktop
app's UI in a webview. enbu decrypts with this device's identity, so the
extension works only in local, trusted workspaces: not in Remote - SSH, WSL,
Dev Containers, Codespaces, or vscode.dev.

## Settings

- `enbu.path`: the `enbu` binary to run. When empty, the extension uses the
  binary bundled for this platform (`bin/<platform>-<arch>/`), then `enbu` on
  `PATH`. On macOS, a Secure Enclave identity works only with the binary that
  created it, so point this at that binary.

## Development

```bash
task vscode/build   # builds web/dist-vscode, then dist/extension.cjs and media/
task vscode/test
task vscode/check
```

To try it, open `vscode/` in VS Code and start the **Extension Development
Host** (F5) with `enbu` on `PATH` or `enbu.path` set.

How it fits together:

- `src/sidecar.ts` starts `enbu rpc --stdio` and completes the handshake
  (`desktop/rpc` is the server).
- `src/panel.ts` relays the webview's calls to enbu and enbu's events back,
  and answers enbu's folder dialog and browser requests.
- `src/webview.ts` serves `web/dist-vscode` with a strict Content Security
  Policy. `web/src/lib/vscode.ts` is the webview side.

Params and results carry secret values. Nothing in the extension logs them.
