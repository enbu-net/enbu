# enbu for VS Code

Manage the team's encrypted `.env` secrets from VS Code, in the same UI as the
enbu desktop app. Run **enbu: Open enbu** from the Command Palette.

The extension runs `enbu rpc --stdio` on this machine and shows the desktop
app's UI in a webview. enbu decrypts with this device's identity, so the
extension works only in local, trusted workspaces: not in Remote - SSH, WSL,
Dev Containers, Codespaces, or vscode.dev.

## Install

Each release attaches one VSIX per platform, with the enbu CLI of that
release inside: `enbu-vscode_<version>_<os>_<arch>.vsix` (linux and windows
on amd64 and arm64, darwin on arm64). Install the one for your machine:

```bash
code --install-extension enbu-vscode_v1.2.3_darwin_arm64.vsix
```

The release's `checksums.txt`, cosign bundles and GitHub attestations cover
the VSIX files like every other asset.

## Settings

- `enbu.path`: the `enbu` binary to run. When empty, the extension uses the
  binary bundled for this platform (`bin/<platform>-<arch>/`), then `enbu` on
  `PATH`. On macOS, a Secure Enclave identity works only with the binary that
  created it, so point this at that binary.

## Development

```bash
task vscode/build   # builds web/dist-vscode, then dist/extension.cjs and media/
task vscode/package # vscode/enbu-vscode.vsix with this machine's enbu inside
task vscode/test
task vscode/check
```

`scripts/package.mjs --enbu PATH [--target TARGET] [--version VERSION]`
puts the binary in `bin/<target>/` and builds a VSIX for that VS Code target
only (default: this machine). The release build runs it once per platform.

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
