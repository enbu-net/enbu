/**
 * enbu decrypts with this device's identity, so it runs only where the editor
 * runs: not in a remote window, where the extension host is another machine,
 * and only in a trusted workspace. WSL is this machine: enbu there keeps its
 * keys in Windows through enbu.exe.
 */
export function refusalReason(
  remoteName: string | undefined,
  trusted: boolean,
): string | undefined {
  if (remoteName && remoteName !== "wsl") {
    return "enbu works on local folders and WSL only. Open the folder locally to use enbu.";
  }
  if (!trusted) {
    return "enbu needs a trusted workspace.";
  }
  return undefined;
}
