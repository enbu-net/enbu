/**
 * Turns the UI's index.html (web/dist-vscode) into a webview page: assets load
 * from the extension through baseUri, and a strict Content Security Policy
 * allows only the extension's own files, the nonce'd entry scripts, and the
 * GitHub avatars the desktop app shows too.
 */
export interface PageOptions {
  /** The webview URI of the UI's directory, without a trailing slash. */
  baseUri: string;
  /** webview.cspSource */
  cspSource: string;
  nonce: string;
}

export function contentSecurityPolicy({ cspSource, nonce }: PageOptions): string {
  return [
    "default-src 'none'",
    `base-uri ${cspSource}`,
    "form-action 'none'",
    `img-src ${cspSource} data: https://avatars.githubusercontent.com`,
    `font-src ${cspSource} data:`,
    // Panda, Ark UI and Monaco set inline styles.
    `style-src ${cspSource} 'unsafe-inline'`,
    // The TOML language server is WebAssembly.
    `script-src 'nonce-${nonce}' ${cspSource} 'wasm-unsafe-eval'`,
    // Workers start from blob: bootstraps; see web/src/lib/vscode.ts.
    `worker-src ${cspSource} blob:`,
    `connect-src ${cspSource}`,
  ].join("; ");
}

export function renderHtml(indexHtml: string, options: PageOptions): string {
  const head = [
    `<meta http-equiv="Content-Security-Policy" content="${escapeAttribute(contentSecurityPolicy(options))}">`,
    `<base href="${escapeAttribute(options.baseUri)}/">`,
  ].join("\n    ");
  return (
    indexHtml
      // Web fonts and the favicon come from outside the extension; the UI
      // falls back to the editor's fonts.
      .replace(/<link\b[^>]*\bhref="(?:https?:)?\/[^"]*"[^>]*>\s*/gi, "")
      .replace(/<script\b/gi, `<script nonce="${escapeAttribute(options.nonce)}"`)
      .replace(/<head>/i, `<head>\n    ${head}`)
  );
}

function escapeAttribute(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
