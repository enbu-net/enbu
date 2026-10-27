import { describe, expect, it } from "vite-plus/test";
import { contentSecurityPolicy, renderHtml } from "./webview";

const index = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link href="https://fonts.googleapis.com/css2?family=Inter&display=swap" rel="stylesheet" />
    <script type="module" crossorigin src="./assets/index-abc.js"></script>
    <link rel="stylesheet" crossorigin href="./assets/index-abc.css">
  </head>
  <body><div id="root"></div></body>
</html>`;

const options = {
  baseUri: "https://file+.vscode-resource.vscode-cdn.net/ext/media/web",
  cspSource: "https://*.vscode-cdn.net",
  nonce: "n0nce",
};

describe("renderHtml", () => {
  const html = renderHtml(index, options);

  it("loads the UI's assets from the extension", () => {
    expect(html).toContain(`<base href="${options.baseUri}/">`);
    expect(html).toContain('href="./assets/index-abc.css"');
  });

  it("puts the policy first in head, before anything loads", () => {
    const head = html.slice(html.indexOf("<head>") + "<head>".length).trimStart();
    expect(head.startsWith('<meta http-equiv="Content-Security-Policy"')).toBe(true);
  });

  it("marks every script with the nonce", () => {
    expect(html).toContain(
      '<script nonce="n0nce" type="module" crossorigin src="./assets/index-abc.js">',
    );
    expect(html.match(/<script\b/g)).toHaveLength(
      html.match(/<script nonce="n0nce"/g)?.length ?? 0,
    );
  });

  it("drops links to anything outside the extension", () => {
    expect(html).not.toContain("fonts.googleapis.com");
    expect(html).not.toContain("favicon.svg");
  });
});

describe("contentSecurityPolicy", () => {
  const policy = contentSecurityPolicy(options);

  it("denies by default and allows scripts only by nonce or from the extension", () => {
    expect(policy).toMatch(/^default-src 'none';/);
    expect(policy).toContain(
      "script-src 'nonce-n0nce' https://*.vscode-cdn.net 'wasm-unsafe-eval'",
    );
    expect(policy).not.toContain(" 'unsafe-eval'");
    expect(policy).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  });

  it("allows connections only to the extension's files", () => {
    expect(policy).toContain("connect-src https://*.vscode-cdn.net");
  });
});
