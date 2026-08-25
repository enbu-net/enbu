// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from "vite-plus/test";
import { applyPreviewMetadata } from "../../../test/preview/preview-metadata.js";

const metadata = {
  pullRequest: "197",
  pullRequestURL: "https://github.com/enbu-net/enbu/pull/197",
  ref: "feat/tui-preview-wasi",
  sha: "5805c62123456789",
};

describe("applyPreviewMetadata", () => {
  beforeEach(() => {
    document.body.innerHTML = '<a id="ref-badge">preview</a><span id="revision-label"></span>';
  });

  it("uses the PR badge and link without a ref override", () => {
    applyPreviewMetadata(document, metadata, null);

    const badge = document.getElementById("ref-badge") as HTMLAnchorElement;
    expect(badge.textContent).toBe("PR #197");
    expect(badge.href).toBe("https://github.com/enbu-net/enbu/pull/197");
  });

  it("preserves a ref query override", () => {
    const badge = document.getElementById("ref-badge") as HTMLAnchorElement;
    badge.textContent = "custom-ref";

    applyPreviewMetadata(document, metadata, "custom-ref");

    expect(badge.textContent).toBe("custom-ref");
    expect(badge.hasAttribute("href")).toBe(false);
  });
});
