import { act } from "react-dom/test-utils";
import { describe, expect, it, vi } from "vite-plus/test";
import { backend } from "../../lib/backend";
import { container, queryButton, renderAndSettle, setupDom } from "../../test/dom";
import { RemovalRecovery } from "./removal-recovery";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

describe("RemovalRecovery", () => {
  it("previews a revision before publishing it, independently of other targets", async () => {
    const review = vi.mocked(backend.ReviewRemovedRevision);
    review.mockResolvedValue({
      diff: { added: ["LATEST"], removed: [], modified: [] },
      baseline: "sha256:baseline",
      kept: ["UNCHANGED"],
    });
    const onApplied = vi.fn();
    await renderAndSettle(
      <RemovalRecovery
        targets={"secrets/default sha256:first\nsecrets/staging sha256:second"}
        onApplied={onApplied}
      />,
    );
    expect(queryButton("Apply reviewed change")).toBeNull();

    await act(async () => queryButton("Review revision")?.click());
    expect(review).toHaveBeenLastCalledWith("secrets/default", "sha256:first", "");
    expect(container.textContent).toContain("+ LATEST");
    await act(async () => queryButton("Apply reviewed change")?.click());
    expect(review).toHaveBeenLastCalledWith("secrets/default", "sha256:first", "sha256:baseline");
    expect(container.textContent).toContain("UNCHANGED");
    expect(onApplied).toHaveBeenCalledWith("secrets/default sha256:first");
    expect(queryButton("Review revision")).toBeTruthy();
  });
});
