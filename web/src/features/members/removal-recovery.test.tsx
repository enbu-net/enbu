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
    review.mockResolvedValue({ added: ["LATEST"], removed: [], modified: [] });
    await renderAndSettle(
      <RemovalRecovery targets={"secrets/default sha256:first\nsecrets/staging sha256:second"} />,
    );
    expect(queryButton("Apply reviewed change")).toBeNull();

    await act(async () => queryButton("Review revision")?.click());
    expect(review).toHaveBeenLastCalledWith("secrets/default", "sha256:first", false);
    expect(container.textContent).toContain("+ LATEST");
    await act(async () => queryButton("Apply reviewed change")?.click());
    expect(review).toHaveBeenLastCalledWith("secrets/default", "sha256:first", true);
    expect(container.textContent).toContain("Published the reviewed change");
    expect(queryButton("Review revision")).toBeTruthy();
  });
});
