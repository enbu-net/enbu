import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import { container, queryButton, renderAndSettle, settle, setupDom } from "../../test/dom";
import { DevicePanel } from "./device-panel";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

describe("DevicePanel", () => {
  it("shows this device's keys", async () => {
    mocked.identity.mockResolvedValueOnce({
      backend: "tpm",
      algorithm: "P-256",
      recipient: "age1tag1example",
      device: "TPM 2.0",
      fingerprint: "aaaa-bbbb",
    });
    await renderAndSettle(<DevicePanel repoPath="/a" postQuantum onUpgraded={() => {}} />);
    expect(container.textContent).toContain("aaaa-bbbb");
    expect(container.textContent).toContain("TPM 2.0");
    expect(container.textContent).toContain("age1tag1example");
    expect(queryButton("Switch to a post-quantum key")).toBeNull();
  });

  it("upgrades a classical key and says when an admin must approve it", async () => {
    mocked.upgradeIdentity.mockResolvedValueOnce({
      backend: "keyring",
      algorithm: "ML-KEM-768+X25519",
      recipient: "age1pq",
      device_id: "d",
      fingerprint: "ffff-0000",
      pending: true,
    });
    const onUpgraded = vi.fn();
    await renderAndSettle(
      <DevicePanel repoPath="/a" postQuantum={false} onUpgraded={onUpgraded} />,
    );

    await act(async () => queryButton("Switch to a post-quantum key")?.click());
    await settle();

    expect(mocked.upgradeIdentity).toHaveBeenCalled();
    expect(onUpgraded).toHaveBeenCalled();
    expect(container.textContent).toContain("Ask an admin to approve the key update");
    expect(container.textContent).toContain("ffff-0000");
  });

  it("checks the hardware on request", async () => {
    mocked.diagnoseIdentity.mockResolvedValueOnce({
      backend: "tpm",
      available: false,
      reason: "no TPM found",
      fallback_available: true,
    });
    await renderAndSettle(<DevicePanel repoPath="/a" postQuantum onUpgraded={() => {}} />);

    await act(async () => queryButton("Check hardware")?.click());
    await settle();

    expect(container.textContent).toContain("is not available: no TPM found");
    expect(container.textContent).toContain("The OS keyring can hold keys.");
  });
});
