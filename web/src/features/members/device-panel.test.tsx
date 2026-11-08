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
      algorithm: "MLKEM768-P256",
      recipient: "age1tagpq1example",
      device: "TPM 2.0",
      fingerprint: "aaaa-bbbb",
    });
    await renderAndSettle(<DevicePanel repoPath="/a" />);
    expect(container.textContent).toContain("aaaa-bbbb");
    expect(container.textContent).toContain("TPM 2.0");
    expect(container.textContent).toContain("age1tagpq1example");
  });

  it("checks the hardware on request", async () => {
    mocked.diagnoseIdentity.mockResolvedValueOnce({
      backend: "tpm",
      available: false,
      fallback_available: true,
    });
    await renderAndSettle(<DevicePanel repoPath="/a" />);

    await act(async () => queryButton("Check hardware")?.click());
    await settle();

    expect(container.textContent).toContain("Hardware key storage (tpm) is not available.");
    expect(container.textContent).toContain("The OS keyring can hold keys.");
  });

  it("says when systemd-creds holds keys instead of the OS keyring", async () => {
    mocked.diagnoseIdentity.mockResolvedValueOnce({
      backend: "tpm",
      available: false,
      fallback_available: true,
      fallback: "systemd-creds",
    });
    await renderAndSettle(<DevicePanel repoPath="/a" />);

    await act(async () => queryButton("Check hardware")?.click());
    await settle();

    expect(container.textContent).toContain("systemd-creds can hold keys.");
  });
});
