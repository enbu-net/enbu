import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { UpdateMethod, UpdateStatus } from "../../lib/types";
import { container, queryButton, root, settle, setupDom } from "../../test/dom";
import { UpdateSection, homebrewCommand, updateAdvice } from "./update-section";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

function status(
  method: string,
  available: boolean,
  extra: Partial<UpdateStatus> = {},
): UpdateStatus {
  return {
    method: method as UpdateMethod,
    current: "v0.9.0",
    latest: available ? "v0.10.0" : "v0.9.0",
    available,
    url: "https://github.com/enbu-net/enbu/releases/tag/v0.10.0",
    ...extra,
  };
}

async function renderAndCheck(result: UpdateStatus) {
  vi.mocked(backend).checkForUpdate.mockResolvedValueOnce(result);
  await act(async () => root.render(<UpdateSection />));
  await act(async () => queryButton("Check for updates")?.click());
  await settle();
}

describe("updateAdvice", () => {
  it("follows who updates the installation", () => {
    expect(updateAdvice(status("self", true))).toBe("install");
    expect(updateAdvice(status("homebrew", true))).toBe("homebrew");
    expect(updateAdvice(status("system_package", true))).toBe("system_package");
    expect(updateAdvice(status("manual", true))).toBe("manual");
    expect(updateAdvice(status("development", true))).toBeNull();
    expect(updateAdvice(status("editor", true))).toBeNull();
    expect(updateAdvice(status("self", false))).toBeNull();
  });
});

describe("UpdateSection", () => {
  it("says the app is up to date", async () => {
    await renderAndCheck(status("self", false));
    expect(container.textContent).toContain("enbu is up to date.");
    expect(queryButton("Update")).toBeNull();
  });

  it("installs a newer release and restarts", async () => {
    vi.mocked(backend).installUpdate.mockResolvedValueOnce(
      status("self", false, { current: "v0.10.0", latest: "v0.10.0" }),
    );
    await renderAndCheck(status("self", true));
    expect(container.textContent).toContain("v0.10.0 is available.");
    expect(container.querySelector("a")?.getAttribute("href")).toContain("v0.10.0");

    await act(async () => queryButton("Update")?.click());
    await settle();
    expect(backend.installUpdate).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain("v0.10.0 is installed.");

    await act(async () => queryButton("Restart")?.click());
    expect(backend.restartApp).toHaveBeenCalledTimes(1);
  });

  it("shows why a verification failed and lets the person try again", async () => {
    vi.mocked(backend).installUpdate.mockRejectedValueOnce({ code: "update_unverified" });
    await renderAndCheck(status("self", true));
    await act(async () => queryButton("Update")?.click());
    await settle();
    expect(container.textContent).toContain("failed signature verification");
    expect(queryButton("Update")).not.toBeNull();
  });

  it("points Homebrew installs to brew", async () => {
    await renderAndCheck(status("homebrew", true));
    expect(container.textContent).toContain(homebrewCommand);
    expect(queryButton("Update")).toBeNull();
  });

  it("points package and read-only installs to the release page", async () => {
    await renderAndCheck(status("system_package", true));
    expect(container.textContent).toContain("package manager");
    await renderAndCheck(status("manual", true));
    expect(container.textContent).toContain("cannot write to");
  });

  it("says a development build is not updated", async () => {
    await renderAndCheck(status("development", false, { latest: undefined }));
    expect(container.textContent).toContain("development build");
  });

  it("shows a failed check", async () => {
    vi.mocked(backend).checkForUpdate.mockRejectedValueOnce({ code: "unavailable" });
    await act(async () => root.render(<UpdateSection />));
    await act(async () => queryButton("Check for updates")?.click());
    await settle();
    expect(container.textContent).toContain("unavailable");
  });
});
