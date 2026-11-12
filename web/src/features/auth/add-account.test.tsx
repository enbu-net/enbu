import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import {
  container,
  queryButton,
  root,
  settle,
  setupDom,
  withSession,
  clipboardWrite,
} from "../../test/dom";
import { openURL } from "../../lib/platform";
import { AddAccount } from "./add-account";
vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));
vi.mock("../../lib/platform", () => ({
  openURL: vi.fn(),
  writeClipboard: vi.fn(async (text: string) => {
    await navigator.clipboard.writeText(text);
  }),
  readClipboard: vi.fn(async () => ""),
}));
setupDom();
const mocked = vi.mocked(backend);
beforeEach(() => {
  vi.useFakeTimers();
  mocked.StartOAuthLogin.mockResolvedValue({
    session_id: "new-account",
    user_code: "ABCD-1234",
    verification_uri: "https://github.com/login/device",
    expires_at: new Date(Date.now() + 60000).toISOString(),
  });
  mocked.GetOAuthLoginStatus.mockResolvedValue({ state: "pending" });
});
describe("AddAccount", () => {
  it("starts in a dedicated screen with code copy and browser actions", async () => {
    const done = vi.fn();
    act(() => root.render(withSession(<AddAccount onDone={done} />)));
    await settle();
    expect(mocked.StartOAuthLogin).toHaveBeenCalledTimes(1);
    expect(container.querySelector("h1")?.textContent).toBe("GitHub Login");
    await act(async () => queryButton("Copy code")?.click());
    expect(clipboardWrite).toHaveBeenCalledWith("ABCD-1234");
    expect(container.textContent).toContain("Code copied");
    act(() => queryButton("Open in browser")?.click());
    expect(openURL).toHaveBeenCalledWith("https://github.com/login/device");
    await act(async () => queryButton("Cancel")?.click());
    expect(mocked.CancelOAuthLogin).toHaveBeenCalledWith("new-account");
    expect(done).toHaveBeenCalledTimes(1);
  });
  it("refreshes accounts and returns to settings after approval", async () => {
    mocked.GetOAuthLoginStatus.mockResolvedValueOnce({ state: "success" });
    const done = vi.fn(),
      refresh = vi.fn(async () => {}),
      reloadRepo = vi.fn(async () => {});
    act(() => root.render(withSession(<AddAccount onDone={done} />, { refresh, reloadRepo })));
    await settle();
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(refresh).toHaveBeenCalledWith({ force: true, invalidate: true });
    expect(reloadRepo).toHaveBeenCalledTimes(1);
    expect(done).toHaveBeenCalledTimes(1);
  });
  it("cancels a pending session when leaving the screen", async () => {
    act(() => root.render(withSession(<AddAccount onDone={() => {}} />)));
    await settle();
    act(() => root.render(<div />));
    await settle();
    expect(mocked.CancelOAuthLogin).toHaveBeenCalledWith("new-account");
  });
});
