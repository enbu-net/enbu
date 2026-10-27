import { describe, expect, it, vi } from "vite-plus/test";
import { createAuthRefresher } from "./auth-refresh";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("createAuthRefresher", () => {
  it("shares an in-flight refresh across repeated calls", async () => {
    const pending = deferred<{ authenticated: boolean; workspace_configured: boolean }>();
    const fetchStatus = vi.fn(() => pending.promise);
    const setStatus = vi.fn();
    const refresher = createAuthRefresher({ fetchStatus, setStatus, now: () => 1000 });

    const first = refresher.refresh({ force: true });
    const second = refresher.refresh({ force: true });

    expect(fetchStatus).toHaveBeenCalledTimes(1);
    pending.resolve({ authenticated: true, workspace_configured: false });
    await Promise.all([first, second]);
    expect(setStatus).toHaveBeenCalledWith({ authenticated: true, workspace_configured: false });
  });

  it("throttles non-forced refreshes within the minimum interval", async () => {
    let now = 1000;
    const fetchStatus = vi.fn(async () => ({ authenticated: true, workspace_configured: false }));
    const setStatus = vi.fn();
    const refresher = createAuthRefresher({ fetchStatus, setStatus, now: () => now });

    await refresher.refresh();
    now += 1000;
    await refresher.refresh();
    now += 4000;
    await refresher.refresh();

    expect(fetchStatus).toHaveBeenCalledTimes(2);
  });

  it("lets forced refreshes bypass the throttle", async () => {
    const fetchStatus = vi.fn(async () => ({ authenticated: true, workspace_configured: false }));
    const refresher = createAuthRefresher({ fetchStatus, setStatus: vi.fn(), now: () => 1000 });

    await refresher.refresh({ force: true });
    await refresher.refresh({ force: true });

    expect(fetchStatus).toHaveBeenCalledTimes(2);
  });

  it("fetches again after a running request when the state it depends on changed", async () => {
    const stale = deferred<{ authenticated: boolean; workspace_configured: boolean }>();
    const fetchStatus = vi
      .fn()
      .mockImplementationOnce(() => stale.promise)
      .mockResolvedValueOnce({ authenticated: false, workspace_configured: true });
    const setStatus = vi.fn();
    const refresher = createAuthRefresher({ fetchStatus, setStatus, now: () => 1000 });

    const running = refresher.refresh({ force: true });
    const first = refresher.refresh({ force: true, invalidate: true });
    const second = refresher.refresh({ force: true, invalidate: true });
    expect(fetchStatus).toHaveBeenCalledTimes(1);

    stale.resolve({ authenticated: false, workspace_configured: false });
    await Promise.all([running, first, second]);

    expect(fetchStatus).toHaveBeenCalledTimes(2);
    expect(setStatus).toHaveBeenLastCalledWith({
      authenticated: false,
      workspace_configured: true,
    });
  });
});
