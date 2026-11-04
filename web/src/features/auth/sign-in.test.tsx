import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { backend } from "../../lib/backend";
import type { Session } from "../../lib/session";
import { container, queryButton, root, setupDom, withSession } from "../../test/dom";
import { SignIn } from "./sign-in";
import { setLocale } from "../../paraglide/runtime";

vi.mock("../../lib/backend", async () => ({
  backend: (await import("../../test/backend-mock")).createBackendMock(),
}));

setupDom();

const mocked = vi.mocked(backend);

function renderSignIn(session: Partial<Session> = {}) {
  act(() => {
    root.render(
      <>
        {withSession(<SignIn />, {
          status: { authenticated: false, workspace_configured: false },
          ...session,
        })}
      </>,
    );
  });
}

async function connect() {
  await act(async () => {
    queryButton("Connect with GitHub")?.click();
    await Promise.resolve();
  });
}

describe("SignIn", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mocked.startOAuthLogin.mockReset();
    mocked.oauthStatus.mockReset();
    mocked.cancelOAuthLogin.mockClear();
    mocked.startOAuthLogin.mockResolvedValue({
      session_id: "session",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
  });

  it("shows the login action and language selector without a redundant heading", () => {
    renderSignIn();

    expect(queryButton("Connect with GitHub")).toBeTruthy();
    expect(container.textContent).not.toContain("Sign in to GitHub");
    expect(container.querySelector("select")?.value).toBe("en");
  });

  it("shows the Japanese authentication label in Japanese", async () => {
    await setLocale("ja", { reload: false });
    renderSignIn();

    expect(queryButton("GitHub認証")).toBeTruthy();
    await setLocale("en", { reload: false });
  });

  it("reloads the session once the browser finishes signing in", async () => {
    const refresh = vi.fn(async () => {});
    const reloadRepo = vi.fn(async () => {});
    mocked.oauthStatus.mockResolvedValue({ state: "success", username: "octo" });
    renderSignIn({ refresh, reloadRepo });

    await connect();
    await act(async () => vi.advanceTimersByTimeAsync(1000));

    expect(mocked.oauthStatus).toHaveBeenCalledWith("session");
    expect(refresh).toHaveBeenCalledWith({ force: true, invalidate: true });
    expect(reloadRepo).toHaveBeenCalledTimes(1);
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });

  it("shows a terminal error when OAuth status polling rejects", async () => {
    mocked.oauthStatus.mockRejectedValue(new Error("poll failed"));
    renderSignIn();

    await connect();
    await act(async () => vi.advanceTimersByTimeAsync(1000));

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("poll failed");
    expect(queryButton("Try again")).toBeTruthy();
  });

  it("cancels and resets a pending OAuth login", async () => {
    mocked.oauthStatus.mockResolvedValue({ state: "pending" });
    renderSignIn();

    await connect();
    await act(async () => {
      queryButton("Cancel")?.click();
      await Promise.resolve();
    });

    expect(mocked.cancelOAuthLogin).toHaveBeenCalledWith("session");
    expect(queryButton("Connect with GitHub")).toBeTruthy();
  });

  it("shows why sign-in could not start", async () => {
    mocked.startOAuthLogin.mockRejectedValue(new Error("no network"));
    renderSignIn();

    await connect();

    expect(container.textContent).toContain("An unexpected error occurred");
    expect(container.textContent).not.toContain("no network");
  });
});
