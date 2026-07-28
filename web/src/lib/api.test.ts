import { describe, it, expect, vi, beforeEach } from "vite-plus/test";
import { api } from "./api";

beforeEach(() => {
  vi.restoreAllMocks();
  Object.defineProperty(document, "cookie", {
    writable: true,
    value: "enbu_csrf=test-token",
  });
});

describe("api.auth.status", () => {
  it("returns authenticated status", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { authenticated: true, username: "testuser" },
        }),
      ),
    );

    const result = await api.auth.status();
    expect(result.authenticated).toBe(true);
    expect(result.username).toBe("testuser");
  });

  it("sends CSRF token from cookie", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { authenticated: false } })),
    );

    await api.auth.status();

    expect(fetch).toHaveBeenCalledWith(
      "/api/auth/status",
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-ENBU-Token": "test-token",
        }),
      }),
    );
  });

  it("throws on error response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { message: "not logged in", code: "not_authenticated", params: {} },
        }),
        { status: 401 },
      ),
    );

    await expect(api.auth.status()).rejects.toMatchObject({
      payload: { code: "not_authenticated", message: "not logged in" },
    });
  });
});

describe("api.gui", () => {
  it("loads selected repository status", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            selected: true,
            repo: { path: "/repo", owner: "octo", repo: "hello" },
          },
        }),
      ),
    );

    const result = await api.gui.repo();
    expect(result.selected).toBe(true);
    expect(result.repo?.owner).toBe("octo");
  });

  it("selects a repository path", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { selected: true } })),
    );

    await api.gui.selectRepo("/repo");
    expect(fetch).toHaveBeenCalledWith(
      "/api/gui/repo",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ path: "/repo" }),
      }),
    );
  });
});

describe("api.secrets", () => {
  it("lists secrets for environment", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            environment: "dev",
            secrets: [{ key: "DB_URL", value: "postgres://localhost" }],
          },
        }),
      ),
    );

    const result = await api.secrets.list("dev");
    expect(result.environment).toBe("dev");
    expect(result.secrets).toHaveLength(1);
    expect(result.secrets[0].key).toBe("DB_URL");
  });

  it("adds a secret", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { key: "NEW_KEY" } })),
    );

    const result = await api.secrets.add("NEW_KEY", "value123");
    expect(result.key).toBe("NEW_KEY");
    expect(fetch).toHaveBeenCalledWith(
      "/api/secrets",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ key: "NEW_KEY", value: "value123" }),
      }),
    );
  });

  it("deletes a secret with env param", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { deleted: "OLD_KEY" } })),
    );

    await api.secrets.delete("OLD_KEY", "staging");
    expect(fetch).toHaveBeenCalledWith(
      "/api/secrets/OLD_KEY?env=staging",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});

describe("api.environments", () => {
  it("lists environments", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            environments: [
              { name: "dev", current: true },
              { name: "staging", current: false },
            ],
          },
        }),
      ),
    );

    const result = await api.environments.list();
    expect(result.environments).toHaveLength(2);
    expect(result.environments[0].current).toBe(true);
  });

  it("switches environment", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ data: { current: "staging" } })),
    );

    const result = await api.environments.switch("staging");
    expect(result.current).toBe("staging");
    expect(fetch).toHaveBeenCalledWith(
      "/api/environments/staging/switch",
      expect.objectContaining({ method: "PUT" }),
    );
  });
});
