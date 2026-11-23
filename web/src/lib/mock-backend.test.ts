import { describe, expect, it } from "vite-plus/test";
import { mockBackend, validEnvironmentName } from "./mock-backend";

describe("mockBackend preview user", () => {
  it("uses yashikota consistently", async () => {
    const [status, initialized, members] = await Promise.all([
      mockBackend.GetAuthStatus(),
      mockBackend.Initialize(
        { url: "", region: "", endpoint: "", path_style: false, plain_http: false },
        false,
      ),
      mockBackend.ListMembers(),
    ]);

    expect(status.username).toBe("yashikota");
    expect(initialized.username).toBe("yashikota");
    expect(members[0]).toMatchObject({ self: true, admin: true });
  });
});

describe("mockBackend membership", () => {
  it("moves an approved request into the members and can remove it again", async () => {
    const [request] = await mockBackend.ListJoinRequests();
    expect(request).toBeDefined();
    if (!request) return;

    await mockBackend.ApproveMember(request.device_id);
    expect(await mockBackend.ListJoinRequests()).not.toContainEqual(request);
    const approved = (await mockBackend.ListMembers()).find(
      (m) => m.device_id === request.device_id,
    );
    expect(approved).toMatchObject({ admin: false, self: false, fingerprint: request.fingerprint });

    await mockBackend.RemoveMember(request.device_id);
    expect((await mockBackend.ListMembers()).some((m) => m.device_id === request.device_id)).toBe(
      false,
    );
  });
});

describe("mockBackend membership errors", () => {
  it("rejects unknown devices instead of ignoring them", async () => {
    await expect(mockBackend.ApproveMember("nobody")).rejects.toBeDefined();
    await expect(mockBackend.RemoveMember("nobody")).rejects.toBeDefined();
  });
});

describe("mockBackend environment names", () => {
  it("accepts the names the real backend accepts", () => {
    expect(validEnvironmentName("staging")).toBe(true);
    expect(validEnvironmentName("feature_1.2-x")).toBe(true);
    expect(validEnvironmentName("e".repeat(100))).toBe(true);
    expect(validEnvironmentName("")).toBe(false);
    expect(validEnvironmentName("e".repeat(101))).toBe(false);
    expect(validEnvironmentName("prod.")).toBe(false);
    expect(validEnvironmentName("ステージング")).toBe(false);
    expect(validEnvironmentName("a b")).toBe(false);
  });

  it.each(["production", "Production"])("rejects creating a duplicate named %s", async (name) => {
    const before = await mockBackend.ListEnvironments();
    await expect(mockBackend.CreateEnvironment(name)).rejects.toMatchObject({
      payload: { code: "environment_already_exists" },
    });
    expect(await mockBackend.ListEnvironments()).toEqual(before);
  });

  it("rejects an invalid name instead of creating or renaming to it", async () => {
    await expect(mockBackend.CreateEnvironment("a b")).rejects.toMatchObject({
      payload: { code: "invalid_argument" },
    });
    await expect(mockBackend.RenameEnvironment("staging", "x".repeat(101))).rejects.toMatchObject({
      payload: { code: "invalid_argument" },
    });
    await expect(mockBackend.RenameEnvironment("staging", "Production")).rejects.toMatchObject({
      payload: { code: "environment_already_exists" },
    });
    await mockBackend.RenameEnvironment("staging", "Staging");
    expect((await mockBackend.ListEnvironments()).map((env) => env.name)).toContain("Staging");
    await mockBackend.RenameEnvironment("Staging", "staging");
    expect((await mockBackend.ListEnvironments()).map((env) => env.name)).toEqual(
      expect.arrayContaining(["staging", "production"]),
    );
  });
});

describe("mockBackend sign-in", () => {
  it("completes a sign-in after polling, adding the account", async () => {
    const start = await mockBackend.StartOAuthLogin();
    expect(start.user_code).not.toBe("");
    expect((await mockBackend.GetOAuthLoginStatus(start.session_id)).state).toBe("pending");
    expect(await mockBackend.GetOAuthLoginStatus(start.session_id)).toMatchObject({
      state: "success",
      username: "mona",
    });
    expect(await mockBackend.GetAuthStatus()).toMatchObject({ username: "mona" });
  });

  it("rejects a cancelled sign-in", async () => {
    const start = await mockBackend.StartOAuthLogin();
    await mockBackend.CancelOAuthLogin(start.session_id);
    await expect(mockBackend.GetOAuthLoginStatus(start.session_id)).rejects.toMatchObject({
      payload: { code: "authentication_expired" },
    });
  });
});
