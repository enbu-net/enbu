import { describe, expect, it } from "vite-plus/test";
import { mockBackend } from "./mock-backend";

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
