import { describe, expect, it } from "vite-plus/test";
import { mockBackend } from "./mock-backend";

describe("mockBackend preview user", () => {
  it("uses yashikota consistently", async () => {
    const [status, initialized, owners, members] = await Promise.all([
      mockBackend.authStatus(),
      mockBackend.initialize(),
      mockBackend.listRepositoryOwners(),
      mockBackend.listMembers(),
    ]);

    expect(status.username).toBe("yashikota");
    expect(initialized.username).toBe("yashikota");
    expect(owners).toContainEqual({ login: "yashikota", organization: false });
    expect(members[0]).toMatchObject({ self: true, admin: true });
  });
});

describe("mockBackend membership", () => {
  it("moves an approved request into the members and can remove it again", async () => {
    const [request] = await mockBackend.listJoinRequests();
    expect(request).toBeDefined();
    if (!request) return;

    await mockBackend.approveMember(request.device_id);
    expect(await mockBackend.listJoinRequests()).not.toContainEqual(request);
    const approved = (await mockBackend.listMembers()).find(
      (m) => m.device_id === request.device_id,
    );
    expect(approved).toMatchObject({ admin: false, self: false, fingerprint: request.fingerprint });

    await mockBackend.removeMember(request.device_id);
    expect((await mockBackend.listMembers()).some((m) => m.device_id === request.device_id)).toBe(
      false,
    );
  });
});
