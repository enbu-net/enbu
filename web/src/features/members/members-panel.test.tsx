import { describe, expect, it, vi } from "vite-plus/test";
import { act } from "react-dom/test-utils";
import { displayError } from "../../lib/app-error";
import { I18nProvider } from "../../lib/i18n";
import { container, queryButton, root, setupDom } from "../../test/dom";
import { MemberAvatar, MemberRow, MembersPanel, PendingRow } from "./members-panel";

setupDom();

const sampleMember = {
  device_id: "d".repeat(64),
  fingerprint: "abcd-efgh-ijkl-mnop-qrst",
  algorithm: "p256",
  admin: false,
  self: false,
};

describe("MemberAvatar", () => {
  it("uses the GitHub avatar and keeps initials as a fallback", () => {
    act(() => {
      root.render(<MemberAvatar username="octo cat" />);
    });
    const image = container.querySelector("img");
    expect(image?.src).toContain("avatars.githubusercontent.com/octo%20cat?size=76");
    expect(container.textContent).toContain("OC");
    act(() => {
      image?.dispatchEvent(new Event("error"));
    });
    expect(image?.style.display).toBe("none");
  });
});

describe("MemberRow", () => {
  it("shows a device fingerprint without assuming a GitHub account", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <MemberRow member={sampleMember} />
        </I18nProvider>,
      );
    });
    expect(container.textContent).toContain("abcd-efgh-ijkl-mnop-qrst");
    expect(container.textContent).toContain("Member");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("button")).toBeNull();
  });

  it("offers removal for others but never for this device", () => {
    const onRemove = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <MemberRow member={sampleMember} onRemove={onRemove} />
          <MemberRow
            member={{ ...sampleMember, fingerprint: "self-self", self: true, admin: true }}
            onRemove={onRemove}
          />
        </I18nProvider>,
      );
    });
    const buttons = container.querySelectorAll("button");
    expect(buttons).toHaveLength(1);
    act(() => buttons[0]?.click());
    expect(onRemove).toHaveBeenCalledTimes(1);
    expect(container.textContent).toContain("Admin");
    expect(container.textContent).toContain("You");
  });
});

describe("accessibility: live regions", () => {
  it("loading state has role=status", async () => {
    act(() => {
      root.render(
        <I18nProvider>
          <MembersPanel
            members={[]}
            requests={[]}
            loading={true}
            error={null}
            onSync={() => {}}
            onApprove={async () => {}}
            onRemove={async () => {}}
            onErrorDismiss={() => {}}
          />
        </I18nProvider>,
      );
    });
    const status = container.querySelector('[role="status"]');
    expect(status).toBeTruthy();
  });
});

describe("MembersPanel actions", () => {
  it("delegates member sync and error dismissal", async () => {
    const onSync = vi.fn();
    const onErrorDismiss = vi.fn();
    act(() => {
      root.render(
        <I18nProvider>
          <MembersPanel
            members={[]}
            requests={[]}
            loading={false}
            error={displayError("internal")}
            onSync={onSync}
            onApprove={async () => {}}
            onRemove={async () => {}}
            onErrorDismiss={onErrorDismiss}
          />
        </I18nProvider>,
      );
    });
    act(() => queryButton("Sync")?.click());
    expect(onSync).toHaveBeenCalledTimes(1);
    act(() => container.querySelector<HTMLButtonElement>('button[aria-label="Close"]')?.click());
    expect(onErrorDismiss).toHaveBeenCalledTimes(1);
  });
});

describe("MembersPanel approval", () => {
  const request = {
    device_id: "e".repeat(64),
    fingerprint: "1111-2222-3333-4444-5555",
    algorithm: "ed25519",
    requested_at: "2026-10-06T09:30:00Z",
  };

  function renderPanel(props: Partial<Parameters<typeof MembersPanel>[0]> = {}) {
    act(() => {
      root.render(
        <I18nProvider>
          <MembersPanel
            members={[{ ...sampleMember, self: true, admin: true }, sampleMember]}
            requests={[request]}
            loading={false}
            error={null}
            onSync={() => {}}
            onApprove={async () => {}}
            onRemove={async () => {}}
            onErrorDismiss={() => {}}
            {...props}
          />
        </I18nProvider>,
      );
    });
  }

  it("lists devices that are waiting for approval", () => {
    renderPanel();
    expect(container.textContent).toContain("Waiting for approval");
    expect(container.textContent).toContain(request.fingerprint);
    expect(queryButton("Approve")).toBeTruthy();
  });

  it("shows nothing about approval when no device is waiting", () => {
    renderPanel({ requests: [] });
    expect(container.textContent).not.toContain("Waiting for approval");
  });

  it("makes the admin compare the fingerprint before approving", async () => {
    const onApprove = vi.fn(async () => {});
    renderPanel({ onApprove });
    act(() => queryButton("Approve")?.click());

    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.querySelector('[data-testid="fingerprint"]')?.textContent).toBe(
      request.fingerprint,
    );
    const confirm = Array.from(dialog?.querySelectorAll("button") ?? []).find(
      (b) => b.textContent?.trim() === "Approve",
    );
    expect(confirm?.hasAttribute("disabled")).toBe(true);
    act(() => confirm?.click());
    expect(onApprove).not.toHaveBeenCalled();

    const checkbox = dialog?.querySelector<HTMLInputElement>('input[type="checkbox"]');
    await act(async () => {
      checkbox?.click();
    });
    expect(confirm?.hasAttribute("disabled")).toBe(false);
    await act(async () => {
      confirm?.click();
      await Promise.resolve();
    });
    expect(onApprove).toHaveBeenCalledWith(request.device_id);
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it("can be cancelled without approving", () => {
    const onApprove = vi.fn(async () => {});
    renderPanel({ onApprove });
    act(() => queryButton("Approve")?.click());
    act(() => queryButton("Cancel")?.click());
    expect(container.querySelector('[role="dialog"]')).toBeNull();
    expect(onApprove).not.toHaveBeenCalled();
  });

  it("removes a member only after confirmation", async () => {
    const onRemove = vi.fn(async () => {});
    renderPanel({ onRemove, requests: [] });
    const trigger = container.querySelector<HTMLButtonElement>(
      `button[aria-label^="Remove: ${sampleMember.fingerprint}"]`,
    );
    act(() => trigger?.click());
    expect(onRemove).not.toHaveBeenCalled();
    await act(async () => {
      container
        .querySelector<HTMLButtonElement>('[role="dialog"] button[aria-label^="Remove:"]')
        ?.click();
      await Promise.resolve();
    });
    expect(onRemove).toHaveBeenCalledWith(sampleMember.device_id);
  });

  it("reports a failed approval as a displayable error", async () => {
    renderPanel({
      onApprove: async () => {
        throw new Error("boom");
      },
    });
    act(() => queryButton("Approve")?.click());
    const dialog = container.querySelector('[role="dialog"]');
    await act(async () => {
      dialog?.querySelector<HTMLInputElement>('input[type="checkbox"]')?.click();
    });
    await act(async () => {
      Array.from(dialog?.querySelectorAll("button") ?? [])
        .find((b) => b.textContent?.trim() === "Approve")
        ?.click();
      await Promise.resolve();
    });
    expect(container.textContent).not.toContain("boom");
    expect(container.textContent).toContain("An unexpected error occurred.");
  });
});

describe("PendingRow", () => {
  it("shows the algorithm and request time", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <PendingRow
            request={{
              device_id: "f".repeat(64),
              fingerprint: "aaaa-bbbb",
              algorithm: "p256",
              requested_at: "not a date",
            }}
            onApprove={() => {}}
          />
        </I18nProvider>,
      );
    });
    expect(container.textContent).toContain("P256");
    expect(container.textContent).not.toContain("Invalid Date");
  });
});

describe("MembersPanel removal", () => {
  it("warns that secrets already read must be rotated", () => {
    act(() => {
      root.render(
        <I18nProvider>
          <MembersPanel
            members={[{ ...sampleMember, self: true, admin: true }, sampleMember]}
            requests={[]}
            loading={false}
            error={null}
            onSync={() => {}}
            onApprove={async () => {}}
            onRemove={async () => {}}
            onErrorDismiss={() => {}}
          />
        </I18nProvider>,
      );
    });
    act(() =>
      container
        .querySelector<HTMLButtonElement>(
          `button[aria-label^="Remove: ${sampleMember.fingerprint}"]`,
        )
        ?.click(),
    );
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain("Rotate secrets it has already read.");
    const describedBy = dialog?.getAttribute("aria-describedby");
    expect(container.querySelector(`[id="${describedBy ?? ""}"]`)?.textContent).toContain("Rotate");
  });
});
