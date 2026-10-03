import { createRef, act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import * as Alert from "./alert";
import * as Popover from "./popover";
import * as Tabs from "./tabs";

describe("Park UI slot recipe components", () => {
  let container: HTMLDivElement;
  let root: ReturnType<typeof createRoot>;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("styles alert slots and forwards refs and custom classes", () => {
    const ref = createRef<HTMLDivElement>();
    act(() => {
      root.render(
        <Alert.Root ref={ref} className="custom-alert">
          <Alert.Title>Sync failed</Alert.Title>
          <Alert.Description>Try again</Alert.Description>
        </Alert.Root>,
      );
    });
    expect(ref.current).toBe(container.firstElementChild);
    expect(ref.current?.classList.contains("custom-alert")).toBe(true);
    expect(ref.current?.classList.contains("alert__root")).toBe(true);
    expect(container.querySelector("h3")?.classList.contains("alert__title")).toBe(true);
    expect(container.querySelector(".alert__description")?.textContent).toBe("Try again");
  });

  it("passes tab variants to every slot and changes the selected panel", async () => {
    await act(async () => {
      root.render(
        <Tabs.Root defaultValue="first" size="sm" variant="enclosed">
          <Tabs.List>
            <Tabs.Trigger value="first">First</Tabs.Trigger>
            <Tabs.Trigger value="second">Second</Tabs.Trigger>
          </Tabs.List>
          <Tabs.Content value="first">First panel</Tabs.Content>
          <Tabs.Content value="second">Second panel</Tabs.Content>
        </Tabs.Root>,
      );
    });
    const triggers = container.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    expect(triggers[0].classList.contains("tabs__trigger--size_sm")).toBe(true);
    expect(triggers[0].classList.contains("tabs__trigger--variant_enclosed")).toBe(true);
    await act(async () => triggers[1].click());
    expect(triggers[1].getAttribute("aria-selected")).toBe("true");
    await vi.waitFor(() => {
      expect(container.querySelector('[role="tabpanel"]:not([hidden])')?.textContent).toBe("Second panel");
    });
  });

  it("provides popover slot styles through the root provider", () => {
    act(() => {
      root.render(
        <Popover.Root open>
          <Popover.Trigger>Details</Popover.Trigger>
          <Popover.Positioner>
            <Popover.Content>
              <Popover.Title>Repository details</Popover.Title>
            </Popover.Content>
          </Popover.Positioner>
        </Popover.Root>,
      );
    });
    expect(container.querySelector(".popover__trigger")?.textContent).toBe("Details");
    expect(container.querySelector(".popover__content")).not.toBeNull();
    expect(container.querySelector(".popover__title")?.textContent).toBe("Repository details");
  });
});
