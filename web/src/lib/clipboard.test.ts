import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const platform = vi.hoisted(() => ({
  readClipboard: vi.fn(async () => ""),
  writeClipboard: vi.fn(async () => {}),
}));
vi.mock("./platform", () => platform);

const { copySecret } = await import("./clipboard");

let writeText: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.useFakeTimers();
  writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  platform.readClipboard.mockReset();
  platform.writeClipboard.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("copySecret", () => {
  it("clears the value once the seconds pass", async () => {
    platform.readClipboard.mockResolvedValue("s3cret");
    await copySecret("s3cret", 30);
    expect(writeText).toHaveBeenCalledWith("s3cret");

    await vi.advanceTimersByTimeAsync(29_000);
    expect(platform.writeClipboard).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(platform.writeClipboard).toHaveBeenCalledWith("");
  });

  it("leaves something copied since in place", async () => {
    platform.readClipboard.mockResolvedValue("something else");
    await copySecret("s3cret", 1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(platform.writeClipboard).not.toHaveBeenCalled();
  });

  it("clears anyway when the clipboard cannot be read back", async () => {
    platform.readClipboard.mockRejectedValue(new Error("denied"));
    await copySecret("s3cret", 1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(platform.writeClipboard).toHaveBeenCalledWith("");
  });

  it("keeps the value with 0 seconds, and a newer copy replaces the pending clear", async () => {
    await copySecret("a", 0);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(platform.writeClipboard).not.toHaveBeenCalled();

    platform.readClipboard.mockResolvedValue("b");
    await copySecret("a", 5);
    await copySecret("b", 10);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(platform.readClipboard).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(platform.writeClipboard).toHaveBeenCalledTimes(1);
  });
});
