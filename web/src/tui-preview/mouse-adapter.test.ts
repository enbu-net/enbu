import { describe, expect, it, vi } from "vite-plus/test";
import type { Terminal } from "ghostty-web";
import { attachMouseReporting, encodeMouseEvent, encodeWheelEvent } from "./mouse-adapter";

const position = { column: 12, row: 7 };

describe("encodeMouseEvent", () => {
  it("encodes press and release using the SGR mouse protocol", () => {
    const event = new MouseEvent("mousedown", { button: 0 });
    expect(encodeMouseEvent(event, position, "press")).toBe("\x1b[<0;12;7M");
    expect(encodeMouseEvent(event, position, "release")).toBe("\x1b[<0;12;7m");
  });

  it("encodes all-motion events and modifiers", () => {
    const event = new MouseEvent("mousemove", { buttons: 0, ctrlKey: true });
    expect(encodeMouseEvent(event, position, "move")).toBe("\x1b[<51;12;7M");
  });
});

describe("encodeWheelEvent", () => {
  it("encodes both wheel directions", () => {
    expect(encodeWheelEvent(new WheelEvent("wheel", { deltaY: -1 }), position)).toBe(
      "\x1b[<64;12;7M",
    );
    expect(encodeWheelEvent(new WheelEvent("wheel", { deltaY: 1 }), position)).toBe(
      "\x1b[<65;12;7M",
    );
  });
});

describe("attachMouseReporting", () => {
  it("gates tracking, maps canvas coordinates, forwards input, and cleans up", () => {
    const host = document.createElement("div");
    const canvas = document.createElement("canvas");
    host.append(canvas);
    vi.spyOn(canvas, "getBoundingClientRect").mockReturnValue({
      x: 10,
      y: 20,
      left: 10,
      top: 20,
      right: 110,
      bottom: 120,
      width: 100,
      height: 100,
      toJSON: () => ({}),
    });
    const hasMouseTracking = vi.fn(() => false);
    const input = vi.fn();
    const terminal = { cols: 10, rows: 5, hasMouseTracking, input } as unknown as Terminal;
    const cleanup = attachMouseReporting(terminal, host);
    const press = () =>
      canvas.dispatchEvent(
        new MouseEvent("mousedown", { bubbles: true, cancelable: true, clientX: 60, clientY: 70 }),
      );

    press();
    expect(input).not.toHaveBeenCalled();
    hasMouseTracking.mockReturnValue(true);
    press();
    expect(input).toHaveBeenCalledWith("\x1b[<0;6;3M", true);

    const move = new MouseEvent("mousemove", {
      bubbles: true,
      cancelable: true,
      clientX: 60,
      clientY: 70,
    });
    canvas.dispatchEvent(move);
    canvas.dispatchEvent(move);
    expect(input).toHaveBeenCalledTimes(2);

    canvas.dispatchEvent(new WheelEvent("wheel", { cancelable: true, deltaX: 1, deltaY: 0 }));
    expect(input).toHaveBeenCalledTimes(2);
    cleanup();
    press();
    expect(input).toHaveBeenCalledTimes(2);
  });
});
