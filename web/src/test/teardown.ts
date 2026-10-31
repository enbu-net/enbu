import { afterAll } from "vite-plus/test";

// The Wails runtime polls `window` every 50 ms from the moment it is imported
// (@wailsio/runtime/dist/drag.js). A test file that finishes sooner has its
// jsdom window torn down before that first tick, which then throws
// "window is not defined". Waiting one tick keeps the window alive for it.
afterAll(() => new Promise((resolve) => setTimeout(resolve, 60)));
