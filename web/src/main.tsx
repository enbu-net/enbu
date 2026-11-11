import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider, createMemoryHistory, createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";
import { host } from "./lib/host";
import { installExternalLinkHandling } from "./lib/platform";
import { startTextSize } from "./lib/settings";
import { startTheme } from "./lib/theme";
import { getLocale } from "./paraglide/runtime";
import "./app.css";

// A VS Code webview has no address to keep the route in, and its assets load
// from a relative base, so the router keeps its history in memory there.
const router = createRouter(
  host === "vscode"
    ? { routeTree, history: createMemoryHistory({ initialEntries: ["/"] }) }
    : { routeTree, basepath: import.meta.env.BASE_URL },
);

installExternalLinkHandling();
// Switching the language reloads the page, so the document language is set once:
// screen readers pronounce by it and browsers pick CJK glyphs by it.
document.documentElement.lang = getLocale();
// Before the first render, so the page never shows the other theme first.
startTheme();
startTextSize();

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
