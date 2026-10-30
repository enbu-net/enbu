import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider, createMemoryHistory, createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";
import { host } from "./lib/host";
import { installExternalLinkHandling } from "./lib/platform";
import "./app.css";

// A VS Code webview has no address to keep the route in, and its assets load
// from a relative base, so the router keeps its history in memory there.
const router = createRouter(
  host === "vscode"
    ? { routeTree, history: createMemoryHistory({ initialEntries: ["/"] }) }
    : { routeTree, basepath: import.meta.env.BASE_URL },
);

installExternalLinkHandling();

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
