/**
 * The browser preview (GitHub Pages, or `vp dev` with ?mock) runs the UI
 * without the desktop shell, against the in-memory preview backend.
 */
export const isPreview =
  (typeof window !== "undefined" && new URLSearchParams(window.location.search).has("mock")) ||
  import.meta.env.BASE_URL.includes("/enbu/");
