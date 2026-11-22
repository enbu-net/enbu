// Bombadil specification of the browser preview (`task gui/bombadil`):
// Bombadil clicks, types, scrolls and navigates at random through the UI
// against the in-memory preview backend, and these properties must hold in
// every state it reaches. https://antithesishq.github.io/bombadil/
import { always, eventually, now } from "@antithesishq/bombadil";
import { extract, type State } from "@antithesishq/bombadil/browser";
import en from "../messages/en.json" with { type: "json" };
import ja from "../messages/ja.json" with { type: "json" };

// The default properties (no uncaught exceptions, unhandled rejections,
// console errors or HTTP error responses) and actions.
export * from "@antithesishq/bombadil/browser/defaults";

const locales = [en, ja];

/** The trimmed text of every element on the page that matches the selector. */
function texts(state: State, selector: string): string[] {
  return [...state.document.querySelectorAll(selector)].map((el) => el.textContent?.trim() ?? "");
}

const internalShown = extract((state) =>
  texts(state, '[role="alert"]').some((text) =>
    locales.some((messages) => text.includes(messages.error_internal)),
  ),
);

// The preview backend never fails in a way the UI does not know: an
// `internal` error on screen is a render crash, an uncaught failure, or an
// error the UI does not classify.
export const noInternalError = always(() => !internalShown.current);

const loading = extract((state) =>
  texts(state, '[role="status"]').some((text) =>
    locales.some((messages) => text === messages.common_loading),
  ),
);

// A loading indicator goes away again: the preview answers every call at once.
export const loadingFinishes = always(
  now(() => loading.current).implies(eventually(() => !loading.current).within(5, "seconds")),
);

const secretKeys = extract((state) =>
  [...state.document.querySelectorAll("input[aria-label]")].flatMap((input) => {
    const label = input.getAttribute("aria-label") ?? "";
    const prefix = locales
      .map((messages) => `${messages.dashboard_value}: `)
      .find((p) => label.startsWith(p));
    return prefix ? [label.slice(prefix.length)] : [];
  }),
);

// An environment lists each secret once, however saves, deletes, imports and
// merges interleave.
export const uniqueSecretKeys = always(
  () => new Set(secretKeys.current).size === secretKeys.current.length,
);

const overflow = extract(
  (state) => state.document.documentElement.scrollWidth - state.window.innerWidth,
);

// Nothing the user types widens the page past the window.
export const noHorizontalOverflow = always(() => overflow.current <= 0);
