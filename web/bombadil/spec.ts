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

/** The page's visible text, one trimmed line per entry. */
function lines(state: State): string[] {
  return state.document.body.innerText.split("\n").map((line) => line.trim());
}

const internalShown = extract((state) => {
  const text = state.document.body.innerText;
  return locales.some((messages) => text.includes(messages.error_internal));
});

// The preview backend never fails in a way the UI does not know: an
// `internal` error anywhere on screen (the global alert or an inline one) is
// a render crash, an uncaught failure, or an error the UI does not classify.
export const noInternalError = always(() => !internalShown.current);

// What the screens and both editors show while they load.
const loadingTexts = [...locales.map((messages) => messages.common_loading), "Starting TOML LSP"];
const loading = extract((state) => lines(state).some((line) => loadingTexts.includes(line)));

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
