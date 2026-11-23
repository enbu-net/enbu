import { always } from "@antithesishq/bombadil";
import { actions, extract, registerCustomAction } from "@antithesishq/bombadil/browser";
import en from "../messages/en.json" with { type: "json" };
import ja from "../messages/ja.json" with { type: "json" };

const locales = [en, ja];

function panel(document: Document) {
  return document.querySelector<HTMLElement>('[role="tabpanel"]:not([hidden])');
}

function button(root: ParentNode | null, labels: readonly string[]) {
  return [...(root?.querySelectorAll<HTMLButtonElement>("button") ?? [])].find((candidate) =>
    labels.includes(candidate.getAttribute("aria-label") ?? candidate.textContent?.trim() ?? ""),
  );
}

function select(root: HTMLElement | null, labels: readonly string[]) {
  return [...(root?.querySelectorAll<HTMLSelectElement>("select") ?? [])].find((candidate) =>
    [...(candidate.labels ?? [])].some((label) => labels.includes(label.textContent.trim())),
  );
}

function environmentButton(root: HTMLElement | null) {
  return [...(root?.querySelectorAll<HTMLButtonElement>("button[aria-label]") ?? [])].find((item) =>
    locales.some((messages) =>
      item.getAttribute("aria-label")?.startsWith(messages.dashboard_currentEnvironment + ": "),
    ),
  );
}

function currentEnvironment(root: HTMLElement | null) {
  const label = environmentButton(root)?.getAttribute("aria-label") ?? "";
  return label.slice(label.indexOf(": ") + 2);
}

function valueField(root: HTMLElement | null, key: string) {
  return [
    ...(root?.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
      "input[aria-label], textarea[aria-label]",
    ) ?? []),
  ].find((field) =>
    locales.some(
      (messages) => field.getAttribute("aria-label") === messages.dashboard_value + ": " + key,
    ),
  );
}

const consistentMaskControls = extract(({ document }) =>
  [
    ...(panel(document)?.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
      "input[aria-label], textarea[aria-label]",
    ) ?? []),
  ].every((field) => {
    if (
      !locales.some((m) => field.getAttribute("aria-label")?.startsWith(m.dashboard_value + ": "))
    ) {
      return true;
    }
    const masked = field.type === "password";
    const expected = locales.map((m) => (masked ? m.dashboard_showValue : m.dashboard_hideValue));
    return button(field.parentElement, expected) !== undefined;
  }),
);

export const secretMaskMatchesControl = always(() => consistentMaskControls.current);

const environmentRowsValid = extract(({ document }) => {
  const activeTab = document.querySelector('[role="tab"][aria-selected="true"]');
  if (!locales.some((m) => activeTab?.textContent?.trim() === m.dashboard_environments))
    return true;
  const rows = [
    ...(panel(document)?.querySelectorAll<HTMLButtonElement>("button[aria-label]") ?? []),
  ].flatMap((item) => {
    const label = item.getAttribute("aria-label") ?? "";
    const prefix = locales
      .map((m) => m.environments_delete + ": ")
      .find((p) => label.startsWith(p));
    return prefix ? [{ name: label.slice(prefix.length), disabled: item.disabled }] : [];
  });
  return (
    rows.length === 0 ||
    (new Set(rows.map((row) => row.name.toLowerCase())).size === rows.length &&
      rows.filter((row) => row.disabled).length === 1)
  );
});
export const environmentNamesAndDeletionControlsAreConsistent = always(
  () => environmentRowsValid.current,
);

const historyListsValid = extract(({ document }) => {
  const root = panel(document);
  const from = select(
    root,
    locales.map((m) => m.history_from),
  );
  const to = select(
    root,
    locales.map((m) => m.history_to),
  );
  if (!from || !to) return true;
  const revisions = [...from.options].map((option) => Number(option.value));
  const olderRevisions = [...from.options].slice(1).map((option) => option.textContent.trim());
  const restoreLabels = [...(root?.querySelectorAll("button[aria-label]") ?? [])].flatMap(
    (item) => {
      const label = item.getAttribute("aria-label") ?? "";
      const prefix = locales.map((m) => m.history_restore + ": ").find((p) => label.startsWith(p));
      return prefix ? [label.slice(prefix.length)] : [];
    },
  );
  return (
    revisions.length === to.options.length &&
    revisions.every(
      (revision, index) =>
        Number.isInteger(revision) &&
        revision > 0 &&
        Number(to.options[index]?.value) === revision &&
        (index === 0 || revisions[index - 1] > revision),
    ) &&
    restoreLabels.length === olderRevisions.length &&
    olderRevisions.every((label) => restoreLabels.includes(label))
  );
});
export const historyOrdersRevisionsAndProtectsLatest = always(() => historyListsValid.current);

async function until(window: Window, ready: () => boolean, description: string) {
  for (let attempt = 0; attempt < 80; attempt++) {
    if (ready()) return;
    await new Promise<void>((resolve) => window.setTimeout(resolve, 25));
  }
  throw new Error(description);
}

// Bombadil samples the page between actions. Leave the result where its
// extractors can report it as a named property violation in the trace.
async function observe(document: Document, property: string, run: () => Promise<void>) {
  try {
    await run();
    document.documentElement.setAttribute(property, "ok");
  } catch (error) {
    // oxlint-disable-next-line enbu/no-raw-error-display -- This test diagnostic is read by Bombadil's trace, never rendered.
    document.documentElement.setAttribute(property, String(error));
  }
}

function pick(select: HTMLSelectElement, value: string) {
  select.value = value;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

const secretOutcome = "data-bombadil-secret-round-trip";
const secretCounter = "data-bombadil-secret-counter";
const historyOutcome = "data-bombadil-history-restore";
const secretResult = extract(({ document }) =>
  document.documentElement.getAttribute(secretOutcome),
);
const historyResult = extract(({ document }) =>
  document.documentElement.getAttribute(historyOutcome),
);
export const secretWritesStayInTheirEnvironment = always(
  () => secretResult.current === null || secretResult.current === "ok",
);
export const restoredRevisionMatchesItsSource = always(
  () => historyResult.current === null || historyResult.current === "ok",
);

const secretRoundTrip = registerCustomAction(
  "enbu.secretRoundTrip",
  async (document, window, slot: number, value: string) => {
    const source = currentEnvironment(panel(document));
    const file = panel(document)?.querySelector<HTMLInputElement>('[data-testid="import-file"]');
    if (!source || !file || document.querySelector("dialog[open]")) return;
    const next = Number(document.documentElement.getAttribute(secretCounter) ?? "0") + 1;
    document.documentElement.setAttribute(secretCounter, String(next));
    const key = `PBT_${next}`;
    const option = (picker: HTMLButtonElement, name: string) =>
      button(document.getElementById(picker.getAttribute("aria-controls") ?? ""), [name]);
    const choose = async (picker: HTMLButtonElement, name: string) => {
      await until(window, () => Boolean(option(picker, name)), "environment option did not appear");
      option(picker, name)?.click();
      await until(
        window,
        () => currentEnvironment(panel(document)) === name,
        "environment switch did not finish",
      );
    };

    await observe(document, secretOutcome, async () => {
      const transfer = new DataTransfer();
      transfer.items.add(new File([key + '="' + value + '"\n'], "probe.env"));
      file.files = transfer.files;
      file.dispatchEvent(new Event("change", { bubbles: true }));
      await until(
        window,
        () => valueField(panel(document), key) !== undefined,
        "imported secret did not appear",
      );
      const picker = environmentButton(panel(document));
      if (!picker) throw new Error("environment picker disappeared");
      picker.click();
      await until(window, () => Boolean(option(picker, source)), "environment picker did not open");
      const menu = document.getElementById(picker.getAttribute("aria-controls") ?? "");
      const alternatives = [
        ...(menu?.querySelectorAll<HTMLButtonElement>("button[aria-label]") ?? []),
      ]
        .map((item) => item.getAttribute("aria-label") ?? "")
        .filter(
          (name) =>
            name && name !== source && !locales.some((m) => name === m.dashboard_addEnvironment),
        );
      const other = alternatives[slot % alternatives.length];
      if (!other) {
        picker.click();
        return;
      }
      await choose(picker, other);
      if (valueField(panel(document), key))
        throw new Error("new secret appeared in another environment");
      const returnPicker = environmentButton(panel(document));
      if (!returnPicker) throw new Error("environment picker disappeared after switching");
      returnPicker.click();
      await choose(returnPicker, source);
      const field = valueField(panel(document), key);
      if (field?.type !== "password" || field.value !== value) {
        throw new Error("saved value or masking changed after switching back");
      }
    });
  },
);

// Bound the number of generated rows so longer runs can keep exploring other UI.
const importReady = extract(({ document }) => {
  const root = panel(document);
  return Boolean(
    currentEnvironment(root) &&
    root?.querySelector('[data-testid="import-file"]') &&
    !root.querySelector("[data-loading], [data-conflict-key]") &&
    !document.querySelector(
      "dialog[open], [data-scope=popover][data-part=content][data-state=open]",
    ) &&
    Number(document.documentElement.getAttribute(secretCounter) ?? "0") < 8,
  );
});
export const secretRoundTrips = actions(() =>
  importReady.current
    ? [
        secretRoundTrip(0, "value=with=equals"),
        secretRoundTrip(1, " 日本語の値 🧪 "),
        secretRoundTrip(2, "literal # comment"),
      ]
    : [],
);

const restoreAndCompare = registerCustomAction(
  "enbu.restoreAndCompare",
  async (document, window, slot: number) => {
    const messages = document.documentElement.lang === "ja" ? ja : en;
    const fromSelect = () => select(panel(document), [messages.history_from]);
    const toSelect = () => select(panel(document), [messages.history_to]);
    const environment = () => select(panel(document), [messages.history_environment])?.value;
    const from = fromSelect();
    if (!from || from.options.length < 2 || document.querySelector("dialog[open]")) return;
    const sourceEnvironment = environment();
    const count = from.options.length;
    const revision = from.options[1 + (slot % (count - 1))];
    const restore = button(panel(document), [
      messages.history_restore + ": " + revision.textContent.trim(),
    ]);
    if (!sourceEnvironment || !restore || restore.disabled) return;
    await observe(document, historyOutcome, async () => {
      restore.click();
      await until(
        window,
        () => fromSelect()?.options.length === count + 1,
        "restoring did not append one revision",
      );
      if (environment() !== sourceEnvironment)
        throw new Error("restore changed the selected environment");
      const refreshedFrom = fromSelect();
      const refreshedTo = toSelect();
      if (!refreshedFrom || !refreshedTo) throw new Error("revision selectors disappeared");
      pick(refreshedFrom, revision.value);
      pick(refreshedTo, refreshedTo.options[0].value);
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
      const compare = button(panel(document), [messages.history_compare]);
      if (!compare) throw new Error("history comparison disappeared");
      compare.click();
      await until(
        window,
        () => Boolean(panel(document)?.innerText.includes(messages.history_noDifferences)),
        "restored revision differs from its selected source",
      );
    });
  },
);

const openHistory = registerCustomAction("enbu.openHistory", async (document) => {
  button(
    document,
    locales.map((m) => m.history_title),
  )?.click();
});

const historyOnAnotherTab = extract(({ document }) => {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  return (
    !document.querySelector("dialog[open]") &&
    tabs.some(
      (tab) =>
        tab.getAttribute("aria-selected") === "false" &&
        locales.some((m) => tab.textContent.trim() === m.history_title),
    )
  );
});

const historyReady = extract(({ document }) => {
  const root = panel(document);
  const count =
    select(
      root,
      locales.map((m) => m.history_from),
    )?.options.length ?? 0;
  return (
    !document.querySelector("dialog[open]") &&
    !root?.querySelector("[data-loading]") &&
    count > 1 &&
    count < 12
  );
});
export const historyRestores = actions(() => {
  if (historyReady.current) return [restoreAndCompare(0), restoreAndCompare(1)];
  return historyOnAnotherTab.current ? [openHistory()] : [];
});
