import { describe, expect, it, vi } from "vite-plus/test";
import { rules } from "./oxlint-plugin-enbu.mjs";

type RuleName = keyof typeof rules;

function visitorsFor(name: RuleName) {
  const report = vi.fn();
  const caughtVariable = {};
  const scope = { set: new Map([["err", caughtVariable]]), upper: null };
  const context = {
    report,
    sourceCode: {
      getDeclaredVariables: () => [caughtVariable],
      getScope: () => scope,
    },
  };
  return {
    report,
    visitors: rules[name].create(context) as Record<string, (node: unknown) => void>,
  };
}

describe("enbu Oxlint rules", () => {
  it("rejects direct display of caught error details", () => {
    const { report, visitors } = visitorsFor("no-raw-error-display");
    visitors.CatchClause({});
    visitors.MemberExpression({
      type: "MemberExpression",
      computed: false,
      object: { type: "Identifier", name: "err" },
      property: { type: "Identifier", name: "message" },
    });
    visitors.CallExpression({
      type: "CallExpression",
      callee: { type: "Identifier", name: "String" },
      arguments: [{ type: "Identifier", name: "err" }],
    });
    visitors.TemplateLiteral({
      type: "TemplateLiteral",
      expressions: [{ type: "Identifier", name: "err" }],
    });

    expect(report).toHaveBeenCalledTimes(3);
  });

  it("rejects Wails access outside the backend adapter", () => {
    const { report, visitors } = visitorsFor("no-direct-wails-binding");
    const literal = (value: string) => ({ type: "Literal", value });
    visitors.ImportDeclaration({
      source: literal("../bindings/github.com/enbu-net/enbu/desktop/wails"),
    });
    visitors.ImportDeclaration({ source: literal("@wailsio/runtime") });
    visitors.ImportExpression({ source: literal("../../bindings/events") });
    visitors.ExportNamedDeclaration({ source: literal("./bindings/x/models") });
    visitors.ImportDeclaration({ source: literal("../lib/backend") });
    visitors.ImportDeclaration({ source: literal("./binding-helpers") });
    visitors.ExportNamedDeclaration({ source: null });

    expect(report).toHaveBeenCalledTimes(4);
  });

  it("rejects string-based ErrorAlert props", () => {
    const { report, visitors } = visitorsFor("no-error-alert-message");
    visitors.JSXOpeningElement({
      name: { type: "JSXIdentifier", name: "ErrorAlert" },
      attributes: [
        {
          type: "JSXAttribute",
          name: { type: "JSXIdentifier", name: "message" },
        },
      ],
    });

    expect(report).toHaveBeenCalledOnce();
  });

  it("rejects generic raw Error message fallbacks", () => {
    const { report, visitors } = visitorsFor("no-raw-error-display");
    visitors.ConditionalExpression({
      type: "ConditionalExpression",
      test: {
        type: "BinaryExpression",
        operator: "instanceof",
        left: { type: "Identifier", name: "failure" },
        right: { type: "Identifier", name: "Error" },
      },
      consequent: {
        type: "MemberExpression",
        computed: false,
        object: { type: "Identifier", name: "failure" },
        property: { type: "Identifier", name: "message" },
      },
      alternate: {
        type: "CallExpression",
        callee: { type: "Identifier", name: "String" },
        arguments: [{ type: "Identifier", name: "failure" }],
      },
    });

    expect(report).toHaveBeenCalledOnce();
  });
});
