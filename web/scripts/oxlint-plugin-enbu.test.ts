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
    visitors.MemberExpression({
      type: "MemberExpression",
      computed: false,
      object: { type: "Identifier", name: "window" },
      property: { type: "Identifier", name: "go" },
    });

    expect(report).toHaveBeenCalledOnce();
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
