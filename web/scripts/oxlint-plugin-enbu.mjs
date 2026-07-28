const messages = {
  directWailsBinding: "Wails bindings may only be accessed through src/lib/backend.ts.",
  errorAlertMessage: "ErrorAlert accepts typed DisplayError through the error prop.",
  rawErrorDetail: "User-visible errors must pass through toDisplayError.",
};

function isIdentifier(node, name) {
  return node?.type === "Identifier" && node.name === name;
}

function isNamedProperty(node, objectName, propertyName) {
  return (
    node?.type === "MemberExpression" &&
    !node.computed &&
    isIdentifier(node.object, objectName) &&
    isIdentifier(node.property, propertyName)
  );
}

function resolvedVariable(sourceCode, identifier) {
  for (let scope = sourceCode.getScope(identifier); scope; scope = scope.upper) {
    const variable = scope.set?.get(identifier.name);
    if (variable) return variable;
  }
  return undefined;
}

function isRawErrorFallback(node) {
  if (node?.type !== "ConditionalExpression") return false;
  const { test, consequent, alternate } = node;
  if (
    test?.type !== "BinaryExpression" ||
    test.operator !== "instanceof" ||
    !isIdentifier(test.left, test.left?.name) ||
    !isIdentifier(test.right, "Error")
  ) {
    return false;
  }
  const name = test.left.name;
  return (
    isNamedProperty(consequent, name, "message") &&
    alternate?.type === "CallExpression" &&
    isIdentifier(alternate.callee, "String") &&
    alternate.arguments.length === 1 &&
    isIdentifier(alternate.arguments[0], name)
  );
}

const noDirectWailsBinding = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.directWailsBinding },
    schema: [],
  },
  create(context) {
    return {
      MemberExpression(node) {
        if (isNamedProperty(node, "window", "go")) {
          context.report({ node, messageId: "forbidden" });
        }
      },
    };
  },
};

const noErrorAlertMessage = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.errorAlertMessage },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        if (node.name?.type !== "JSXIdentifier" || node.name.name !== "ErrorAlert") return;
        const message = node.attributes.find(
          (attribute) =>
            attribute.type === "JSXAttribute" &&
            attribute.name?.type === "JSXIdentifier" &&
            attribute.name.name === "message",
        );
        if (message) context.report({ node: message, messageId: "forbidden" });
      },
    };
  },
};

const noRawErrorDisplay = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.rawErrorDetail },
    schema: [],
  },
  create(context) {
    const caughtVariables = new Set();
    const sourceCode = context.sourceCode;
    const isCaught = (node) =>
      node?.type === "Identifier" && caughtVariables.has(resolvedVariable(sourceCode, node));

    return {
      CatchClause(node) {
        for (const variable of sourceCode.getDeclaredVariables(node)) {
          caughtVariables.add(variable);
        }
      },
      MemberExpression(node) {
        if (!node.computed && isCaught(node.object) && isIdentifier(node.property, "message")) {
          context.report({ node, messageId: "forbidden" });
        }
      },
      CallExpression(node) {
        if (
          isIdentifier(node.callee, "String") &&
          node.arguments.length === 1 &&
          isCaught(node.arguments[0])
        ) {
          context.report({ node, messageId: "forbidden" });
        }
      },
      TemplateLiteral(node) {
        if (node.expressions.some(isCaught)) {
          context.report({ node, messageId: "forbidden" });
        }
      },
      ConditionalExpression(node) {
        if (isRawErrorFallback(node)) {
          context.report({ node, messageId: "forbidden" });
        }
      },
    };
  },
};

export const rules = {
  "no-direct-wails-binding": noDirectWailsBinding,
  "no-error-alert-message": noErrorAlertMessage,
  "no-raw-error-display": noRawErrorDisplay,
};

export default {
  meta: { name: "enbu" },
  rules,
};
