const messages = {
  directWailsBinding:
    "Wails bindings and runtime may only be used through src/lib/backend.ts, src/lib/platform.ts and src/lib/types.ts.",
  errorAlertMessage: "ErrorAlert accepts typed DisplayError through the error prop.",
  rawErrorDetail: "User-visible errors must pass through toDisplayError.",
  nativeElement:
    "Use the native element: <button> for role=button, ModalDialog (a <dialog> opened with showModal) for role=dialog or aria-modal, and a popover for a menu (modern-web-guidance: accessibility, dialog, menu).",
  pxFontSize:
    "Size text with the fontSizes tokens or rem, not px, so it follows the user's text size (modern-web-guidance: typography).",
};

// Roles that a native element already provides, with its behavior built in.
const nativeRoles = new Set(["button", "dialog", "alertdialog", "menu", "menuitem"]);

function jsxAttribute(node, name) {
  return node.attributes.find(
    (attribute) =>
      attribute.type === "JSXAttribute" &&
      attribute.name?.type === "JSXIdentifier" &&
      attribute.name.name === name,
  );
}

// The string an attribute is set to: role="x" or role={"x"}.
function staticString(attribute) {
  const value = attribute?.value;
  if (value?.type === "Literal") return value.value;
  if (value?.type === "JSXExpressionContainer" && value.expression?.type === "Literal") {
    return value.expression.value;
  }
  return undefined;
}

function isPx(value) {
  return typeof value === "string" && /^-?\d*\.?\d+px$/.test(value.trim());
}

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

// The generated bindings (src/bindings) and the Wails runtime.
function isWailsModule(source) {
  return (
    typeof source === "string" &&
    (source === "@wailsio/runtime" ||
      source.startsWith("@wailsio/runtime/") ||
      /(^|\/)bindings(\/|$)/.test(source))
  );
}

const noDirectWailsBinding = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.directWailsBinding },
    schema: [],
  },
  create(context) {
    const check = (node) => {
      if (isWailsModule(node.source?.value)) context.report({ node, messageId: "forbidden" });
    };
    return {
      ImportDeclaration: check,
      ImportExpression: check,
      ExportNamedDeclaration: check,
      ExportAllDeclaration: check,
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

const preferNativeElement = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.nativeElement },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        const role = jsxAttribute(node, "role");
        if (role && nativeRoles.has(staticString(role))) {
          context.report({ node: role, messageId: "forbidden" });
        }
        const modal = jsxAttribute(node, "aria-modal");
        if (modal) context.report({ node: modal, messageId: "forbidden" });
      },
    };
  },
};

const noPxFontSize = {
  meta: {
    type: "problem",
    messages: { forbidden: messages.pxFontSize },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        const size = jsxAttribute(node, "fontSize");
        if (size && isPx(staticString(size)))
          context.report({ node: size, messageId: "forbidden" });
      },
      Property(node) {
        const key = node.key?.type === "Identifier" ? node.key.name : node.key?.value;
        if ((key === "fontSize" || key === "font-size") && isPx(node.value?.value)) {
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
  "no-px-font-size": noPxFontSize,
  "prefer-native-element": preferNativeElement,
};

export default {
  meta: { name: "enbu" },
  rules,
};
