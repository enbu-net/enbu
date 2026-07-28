import assert from "node:assert/strict";
import test from "node:test";
import { inspectSource } from "./check-user-errors.mjs";

test("rejects direct display of caught error details", () => {
  const violations = inspectSource(
    "src/routes/example.tsx",
    `try { await run() } catch (err) {
      setError(err.message)
      setOther(String(err))
      setThird(\`\${err}\`)
    }`,
  );
  assert.equal(violations.length, 3);
});

test("accepts the typed display-error gate", () => {
  const violations = inspectSource(
    "src/routes/example.tsx",
    `try { await run() } catch (err) {
      setError(toDisplayError(err))
    }`,
  );
  assert.deepEqual(violations, []);
});

test("rejects Wails access outside the backend adapter", () => {
  const violations = inspectSource(
    "src/routes/example.tsx",
    "const service = window.go?.main?.DesktopService",
  );
  assert.equal(violations.length, 1);
});

test("rejects string-based ErrorAlert props", () => {
  const violations = inspectSource(
    "src/routes/example.tsx",
    "<ErrorAlert message={error.message} />",
  );
  assert.equal(violations.length, 1);
});
