/**
 * Regression test for GAP-0365 (Ctrl+Enter / Cmd+Enter send not wired in
 * ComposeBar) in `frontend/src/pages/messages/ComposeBar.tsx`.
 *
 * A full keystroke send test requires the live messaging stack (auth seeding,
 * DynamoDB, a real conversation). The robust, hermetic regression here is a
 * SOURCE-LEVEL assertion (mirrors the readFileSync-based specs already in this
 * folder, e.g. media-player-drm.spec.ts): read ComposeBar.tsx and assert the
 * new Ctrl/Cmd+Enter wiring is present in handleKeyDown.
 *
 * Fails-before: the original handleKeyDown only had the
 * `e.key === "Enter" && !e.shiftKey` branch, so the ctrlKey/metaKey assertions
 * below would fail.
 * Passes-after: handleKeyDown contains a `(e.ctrlKey || e.metaKey)` Enter
 * branch that calls handleSubmit.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(
  resolve(here, "../src/pages/messages/ComposeBar.tsx"),
  "utf-8",
);

// Isolate the handleKeyDown function body so assertions can't be satisfied by
// unrelated code elsewhere in the file.
function handleKeyDownBody(): string {
  const start = SOURCE.indexOf("const handleKeyDown");
  expect(start).toBeGreaterThanOrEqual(0);
  // Grab a generous window covering the whole arrow-function body.
  return SOURCE.slice(start, start + 600);
}

test.describe("GAP-0365 — ComposeBar Ctrl/Cmd+Enter send", () => {
  test("handleKeyDown still handles plain Enter (no shift) send", () => {
    const body = handleKeyDownBody();
    expect(body).toMatch(/e\.key\s*===\s*["']Enter["']\s*&&\s*!e\.shiftKey/);
    expect(body).toContain("handleSubmit");
  });

  test("handleKeyDown adds a Ctrl/Cmd+Enter send branch", () => {
    const body = handleKeyDownBody();
    // Enter with a modifier key (Ctrl on Win/Linux, Cmd/Meta on macOS).
    expect(body).toMatch(/e\.ctrlKey\s*\|\|\s*e\.metaKey/);
    // The modifier branch must also gate on the Enter key.
    expect(body).toMatch(
      /e\.key\s*===\s*["']Enter["']\s*&&\s*\(\s*e\.ctrlKey\s*\|\|\s*e\.metaKey\s*\)/,
    );
  });

  test("the Ctrl/Cmd+Enter branch calls the submit fn and prevents default", () => {
    const body = handleKeyDownBody();
    const idx = body.search(/e\.ctrlKey\s*\|\|\s*e\.metaKey/);
    expect(idx).toBeGreaterThanOrEqual(0);
    // Within the modifier branch, both preventDefault and handleSubmit appear.
    const branch = body.slice(idx, idx + 200);
    expect(branch).toContain("preventDefault");
    expect(branch).toContain("handleSubmit");
  });
});
