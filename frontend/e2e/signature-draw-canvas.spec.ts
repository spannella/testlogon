/**
 * Regression test for GAP-0352 (no signature drawing canvas) in
 * `frontend/src/pages/files/SignaturePacketComposer.tsx` + the new
 * `frontend/src/components/SignatureDrawCanvas.tsx`.
 *
 * Before the fix, the drawn signature mode rendered a plain text <Input> with the
 * placeholder "Drawn JSON points, e.g. [[0.1,0.2],[0.2,0.3]]" — users had to type
 * raw JSON coordinates and there was no HTML5 canvas for freehand drawing.
 *
 * A full pointer-draw interaction test needs a live signer + packet which isn't
 * available offline, so this is a hermetic SOURCE-LEVEL assertion (mirrors the
 * readFileSync pattern in media-player-drm.spec.ts): assert the drawn branch now
 * uses a <canvas> with pointer handlers and no longer the JSON-points <Input>.
 *
 * Fails-before: the placeholder + drawn <Input> existed and SignatureDrawCanvas
 * did not. Passes-after: the canvas component exists and is wired in.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const COMPOSER = readFileSync(
  resolve(here, "../src/pages/files/SignaturePacketComposer.tsx"),
  "utf-8",
);
const CANVAS = readFileSync(
  resolve(here, "../src/components/SignatureDrawCanvas.tsx"),
  "utf-8",
);

test.describe("GAP-0352 — signature drawing canvas component", () => {
  test("SignatureDrawCanvas renders an HTML5 <canvas> via a useRef", () => {
    expect(CANVAS).toMatch(/useRef<HTMLCanvasElement>/);
    expect(CANVAS).toMatch(/<canvas\b/);
  });

  test("captures freehand strokes with pointer event handlers (mouse + touch)", () => {
    expect(CANVAS).toContain("onPointerDown");
    expect(CANVAS).toContain("onPointerMove");
    expect(CANVAS).toContain("onPointerUp");
    // pointerdown/move/up cover both mouse and touch
    expect(CANVAS).toMatch(/PointerEvent<HTMLCanvasElement>/);
  });

  test("normalizes coordinates to 0..1 and emits JSON for the existing pipeline", () => {
    expect(CANVAS).toMatch(/clamp01/);
    expect(CANVAS).toContain("JSON.stringify");
    expect(CANVAS).toMatch(/onChange/);
  });

  test("provides a Clear button to reset the drawing", () => {
    expect(CANVAS).toMatch(/Clear/);
    expect(CANVAS).toMatch(/handleClear/);
  });
});

test.describe("GAP-0352 — composer drawn branch uses the canvas", () => {
  test("imports and renders SignatureDrawCanvas", () => {
    expect(COMPOSER).toMatch(/import\s*\{\s*SignatureDrawCanvas\s*\}\s*from\s*["']@\/components\/SignatureDrawCanvas["']/);
    expect(COMPOSER).toContain("<SignatureDrawCanvas");
  });

  test("no longer uses the JSON-points text Input in drawn mode", () => {
    expect(COMPOSER).not.toContain("Drawn JSON points");
  });

  test("submission still reads drawn_strokes via parseDrawnStrokes", () => {
    // The existing fill pipeline must remain wired unchanged.
    expect(COMPOSER).toContain("drawn_strokes: parseDrawnStrokes(drawnRaw)");
  });

  test("the canvas writes into the same drawnValues state the submit reads", () => {
    expect(COMPOSER).toMatch(/setDrawnValues\(\(prev\) => \(\{ \.\.\.prev, \[field\.field_id\]: serialized \}\)\)/);
  });
});
