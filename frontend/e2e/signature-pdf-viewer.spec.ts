/**
 * Regression test for GAP-0351 (no visual PDF viewer) in
 * `frontend/src/pages/files/SignaturePacketComposer.tsx`.
 *
 * A full render test requires a real PDF, the pdf.js worker, and a CDM-free
 * browser canvas pipeline — heavy and flaky offline. The robust, hermetic
 * regression here is a SOURCE-LEVEL assertion (mirrors the readFileSync-based
 * specs already in this folder, e.g. media-player-drm.spec.ts): assert that
 * `react-pdf` is installed and that the composer now renders real PDF pages
 * (<Document>/<Page>) with the pdf.js worker configured — instead of the blank
 * grey `bg-slate-50` placeholder that was the only thing rendered before.
 *
 * Fails-before: react-pdf absent from package.json; the component had no
 * Document/Page import and only the blank `bg-slate-50` canvas.
 * Passes-after: react-pdf is a dependency and the component renders the viewer.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(
  resolve(here, "../src/pages/files/SignaturePacketComposer.tsx"),
  "utf-8",
);
const PKG = JSON.parse(
  readFileSync(resolve(here, "../package.json"), "utf-8"),
) as { dependencies?: Record<string, string> };

test.describe("GAP-0351 — Signature composer PDF viewer", () => {
  test("react-pdf is a declared dependency", () => {
    expect(PKG.dependencies).toBeTruthy();
    expect(PKG.dependencies?.["react-pdf"]).toBeTruthy();
  });

  test("imports Document/Page/pdfjs from react-pdf", () => {
    expect(SOURCE).toMatch(/import\s*\{[^}]*\bDocument\b[^}]*\}\s*from\s*["']react-pdf["']/);
    expect(SOURCE).toMatch(/import\s*\{[^}]*\bPage\b[^}]*\}\s*from\s*["']react-pdf["']/);
    expect(SOURCE).toMatch(/import\s*\{[^}]*\bpdfjs\b[^}]*\}\s*from\s*["']react-pdf["']/);
  });

  test("configures the pdf.js worker", () => {
    expect(SOURCE).toContain("pdfjs.GlobalWorkerOptions.workerSrc");
    expect(SOURCE).toContain("pdf.worker.min.mjs");
  });

  test("renders real PDF pages via <Document> and <Page>", () => {
    expect(SOURCE).toMatch(/<Document\b/);
    expect(SOURCE).toMatch(/<Page\b/);
    expect(SOURCE).toContain("pageNumber");
  });

  test("keeps the data-testid signature-canvas container", () => {
    expect(SOURCE).toContain('data-testid="signature-canvas"');
  });

  test("no longer renders the PDF behind only a blank bg-slate-50 box", () => {
    // The blank placeholder may still exist as a no-PDF fallback, but the real
    // viewer (Document/Page) must be the primary render path. Guard against a
    // regression where the viewer is removed and only the grey box remains.
    expect(SOURCE).toMatch(/pdfUrl\s*\?/);
    expect(SOURCE).toMatch(/<Document\b/);
  });

  test("maps field overlays per rendered page", () => {
    // Field boxes are filtered to the current page and positioned with normalized
    // 0..1 coordinates scaled to the rendered page via CSS percentages.
    expect(SOURCE).toMatch(/\.filter\(\s*\(field\)\s*=>\s*\(field\.page\s*\?\?\s*1\)\s*===\s*pageNum\s*\)/);
    expect(SOURCE).toContain("field.x) * 100}%");
  });
});
