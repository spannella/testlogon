/**
 * GAP-0305 regression — User Appeals frontend (MOD-003).
 *
 * The appeals BACKEND (`/v1/appeals`, `/v1/admin/appeals`) is fully wired, but
 * the frontend was entirely absent. This spec is an OFFLINE source-presence +
 * route-presence check (mirrors the readFileSync pattern in other specs) so it
 * runs without a backend / seeded sessions: it asserts the new files exist,
 * export the expected symbols, and that App.tsx + Sidebar.tsx reference the new
 * appeals routes.
 *
 * Before the fix: the appeals files do not exist and App.tsx/Sidebar.tsx have
 * zero "appeal" references → these assertions fail.
 * After the fix: all assertions pass.
 */

import { test, expect } from "@playwright/test";
import { readFileSync, existsSync } from "fs";

const SRC = "/home/ubuntu/testlogon/frontend/src";

function read(rel: string): string {
  const p = `${SRC}/${rel}`;
  if (!existsSync(p)) throw new Error(`Expected source file missing: ${p}`);
  return readFileSync(p, "utf-8");
}

test.describe("GAP-0305 — appeals frontend source presence", () => {
  test("appeals API endpoints file exists and exports all wrappers", () => {
    const src = read("api/endpoints/appeals.ts");
    for (const fn of [
      "submitAppeal",
      "listMyAppeals",
      "getAppeal",
      "withdrawAppeal",
      "listAppealQueue",
      "getAppealQueueStats",
      "getAppealDetail",
      "claimAppeal",
      "decideAppeal",
    ]) {
      expect(src, `endpoints should export ${fn}`).toContain(`export const ${fn}`);
    }
    // hits the real backend prefixes (no mock-only path)
    expect(src).toContain('"/v1/appeals"');
    expect(src).toContain('"/v1/admin/appeals"');
    expect(src).toContain("/v1/admin/appeals/stats");
  });

  test("user AppealsPage exists with list + file form + withdraw", () => {
    const src = read("pages/appeals/AppealsPage.tsx");
    expect(src).toContain("export default function AppealsPage");
    expect(src).toContain("listMyAppeals");
    expect(src).toContain("submitAppeal");
    expect(src).toContain("withdrawAppeal");
    expect(src).toContain("No appeals yet");
  });

  test("admin AppealReviewQueuePage exists with stats + claim + decide", () => {
    const src = read("pages/admin/AppealReviewQueuePage.tsx");
    expect(src).toContain("export default function AppealReviewQueuePage");
    expect(src).toContain("getAppealQueueStats");
    expect(src).toContain("listAppealQueue");
    expect(src).toContain("getAppealDetail");
    expect(src).toContain("claimAppeal");
    expect(src).toContain("decideAppeal");
  });

  test("App.tsx wires lazy imports and both routes", () => {
    const src = read("App.tsx");
    expect(src).toContain('import("@/pages/appeals/AppealsPage")');
    expect(src).toContain('import("@/pages/admin/AppealReviewQueuePage")');
    expect(src).toContain('path="appeals"');
    expect(src).toContain('path="admin/appeals"');
  });

  test("Sidebar.tsx adds user + admin appeals nav links", () => {
    const src = read("components/layout/Sidebar.tsx");
    expect(src).toContain('path: "/appeals"');
    expect(src).toContain('path: "/admin/appeals"');
    expect(src).toContain("My Appeals");
    expect(src).toContain("Appeal Queue");
  });
});
