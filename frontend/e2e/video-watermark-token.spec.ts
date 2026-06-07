/**
 * Regression test for GAP-0370 (client-side forensic watermark overlay) and
 * GAP-0371 (automatic playback-token refresh) in
 * `frontend/src/pages/videos/VideoPlayerPage.tsx`.
 *
 * A full playback test requires HLS media, a key server and a real browser CDM
 * — none of which exist offline. The robust, hermetic regression here is a
 * SOURCE-LEVEL assertion (mirrors the readFileSync-based specs already in this
 * folder, e.g. media-player-drm.spec.ts): read the source files and assert the
 * watermark + token-refresh wiring is present.
 *
 * Fails-before: the original VideoPlayerPage rendered <MediaPlayer> in a plain
 * <div> with no overlay and built a static playbackUrl with no refresh path; and
 * WatermarkOverlay.tsx did not exist. Every assertion below would fail.
 * Passes-after: the fixed files contain all the symbols.
 */
import { test, expect } from "@playwright/test";
import { readFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));

const WATERMARK_PATH = resolve(
  here,
  "../src/components/shared/WatermarkOverlay.tsx",
);
const PLAYER_PATH = resolve(here, "../src/pages/videos/VideoPlayerPage.tsx");

const PLAYER_SOURCE = readFileSync(PLAYER_PATH, "utf-8");

test.describe("GAP-0370 — forensic watermark overlay", () => {
  test("WatermarkOverlay component file exists", () => {
    expect(existsSync(WATERMARK_PATH)).toBe(true);
  });

  test("WatermarkOverlay renders a pointer-events-none, aria-hidden overlay", () => {
    const src = readFileSync(WATERMARK_PATH, "utf-8");
    expect(src).toMatch(/export\s+(default\s+)?function\s+WatermarkOverlay/);
    expect(src).toContain('data-testid="watermark-overlay"');
    expect(src).toMatch(/aria-hidden/);
    expect(src).toMatch(/pointerEvents:\s*["']none["']/);
    expect(src).toMatch(/position:\s*["']absolute["']/);
    // accepts session + tenant identity props
    expect(src).toMatch(/sessionId/);
    expect(src).toMatch(/tenantId/);
  });

  test("VideoPlayerPage imports and renders WatermarkOverlay with session/tenant", () => {
    expect(PLAYER_SOURCE).toMatch(
      /import\s+WatermarkOverlay\s+from\s+["']@\/components\/shared\/WatermarkOverlay["']/,
    );
    expect(PLAYER_SOURCE).toContain("<WatermarkOverlay");
    // wired with the session fingerprint + tenant id
    expect(PLAYER_SOURCE).toMatch(/sessionId=\{video\.playback_token\?\.slice\(0,\s*12\)\}/);
    expect(PLAYER_SOURCE).toMatch(/tenantId=\{video\.owner_user_id\}/);
  });

  test("player container establishes a positioning context for the overlay", () => {
    expect(PLAYER_SOURCE).toMatch(/position:\s*["']relative["']/);
  });
});

test.describe("GAP-0371 — automatic playback token refresh", () => {
  test("VideoPlayerPage wires MediaPlayer token-refresh props", () => {
    // Uses the GAP-0300 in-place rotation hook on MediaPlayer.
    expect(PLAYER_SOURCE).toMatch(/onTokenExpiring=\{/);
    expect(PLAYER_SOURCE).toMatch(/tokenExpiresAt=\{/);
    // consumes the previously-ignored expiry field
    expect(PLAYER_SOURCE).toContain("playback_expires_at");
  });

  test("token refresh handler refetches to mint a fresh token", () => {
    expect(PLAYER_SOURCE).toMatch(/handleTokenExpiring/);
    // returns the fresh playback_token from a refetch
    expect(PLAYER_SOURCE).toMatch(/refetch\(\)/);
    expect(PLAYER_SOURCE).toMatch(/playback_token/);
  });
});
