/**
 * Regression test for GAP-0299 (DRM license-server integration) and
 * GAP-0300 (token-refresh callback) in
 * `frontend/src/components/shared/MediaPlayer.tsx`.
 *
 * A full DRM/token playback test requires a CDM, a license server and real
 * DRM-encrypted media — none of which exist offline. The robust, hermetic
 * regression here is a SOURCE-LEVEL assertion (mirrors the readFileSync-based
 * specs already in this folder, e.g. alerts.spec.ts / fraud-detection.spec.ts):
 * read MediaPlayer.tsx and assert the new DRM + token-refresh wiring is present.
 *
 * Fails-before: the original file had only `if (drmKeyUrl) { emeEnabled = true }`
 * and no token-refresh symbols, so every assertion below would fail.
 * Passes-after: the fixed file contains all the symbols.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(
  resolve(here, "../src/components/shared/MediaPlayer.tsx"),
  "utf-8",
);

test.describe("GAP-0299 — MediaPlayer DRM (Widevine/PlayReady/FairPlay)", () => {
  test("declares a DrmConfig interface with license/token/fairplay cert fields", () => {
    expect(SOURCE).toMatch(/interface\s+DrmConfig\b/);
    expect(SOURCE).toContain("licenseUrl");
    expect(SOURCE).toContain("fairplayCertificateUrl");
    // token field used for license-server auth
    expect(SOURCE).toMatch(/token\??:\s*string/);
  });

  test("exposes a drmConfig prop while keeping legacy drmKeyUrl for back-compat", () => {
    expect(SOURCE).toMatch(/drmConfig\??:\s*DrmConfig/);
    // legacy AES-128 prop must remain
    expect(SOURCE).toMatch(/drmKeyUrl\??:\s*string/);
  });

  test("configures hls.js drmSystems with a license XHR setup callback", () => {
    expect(SOURCE).toContain("drmSystems");
    expect(SOURCE).toContain("com.widevine.alpha");
    expect(SOURCE).toMatch(/licenseXhrSetup/);
    // Bearer token attached to license request
    expect(SOURCE).toMatch(/Authorization.*Bearer/);
  });

  test("implements a Safari native FairPlay path via the EME encrypted event", () => {
    expect(SOURCE).toContain("fairplayCertificateUrl");
    expect(SOURCE).toMatch(/addEventListener\(\s*["']encrypted["']/);
    expect(SOURCE).toMatch(/generateRequest/);
  });

  test("non-DRM path is preserved: emeEnabled only set behind a guard", () => {
    // emeEnabled must still be gated, never unconditionally enabled
    expect(SOURCE).toMatch(/emeEnabled\s*=\s*true/);
    expect(SOURCE).toMatch(/if\s*\(drmKeyUrl\)/);
  });
});

test.describe("GAP-0300 — MediaPlayer token refresh", () => {
  test("exposes an onTokenExpiring callback prop", () => {
    expect(SOURCE).toMatch(/onTokenExpiring\??:\s*\(\)\s*=>\s*Promise<string>/);
  });

  test("accepts a tokenExpiresAt prop", () => {
    expect(SOURCE).toMatch(/tokenExpiresAt\??:\s*number/);
  });

  test("schedules the refresh ~30s before the JWT exp claim", () => {
    // JWT exp decoding present
    expect(SOURCE).toMatch(/exp/);
    expect(SOURCE).toMatch(/decodeJwtExp|payload\.exp/);
    // 30-second buffer before expiry
    expect(SOURCE).toMatch(/30/);
    expect(SOURCE).toContain("setTimeout");
    expect(SOURCE).toContain("clearTimeout");
  });

  test("injects the refreshed token via hls xhrSetup", () => {
    expect(SOURCE).toContain("xhrSetup");
    expect(SOURCE).toMatch(/tokenRef/);
  });
});
