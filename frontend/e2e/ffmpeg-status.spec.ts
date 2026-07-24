/**
 * E2E tests for FFmpeg Health Check endpoint (MEDIA-002).
 *
 * Section 117: FFmpeg Health Check
 *
 * Prerequisites:
 *   - Backend running on port 8000
 *   - FFmpeg installed on the dev stack
 *
 * Auth: None required (internal diagnostic endpoint)
 */

import { test, expect } from "@playwright/test";
import { API } from "./cpp.config";


test.describe("Section 117: FFmpeg Health Check", () => {
  test("117.1 GET /internal/ffmpeg-status returns 200", async ({ request }) => {
    const resp = await request.get(`${API}/internal/ffmpeg-status`);
    expect(resp.status()).toBe(200);
  });

  test("117.2 Response contains status and path fields", async ({ request }) => {
    const resp = await request.get(`${API}/internal/ffmpeg-status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("status");
    expect(body).toHaveProperty("path");
    // status must be one of the known values
    expect(["healthy", "degraded", "unavailable"]).toContain(body.status);
  });

  test("117.3 Response structure is valid for current FFmpeg state", async ({ request }) => {
    const resp = await request.get(`${API}/internal/ffmpeg-status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    if (body.status === "healthy" || body.status === "degraded") {
      // When FFmpeg is available, these fields are populated
      expect(body.path).toBeTruthy();
      expect(body.version).toBeTruthy();
      expect(body.codecs).toBeInstanceOf(Array);
      expect(body.codecs.length).toBeGreaterThan(0);
      expect(body).toHaveProperty("missing_required");
      expect(body).toHaveProperty("missing_recommended");
      expect(body).toHaveProperty("issues");
    } else {
      // When unavailable, error field is present
      expect(body.status).toBe("unavailable");
      expect(body).toHaveProperty("error");
    }
  });
});
