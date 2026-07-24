// frontend/e2e/content-boost.spec.ts
//
// ADS-012: Self-Promotion / Content Boosting — E2E API contract tests.
//
// These tests verify the boost endpoints are mounted under /ui/ads/boost and
// enforce authentication. Mutating endpoints require an authenticated UI
// session (cookies) + CSRF; the boost lifecycle (active / expired-by-budget /
// expired-by-duration / cancelled-with-refund) is exercised deterministically
// at the service layer (app/services/content_boost.py) via an injectable `now`.
import { test, expect } from "@playwright/test";
import { API } from "./cpp.config";

const BASE = `${API}/ui/ads/boost`;

test.describe("Content Boost (ADS-012)", () => {
  test("create boost requires auth", async ({ request }) => {
    const res = await request.post(BASE, {
      data: {
        content_type: "post",
        content_id: "post_e2e",
        budget_cents: 500,
        duration_seconds: 3600,
      },
    });
    expect([401, 403]).toContain(res.status());
  });

  test("list boosts requires auth", async ({ request }) => {
    const res = await request.get(BASE);
    expect([401, 403]).toContain(res.status());
  });

  test("get boost requires auth", async ({ request }) => {
    const res = await request.get(`${BASE}/boost_doesnotexist`);
    expect([401, 403]).toContain(res.status());
  });

  test("get spend requires auth", async ({ request }) => {
    const res = await request.get(`${BASE}/boost_doesnotexist/spend`);
    expect([401, 403]).toContain(res.status());
  });

  test("cancel boost requires auth", async ({ request }) => {
    const res = await request.post(`${BASE}/boost_doesnotexist/cancel`);
    expect([401, 403]).toContain(res.status());
  });

  test("boost endpoints are mounted (not 404 routing)", async ({ request }) => {
    // An auth failure (401/403) proves the route exists; a 404 here would mean
    // the router was never registered.
    const res = await request.get(BASE);
    expect(res.status()).not.toBe(404);
  });

  test("create rejects unauthenticated even with valid-looking body", async ({ request }) => {
    const res = await request.post(BASE, {
      data: {
        content_type: "video",
        content_id: "vid_e2e",
        budget_cents: 1000,
        duration_seconds: 86400,
      },
    });
    expect([401, 403]).toContain(res.status());
  });
});
