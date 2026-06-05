/**
 * GAP-0041: update_creator_ad_settings must perform an atomic partial UPDATE,
 * not a read-merge-PutItem. A partial PATCH (only allow_ads) must NOT clear the
 * other creator ad-settings fields (allowed_ad_categories, min_cpm_cents).
 *
 * Exercises the HTTP path PATCH /ui/ads/creator/ad-settings end-to-end.
 */
import { test, expect } from "@playwright/test";
import { injectAuth, getSession } from "./helpers/session";

const SETTINGS_PATH = "/ui/ads/creator/ad-settings";

test.describe("GAP-0041 creator ad-settings partial update", () => {
  test("partial PATCH allow_ads=false does not clear other fields", async ({ page }) => {
    await injectAuth(page, "alice");
    const csrf = getSession(page).csrf_token;

    // Seed full settings.
    const seed = await page.request.patch(SETTINGS_PATH, {
      headers: { "x-csrf-token": csrf },
      data: { allow_ads: true, allowed_ad_categories: ["sports", "tech"], min_cpm_cents: 150 },
    });
    expect(seed.ok()).toBeTruthy();

    // Partial PATCH — only allow_ads.
    const partial = await page.request.patch(SETTINGS_PATH, {
      headers: { "x-csrf-token": csrf },
      data: { allow_ads: false },
    });
    expect(partial.ok()).toBeTruthy();

    // The untouched fields must survive the partial update.
    const resp = await page.request.get(SETTINGS_PATH);
    expect(resp.ok()).toBeTruthy();
    const body = await resp.json();
    expect(body.allow_ads).toBe(false);
    expect(body.allowed_ad_categories).toEqual(["sports", "tech"]);
    expect(body.min_cpm_cents).toBe(150);
  });
});
