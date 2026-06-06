/**
 * E2E tests for GAP-0109: Register page recovery path for taken-but-unverified
 * email addresses.
 *
 * Before the fix, when `/ui/register/check` returned `available: false`, the
 * Register page showed a hard dead-end ("An account with this email already
 * exists") with the submit button disabled and no way to recover.
 *
 * The fix distinguishes a fully-verified account (dead-end + "Sign in instead"
 * link) from a pending/unverified account (amber panel + "Resend verification
 * code" button that resumes the verify step).
 *
 * These tests mock `/ui/register/check` (and `/ui/register/resend`) at the
 * browser level so they are self-contained and do not depend on the sibling
 * GAP-0107 backend change that adds the `unverified` field, nor on seeded data.
 */

import { test, expect, type Page } from "@playwright/test";

const BASE = "http://localhost:3000";

/** Mock the email-availability check to return a given shape. */
async function mockCheck(
  page: Page,
  body: { status?: string; available: boolean; unverified?: boolean },
) {
  await page.route("**/ui/register/check", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: "ok", ...body }),
    });
  });
}

test.describe("GAP-0109: Register recovery path", () => {
  test("taken-but-unverified email shows resend option, not a dead-end", async ({ page }) => {
    await mockCheck(page, { available: false, unverified: true });
    await page.route("**/ui/register/resend", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ status: "ok", delivery_medium: "email", delivery_destination: "pendingux@test.local" }),
      });
    });

    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#email").fill("pendingux@test.local");

    // Recovery panel + resend button must appear.
    const resendBtn = page.getByRole("button", { name: /resend verification code/i });
    await expect(resendBtn).toBeVisible({ timeout: 6000 });

    // The dead-end "already exists" message must NOT be shown for unverified.
    await expect(page.getByText("An account with this email already exists")).not.toBeVisible();

    // Clicking resend advances to the verify step.
    await resendBtn.click();
    await expect(page.getByRole("button", { name: /verify account/i })).toBeVisible({ timeout: 6000 });
    await expect(page.locator("text=/verification code/i").first()).toBeVisible();
  });

  test("verified account shows dead-end message with Sign in instead link", async ({ page }) => {
    await mockCheck(page, { available: false, unverified: false });

    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#email").fill("verified-existing@test.local");

    await expect(page.getByText("An account with this email already exists")).toBeVisible({ timeout: 6000 });
    await expect(page.getByRole("link", { name: /sign in instead/i })).toBeVisible();

    // No resend option for a fully-verified account.
    await expect(page.getByRole("button", { name: /resend verification code/i })).not.toBeVisible();
  });

  test("backward compatible: response without unverified field keeps dead-end", async ({ page }) => {
    // Old backend shape (no `unverified` key) must behave exactly like today.
    await mockCheck(page, { available: false });

    await page.goto(`${BASE}/register`, { waitUntil: "domcontentloaded" });
    await page.locator("#email").fill("legacy-existing@test.local");

    await expect(page.getByText("An account with this email already exists")).toBeVisible({ timeout: 6000 });
    await expect(page.getByRole("button", { name: /resend verification code/i })).not.toBeVisible();
  });
});
