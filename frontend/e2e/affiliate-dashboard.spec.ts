import { test, expect } from "@playwright/test";
import { injectAuth } from "./helpers/session";

// GAP-0198 / FIN-010: AffiliateDashboard tabbed analytics layout.
// Before the fix the page rendered only the link-list Card with no <Tabs>.
// These tests fail-before (no tabs) and pass-after (tabbed layout present).
//
// The four analytics tabs depend on GAP-0197 backend endpoints which are not
// yet shipped, so analytics are gated behind VITE_AFFILIATE_ANALYTICS. With the
// flag off (the default for this rollout window) each analytics tab renders a
// progressive-disclosure "coming soon" panel; the Links tab is fully functional.

test.describe("Affiliate Dashboard (GAP-0198)", () => {
  test("links tab renders link list (regression guard)", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/affiliates");
    await expect(page.getByRole("tab", { name: "Links" })).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Create Link" })
    ).toBeVisible();
  });

  test("analytics tab is present and shows content", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/affiliates");
    await page.getByRole("tab", { name: "Analytics" }).click();
    // With analytics enabled: summary cards. With the flag off: coming-soon panel.
    await expect(
      page
        .getByText("Total Clicks")
        .or(page.getByText("Analytics coming soon"))
    ).toBeVisible();
  });

  test("earnings tab is present and shows content", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/affiliates");
    await page.getByRole("tab", { name: "Earnings" }).click();
    await expect(
      page
        .getByRole("table")
        .or(page.getByText("Earnings coming soon"))
        .or(page.getByText(/No earnings yet/i))
    ).toBeVisible();
  });

  test("top products tab is present and shows content", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/affiliates");
    await page.getByRole("tab", { name: "Top Products" }).click();
    await expect(
      page
        .getByRole("table")
        .or(page.getByText("Top Products coming soon"))
        .or(page.getByText(/No products to rank yet/i))
    ).toBeVisible();
  });
});
