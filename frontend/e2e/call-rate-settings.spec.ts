/**
 * E2E: Creator Call Rate Settings (GAP-0149)
 *
 * Verifies the settings page that lets creators view/set their per-minute call
 * rate (frontend/src/pages/settings/CallRateSettings.tsx), the route
 * /settings/call-rate, and the "Manage Call Rate" link on the SettingsPage.
 *
 * Before the fix: the link, route, and page did not exist — every test here
 * fails. After the fix: all pass.
 */
import { test, expect } from "@playwright/test";
import { injectAuth, getSession } from "./helpers";

test.describe("Call Rate Settings (GAP-0149)", () => {
  test("Settings page exposes a 'Manage Call Rate' link that navigates to the page", async ({
    page,
  }) => {
    await injectAuth(page, "alice");
    await page.goto("/settings");

    const link = page.getByTestId("call-rate-settings-link");
    await expect(link).toBeVisible();
    await link.click();

    await expect(page).toHaveURL(/\/settings\/call-rate/);
    await expect(page.getByTestId("rate-input")).toBeVisible();
  });

  test("Create a call rate and persist it across reload", async ({ page }) => {
    const sess = await (async () => {
      await injectAuth(page, "alice");
      return getSession(page);
    })();

    // Start from a clean slate — remove any rate left by previous runs.
    await page.request.delete("/ui/calls/rates", {
      headers: { "x-csrf-token": sess.csrf_token },
    });

    await page.goto("/settings/call-rate");

    const rateInput = page.getByTestId("rate-input");
    await expect(rateInput).toBeVisible();
    await rateInput.fill("2.50");
    await page.getByTestId("save-rate-button").click();

    await expect(page.getByText("Call rate saved.")).toBeVisible();

    // Reload — the saved value is reflected in the form.
    await page.reload();
    await expect(page.getByTestId("rate-input")).toHaveValue("2.5");
  });

  test("Disable paid calls via the delete button", async ({ page }) => {
    await injectAuth(page, "alice");
    const sess = getSession(page);

    // Pre-seed a rate so the delete button is rendered.
    await page.request.post("/ui/calls/rates", {
      headers: { "x-csrf-token": sess.csrf_token },
      data: {
        rate_cents_per_minute: 100,
        enabled: true,
        min_balance_minutes: 5,
        max_duration_minutes: 120,
      },
    });

    await page.goto("/settings/call-rate");

    const deleteBtn = page.getByTestId("delete-rate-button");
    await expect(deleteBtn).toBeVisible();

    // Accept the confirm() dialog the button triggers.
    page.once("dialog", (d) => d.accept());
    await deleteBtn.click();

    await expect(page.getByText("Paid calls disabled.")).toBeVisible();
    await expect(page.getByTestId("save-rate-button")).toHaveText(
      "Enable Paid Calls",
    );
  });
});
