/**
 * CTI — Browser SSH terminal page (ported from the backoffice fork).
 *
 * Verifies the page renders behind the `remote/ssh` route and that the
 * quick-connect / "Open terminal" deep-link query params prefill the form
 * (CTI-006). The live SSH/WebSocket path is exercised by the backend's own
 * browser_ssh_terminal tests; here we cover the FE route + prefill.
 */
import { test, expect } from "@playwright/test";
import { injectAuth } from "./helpers/session";

test.describe("CTI — Browser SSH terminal page", () => {
  test("renders the SSH terminal page at /remote/ssh", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("http://localhost:3000/remote/ssh", { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Browser SSH Terminal" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByLabel("Host")).toBeVisible();
    await expect(page.getByLabel("Port")).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByRole("button", { name: "Connect", exact: true })).toBeVisible();
  });

  test("deep-link query params prefill the connection form (CTI-006)", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(
      "http://localhost:3000/remote/ssh?host=data-node-01.internal&port=2222&username=ops",
      { waitUntil: "domcontentloaded" },
    );

    await expect(page.getByRole("heading", { name: "Browser SSH Terminal" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByLabel("Host")).toHaveValue("data-node-01.internal");
    await expect(page.getByLabel("Port")).toHaveValue("2222");
    await expect(page.getByLabel("Username")).toHaveValue("ops");
  });
});
