/**
 * E2E tests for the SuiteCRM Quotes & Contracts (QUO) frontend.
 *
 * Sections:
 *   90 — Quotes list + create UI (flag-gated)
 *   91 — Quote detail / builder UI
 *   92 — Contracts list + detail UI
 *
 * Auth: e2e_session_setup.py (Alice). Quotes/Contracts are flag-gated
 * (AOS_QUOTES_ENABLED / AOS_CONTRACTS_ENABLED). When the flags are OFF the
 * backend returns 404; the UI must show a clear "not enabled" state. These
 * tests assert the page renders one of the two valid states (data table OR
 * not-enabled card) so they pass regardless of flag configuration.
 *
 * NOTE: do not run automatically — author-only spec.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── Section 90 — Quotes list ──────────────────────────────────────────────────

test.describe("90 — Quotes list UI", () => {
  test("renders quotes page (table or not-enabled state)", async ({ page }) => {
    await injectAuth(page);
    await page.goto(`${BASE}/crm/quotes`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Quotes" })).toBeVisible({ timeout: 15_000 });

    // Either the "New quote" button (feature enabled) or the not-enabled card.
    const newBtn = page.getByRole("button", { name: /new quote/i }).first();
    const notEnabled = page.getByText(/Quotes is not enabled/i);
    await expect(newBtn.or(notEnabled)).toBeVisible({ timeout: 15_000 });
  });

  test("create dialog opens when feature enabled", async ({ page }) => {
    await injectAuth(page);
    await page.goto(`${BASE}/crm/quotes`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Quotes" })).toBeVisible({ timeout: 15_000 });

    const newBtn = page.getByRole("button", { name: /new quote/i }).first();
    if (!(await newBtn.isVisible().catch(() => false))) {
      test.skip(true, "Quotes feature flag disabled");
    }
    await newBtn.click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("heading", { name: "New quote" })).toBeVisible();
    await expect(page.getByLabel("Title")).toBeVisible();
    await expect(page.getByRole("button", { name: /add line item/i })).toBeVisible();
  });
});

// ─── Section 91 — Quote builder ─────────────────────────────────────────────────

test.describe("91 — Quote builder UI", () => {
  test("create + open a quote shows totals and stage controls", async ({ page }) => {
    await injectAuth(page);
    await page.goto(`${BASE}/crm/quotes`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Quotes" })).toBeVisible({ timeout: 15_000 });

    const newBtn = page.getByRole("button", { name: /new quote/i }).first();
    if (!(await newBtn.isVisible().catch(() => false))) {
      test.skip(true, "Quotes feature flag disabled");
    }
    await newBtn.click();

    const title = `E2E Quote ${Date.now()}`;
    await page.getByLabel("Title").fill(title);
    await page.getByLabel("Line 1 description").fill("Consulting hours");
    await page.getByLabel("Line 1 quantity").fill("4");
    await page.getByLabel("Line 1 unit price").fill("150.00");

    await page.getByRole("button", { name: "Create quote" }).click();

    // Navigate into the quote from the list.
    await expect(page.getByRole("link", { name: title })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("link", { name: title }).click();

    await expect(page.getByRole("heading", { name: "Totals" })).toBeVisible();
    await expect(page.getByText("Convert to invoice")).toBeVisible();
    await expect(page.getByText("Convert to contract")).toBeVisible();
  });
});

// ─── Section 92 — Contracts ─────────────────────────────────────────────────────

test.describe("92 — Contracts UI", () => {
  test("renders contracts page (table or not-enabled state)", async ({ page }) => {
    await injectAuth(page);
    await page.goto(`${BASE}/crm/contracts`, { waitUntil: "domcontentloaded" });

    await expect(page.getByRole("heading", { name: "Contracts" })).toBeVisible({ timeout: 15_000 });
    const newBtn = page.getByRole("button", { name: /new contract/i }).first();
    const notEnabled = page.getByText(/Contracts is not enabled/i);
    await expect(newBtn.or(notEnabled)).toBeVisible({ timeout: 15_000 });
  });

  test("create dialog opens when feature enabled", async ({ page }) => {
    await injectAuth(page);
    await page.goto(`${BASE}/crm/contracts`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Contracts" })).toBeVisible({ timeout: 15_000 });

    const newBtn = page.getByRole("button", { name: /new contract/i }).first();
    if (!(await newBtn.isVisible().catch(() => false))) {
      test.skip(true, "Contracts feature flag disabled");
    }
    await newBtn.click();
    await expect(page.getByRole("heading", { name: "New contract" })).toBeVisible();
    await expect(page.getByLabel("Start date")).toBeVisible();
  });
});
