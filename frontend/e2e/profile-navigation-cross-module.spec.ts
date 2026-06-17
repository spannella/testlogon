import { test, expect, type Browser, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

type SessionData = {
  csrf_token: string;
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
};

let sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    sessions = JSON.parse(raw);
  }
  return sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function sessionPost(browser: Browser, userId: string, path: string, body: Record<string, unknown>) {
  const session = getSessions()[userId];
  const ctx = await browser.newContext({ baseURL: API });
  await ctx.addCookies(session.cookies);
  const resp = await ctx.request.post(path, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
  const jsonBody = await resp.json().catch(() => null);
  const status = resp.status();
  const ok = resp.ok();
  await ctx.close();
  return { ok: () => ok, status: () => status, json: async () => jsonBody };
}

async function gotoModule(page: Page, path: string) {
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.goto(`${BASE}${path}`, { waitUntil: "load" });
}

let _calName = "";

test.describe("UPR-019 cross-module canonical profile navigation", () => {
  test.beforeAll(async ({ browser }) => {
    // Seed messaging conversation
    const convoResp = await sessionPost(browser, ALICE_ID, "/messaging/conversations", {
      type: "dm",
      participant_ids: [BOB_ID],
    });
    expect(convoResp.ok()).toBe(true);

    // Seed contact
    await sessionPost(browser, ALICE_ID, "/ui/contacts", { user_id: BOB_ID });

    // Seed feed post authored by Bob
    await sessionPost(browser, BOB_ID, "/posts", { body: `E2E profile-nav post ${Date.now()}` });

    // Seed calendar share
    _calName = `E2E profile-nav calendar ${Date.now()}`;
    const calResp = await sessionPost(browser, ALICE_ID, "/ui/calendars", {
      name: _calName,
      timezone: "UTC",
    });
    if (calResp.ok()) {
      const cal = await calResp.json() as { calendar_id: string };
      await sessionPost(browser, ALICE_ID, `/ui/calendars/${cal.calendar_id}/shares`, {
        user_sub: BOB_ID,
        permission: "read",
      });
    }

    // Seed ticket owned by Bob
    await sessionPost(browser, BOB_ID, "/tickets", {
      subject: `E2E profile-nav ticket ${Date.now()}`,
      description: "profile navigation",
    });
  });

  test("messaging entry point navigates to canonical profile", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoModule(page, "/messages");

    const profileTrigger = page.locator("[aria-label*='Open'][aria-label*='profile']").first();
    await expect(profileTrigger).toBeVisible({ timeout: 10_000 });
    await profileTrigger.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("contacts entry point navigates to canonical profile", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoModule(page, "/contacts");

    const profileLink = page.locator('main a[href*="/u/"]').first();
    await expect(profileLink).toBeVisible({ timeout: 10_000 });
    await profileLink.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("newsfeed entry point navigates to canonical profile", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoModule(page, "/feed");

    const profileLink = page.locator('main a[href*="/u/"]').first();
    await expect(profileLink).toBeVisible({ timeout: 10_000 });
    await profileLink.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("calendar entry point navigates to canonical profile", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await gotoModule(page, "/calendar");
    await page.getByRole("tab", { name: "Sharing" }).click();

    // Select the calendar that has the share
    if (_calName) {
      await page.getByRole("combobox").first().click();
      await page.getByRole("option", { name: new RegExp(_calName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) }).click();
      await page.waitForTimeout(500);
    }

    const profileLink = page.locator('main a[href*="/u/"]').first();
    await expect(profileLink).toBeVisible({ timeout: 10_000 });
    await profileLink.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("ticket manager entry point navigates to canonical profile", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, BOB_ID);
    await gotoModule(page, "/tickets");

    const profileLink = page.locator('main a[href*="/u/"]').first();
    await expect(profileLink).toBeVisible({ timeout: 10_000 });
    await profileLink.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("deep link renders public profile state when logged out (a11y smoke)", async ({ page }) => {
    await page.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`, { waitUntil: "load" });

    await expect(page.getByText(/Audience: public/i)).toBeVisible({ timeout: 8_000 });
    await expect(page.getByRole("button", { name: /sign in to view more/i })).toBeVisible({ timeout: 8_000 });
    await expect(page.getByRole("button", { name: /^Message$/i })).toBeVisible({ timeout: 8_000 });
  });

  test("deep link renders member profile state when logged in (a11y smoke)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`, { waitUntil: "load" });

    await expect(page.getByText(/Audience: member/i)).toBeVisible({ timeout: 8_000 });
    await expect(page.getByRole("button", { name: /^Message$/i })).toBeVisible({ timeout: 8_000 });
    await expect(page.getByRole("button", { name: /Add contact/i })).toBeVisible({ timeout: 8_000 });
    await page.close();
  });
});
