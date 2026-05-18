import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

interface SessionData {
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
}

let sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
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
  await ctx.close();
  return resp;
}

test.describe("UPR-017 profile links — calendar and tickets", () => {
  test("calendar sharing collaborator link navigates to canonical profile", async ({ browser }) => {
    const createCal = await sessionPost(browser, ALICE_ID, "/ui/calendars", { name: `E2E Link Cal ${Date.now()}`, timezone: "UTC" });
    expect(createCal.ok()).toBe(true);
    const cal = await createCal.json() as { calendar_id: string };

    const share = await sessionPost(browser, ALICE_ID, `/ui/calendars/${cal.calendar_id}/shares`, { user_sub: BOB_ID, permission: "read" });
    expect(share.ok()).toBe(true);

    const page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/calendar`, { waitUntil: "load" });
    await page.getByRole("tab", { name: "Sharing" }).click();

    const link = page.getByRole("link", { name: new RegExp(`Open ${BOB_ID} profile`) }).first();
    await expect(link).toBeVisible({ timeout: 8_000 });
    await link.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("tickets owner/reporter links navigate to canonical profile", async ({ browser }) => {
    const createTicket = await sessionPost(browser, BOB_ID, "/tickets", { subject: `E2E link ticket ${Date.now()}`, description: "Profile links" });
    expect(createTicket.ok()).toBe(true);

    const page = await browser.newPage();
    await injectAuth(page, BOB_ID);
    await page.goto(`${BASE}/tickets`, { waitUntil: "load" });

    const ownerLink = page.getByRole("link", { name: new RegExp(`Open ${BOB_ID} profile`) }).first();
    await expect(ownerLink).toBeVisible({ timeout: 8_000 });
    await ownerLink.click();
    await expect(page).toHaveURL(/\/u\//, { timeout: 8_000 });
    await page.close();
  });

  test("unauthenticated canonical profile render remains public", async ({ page }) => {
    await page.goto(`${BASE}/u/${encodeURIComponent(BOB_ID)}`, { waitUntil: "load" });
    await expect(page.getByText(/Audience: public/i)).toBeVisible({ timeout: 8_000 });
  });
});
