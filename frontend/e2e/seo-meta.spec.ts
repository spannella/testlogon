import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon", timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  // Set the Zustand auth-store in localStorage so ProtectedRoute passes
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await injectAuth(page, identity);
  return page;
}

const ALICE_ID = "alice";

// ---------------------------------------------------------------------------
// Section 76: SEO / Open Graph Meta Tags — Document Titles
// ---------------------------------------------------------------------------
test.describe("76 · SEO & Meta — Document titles and Open Graph", () => {
  test("76.1 Dashboard page sets correct document title", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_ID);
    // Dashboard is the index route at "/"
    await page.goto("/");
    await expect(page).toHaveTitle(/Dashboard.*Control Panel/);
    await page.context().close();
  });

  test("76.2 Messages page sets correct document title", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_ID);
    await page.goto("/messages");
    await expect(page).toHaveTitle(/Messages.*Control Panel/);
    await page.context().close();
  });

  test("76.3 Feed page sets correct document title", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_ID);
    await page.goto("/feed");
    await expect(page).toHaveTitle(/Feed.*Control Panel/);
    await page.context().close();
  });

  test("76.4 PageMeta renders og:title and description meta tags", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE_ID);
    // Dashboard is the index route at "/"
    await page.goto("/");
    // Wait for Helmet to update the title
    await expect(page).toHaveTitle(/Dashboard.*Control Panel/);

    // description meta tag should be present
    const metaDesc = await page
      .locator('meta[name="description"]')
      .first()
      .getAttribute("content");
    expect(metaDesc).toBeTruthy();
    expect(metaDesc!.length).toBeGreaterThan(0);

    // og:title meta tag should be present
    const ogTitle = await page
      .locator('meta[property="og:title"]')
      .first()
      .getAttribute("content");
    expect(ogTitle).toBeTruthy();
    expect(ogTitle).toContain("Dashboard");

    // og:description meta tag should be present
    const ogDesc = await page
      .locator('meta[property="og:description"]')
      .first()
      .getAttribute("content");
    expect(ogDesc).toBeTruthy();

    await page.context().close();
  });

  test("76.5 Login page sets correct document title (no auth required)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto("http://localhost:3000/login");
    await expect(page).toHaveTitle(/Log In.*Control Panel/);
    await ctx.close();
  });

  test("76.6 Register page sets correct document title (no auth required)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto("http://localhost:3000/register");
    await expect(page).toHaveTitle(/Create Account.*Control Panel/);
    await ctx.close();
  });

  test("76.7 Default Helmet title is set in App.tsx", async ({ browser }) => {
    // Even on pages without explicit PageMeta, the default Helmet in App.tsx
    // should set a title containing "Control Panel"
    const page = await newIdentityPage(browser, ALICE_ID);
    await page.goto("/calendar");
    await expect(page).toHaveTitle(/Control Panel/);
    await page.context().close();
  });
});
