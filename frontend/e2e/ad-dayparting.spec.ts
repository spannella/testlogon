/**
 * E2E tests for Ad Scheduling & Dayparting (ADS-016).
 *
 * Sections:
 *   408 — Dayparting Configuration API (4 tests)
 *   409 — Flight Scheduling API (4 tests)
 *   410 — Eligibility & Budget Pacing API (4 tests)
 *   411 — Schedule UI (1 test)
 *
 * Auth:
 *   Alice (USER) — advertiser who owns the account + campaign
 *   Bob (USER)   — non-owner (ownership isolation)
 *   Root (ROOT)  — approves the account + campaign so it becomes active
 *
 * Sessions created by e2e_admin_session_setup.py (role-bearing JWT cookies).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const ALICE_ID = "alice";
const BOB_ID = "bob";
const ROOT_ID = "root";
const TS = Date.now();

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
function getAdminSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getAdminSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

let alicePage: Page;
let bobPage: Page;
let rootPage: Page;
let accountId: string;
let campaignId: string;

const FULL_SCHEDULE = {
  monday: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  tuesday: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  wednesday: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  thursday: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  friday: [9, 10, 11, 12, 13, 14, 15, 16, 17],
  saturday: [],
  sunday: [],
};

test.beforeAll(async ({ browser }) => {
  alicePage = await newIdentityPage(browser, ALICE_ID);
  bobPage = await newIdentityPage(browser, BOB_ID);
  rootPage = await newIdentityPage(browser, ROOT_ID);

  // Create + approve an advertiser account.
  const acctResp = await apiPost(alicePage, ALICE_ID, "/ui/ads/accounts", {
    company_name: `SchedCo_${TS}`,
    billing_email: `sched_${TS}@acme.test`,
  });
  expect(acctResp.status(), `account create: ${await acctResp.text()}`).toBe(201);
  accountId = (await acctResp.json()).account_id;
  expect(accountId, "account_id must be defined").toBeTruthy();

  const reviewResp = await apiPost(
    rootPage,
    ROOT_ID,
    `/ui/admin/ads/accounts/${accountId}/review`,
    { decision: "approve", notes: "ok" },
  );
  expect(reviewResp.status(), `account review: ${await reviewResp.text()}`).toBe(200);

  // Create a campaign with broad start/end dates so flights fit within range.
  // CampaignCreateIn.start_date/end_date are Unix timestamps (int), not ISO strings.
  const campResp = await apiPost(
    alicePage,
    ALICE_ID,
    `/ui/ads/accounts/${accountId}/campaigns`,
    {
      name: `Sched Campaign ${TS}`,
      objective: "awareness",
      budget_cents: 240000,
      budget_type: "daily",
      start_date: Math.floor(Date.UTC(2026, 5, 1) / 1000),
      end_date: Math.floor(Date.UTC(2026, 5, 30) / 1000),
    },
  );
  expect(campResp.status(), `campaign create: ${await campResp.text()}`).toBe(201);
  campaignId = (await campResp.json()).campaign_id;
  expect(campaignId, "campaign_id must be defined").toBeTruthy();
});

test.afterAll(async () => {
  await alicePage?.close();
  await bobPage?.close();
  await rootPage?.close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 408: Dayparting Configuration API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("408 — Dayparting Configuration API", () => {
  test("408.1 Set dayparting schedule on campaign", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        campaign_timezone: "America/New_York",
        dayparting: { timezone: "America/New_York", schedule: FULL_SCHEDULE },
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.dayparting.timezone).toBe("America/New_York");
    expect(data.dayparting.schedule.monday).toEqual(FULL_SCHEDULE.monday);
    expect(data.dayparting.schedule.saturday).toEqual([]);
  });

  test("408.2 Invalid timezone rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        dayparting: { timezone: "Invalid/Zone", schedule: { monday: [9] } },
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("408.3 Empty schedule rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        dayparting: {
          timezone: "UTC",
          schedule: {
            monday: [],
            tuesday: [],
            wednesday: [],
            thursday: [],
            friday: [],
            saturday: [],
            sunday: [],
          },
        },
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("408.4 Get schedule returns dayparting config", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // Reflects the schedule set in 408.1 (408.2/408.3 were rejected, no change).
    expect(data.dayparting.timezone).toBe("America/New_York");
    expect(data.dayparting.schedule.monday).toEqual(FULL_SCHEDULE.monday);
  });

  test("408.5 Non-owner cannot set schedule", async () => {
    const resp = await apiPatch(
      bobPage,
      BOB_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      { dayparting: { timezone: "UTC", schedule: { monday: [9] } } },
    );
    expect(resp.status()).toBe(403);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 409: Flight Scheduling API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("409 — Flight Scheduling API", () => {
  test("409.1 Set flight schedule on campaign", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        flights: [
          {
            name: "Teaser",
            start_date: "2026-06-01",
            end_date: "2026-06-14",
            daily_budget_cents: 50000,
            creative_ids: ["cr_1", "cr_2"],
          },
          {
            name: "Full Launch",
            start_date: "2026-06-15",
            end_date: "2026-06-30",
            daily_budget_cents: 200000,
            creative_ids: ["cr_3"],
          },
        ],
      },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.flights.length).toBe(2);
    expect(data.flights[0].flight_id).toBeTruthy();
    expect(data.flights[0].status).toBe("scheduled");
  });

  test("409.2 Overlapping flights rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        flights: [
          {
            name: "A",
            start_date: "2026-06-01",
            end_date: "2026-06-15",
            daily_budget_cents: 50000,
            creative_ids: ["cr_1"],
          },
          {
            name: "B",
            start_date: "2026-06-10",
            end_date: "2026-06-20",
            daily_budget_cents: 50000,
            creative_ids: ["cr_2"],
          },
        ],
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("409.3 Flight outside campaign range rejected", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        flights: [
          {
            name: "OutOfRange",
            start_date: "2026-05-01",
            end_date: "2026-06-10",
            daily_budget_cents: 50000,
            creative_ids: ["cr_1"],
          },
        ],
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("409.4 Invalid flight (budget too low) rejected with 422", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule`,
      {
        flights: [
          {
            name: "Cheap",
            start_date: "2026-06-01",
            end_date: "2026-06-10",
            daily_budget_cents: 1,
            creative_ids: ["cr_1"],
          },
        ],
      },
    );
    // Pydantic field constraint (ge=100) → 422.
    expect(resp.status()).toBe(422);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 410: Eligibility & Budget Pacing API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("410 — Eligibility & Budget Pacing API", () => {
  // 2026-06-01 is a Monday. 14:00 UTC == 10:00 ET (within 9-17 schedule).
  const MON_14_UTC = Math.floor(Date.UTC(2026, 5, 1, 14, 0, 0) / 1000);
  // 2026-06-07 is a Sunday (schedule empty → not eligible).
  const SUN_14_UTC = Math.floor(Date.UTC(2026, 5, 7, 14, 0, 0) / 1000);

  test("410.1 Eligibility active when within daypart (deterministic now)", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule/eligibility?now=${MON_14_UTC}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data).toHaveProperty("eligible");
    expect(data).toHaveProperty("timezone");
    expect(data).toHaveProperty("day");
    expect(data).toHaveProperty("hour");
    expect(data.eligible).toBe(true);
    expect(data.day).toBe("monday");
    expect(data.hour).toBe(10); // 14:00 UTC → 10:00 ET
  });

  test("410.2 Eligibility false outside daypart (Sunday)", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule/eligibility?now=${SUN_14_UTC}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.eligible).toBe(false);
  });

  test("410.3 Budget pacing reflects dayparting hours", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      `/ui/ads/scheduling/campaigns/${campaignId}/schedule/pacing?now=${MON_14_UTC}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.active_hours_today).toBeLessThanOrEqual(24);
    // 9 active hours on Monday (9-17).
    expect(data.active_hours_today).toBe(9);
    expect(data.remaining_budget_cents).toBeLessThanOrEqual(240000);
  });

  test("410.4 Schedule templates endpoint returns presets", async () => {
    const resp = await apiGet(
      alicePage,
      ALICE_ID,
      "/ui/ads/scheduling/templates",
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.templates).toHaveProperty("weekdays_business");
    expect(data.templates).toHaveProperty("evenings");
    expect(data.templates).toHaveProperty("weekends");
    expect(data.templates).toHaveProperty("always");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 411: Schedule UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("411 — Schedule UI", () => {
  test("411.1 Schedule page loads with weekly grid", async () => {
    await injectAuth(alicePage, ALICE_ID);
    await alicePage.goto(`${BASE}/ads/scheduling?campaign=${campaignId}`);
    await expect(
      alicePage.getByRole("heading", { name: /Ad Schedule/i }),
    ).toBeVisible();
    // Weekly grid cells render.
    await expect(
      alicePage.getByTestId("cell-monday-10"),
    ).toBeVisible();
    await expect(alicePage.getByTestId("dayparting-summary")).toBeVisible();
    // Presets and save button present.
    await expect(alicePage.getByTestId("preset-weekdays_business")).toBeVisible();
    await expect(alicePage.getByTestId("save-schedule")).toBeVisible();
  });
});
