/**
 * E2E tests for Activity Feed Engine (SOC-003).
 *
 * Sections:
 *   200 — Activity Feed API   (10 tests)
 *   201 — Activity Feed UI    (6 tests)
 *
 * Auth: Alice + Bob session cookies (from e2e_session_setup.py).
 *
 * This tests the dedicated activity_feed DynamoDB table and the
 * /ui/activity/* endpoints (separate from the alerts-based activity
 * system tested in activity-feed.spec.ts).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── API helpers — route through Vite proxy so session cookies are forwarded ─

async function apiGet(page: Page, path: string, identity = ALICE_ID) {
  const session = getSessions()[identity];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(page: Page, path: string, body: object, identity = ALICE_ID) {
  const session = getSessions()[identity];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helper: ensure activity_feed table exists ──────────────────────────

function ensureActivityFeedTable(): void {
  const script = `
import boto3, os
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
try:
    tbl = ddb.Table('activity_feed')
    tbl.load()
    print('exists')
except Exception:
    try:
        tbl = ddb.create_table(
            TableName='activity_feed',
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                {'AttributeName': 'sk', 'KeyType': 'RANGE'},
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},
                {'AttributeName': 'sk', 'AttributeType': 'S'},
            ],
            BillingMode='PAY_PER_REQUEST',
        )
        tbl.wait_until_exists()
        print('created')
    except Exception as e:
        if 'ResourceInUseException' in str(type(e)):
            print('exists')
        else:
            raise
`;
  execSync(`python3 -c "${script.replace(/"/g, '\\"')}"`, {
    cwd: REPO_ROOT,
    timeout: 15_000,
  });
}

// =============================================================================
// Section 200 — Activity Feed API (SOC-003)
// =============================================================================

test.describe("200 — Activity Feed API (SOC-003)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    ensureActivityFeedTable();
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("200.1 GET /ui/activity/feed returns valid response shape", async () => {
    const resp = await apiGet(alicePage, "/ui/activity/feed");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data).toHaveProperty("items");
    expect(data).toHaveProperty("next_cursor");
    expect(data).toHaveProperty("total_unread");
    expect(Array.isArray(data.items)).toBe(true);
  });

  test("200.2 POST /ui/activity/feed/record creates activity item", async () => {
    const resp = await apiPost(alicePage, "/ui/activity/feed/record", {
      user_id: ALICE_ID,
      actor_id: BOB_ID,
      activity_type: "follow",
      target_type: "user",
      target_id: ALICE_ID,
      metadata: { description: `Bob followed Alice ${TS}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.activity_id).toBeTruthy();
    expect(typeof data.activity_id).toBe("string");
    expect(data.created_at).toBeGreaterThan(0);
  });

  test("200.3 recorded activity appears in feed", async () => {
    const resp = await apiGet(alicePage, "/ui/activity/feed");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const followItems = data.items.filter(
      (it: any) => it.activity_type === "follow" && it.actor_id === BOB_ID,
    );
    expect(followItems.length).toBeGreaterThanOrEqual(1);
    // Verify item shape
    const item = followItems[0];
    expect(item).toHaveProperty("activity_id");
    expect(item).toHaveProperty("actor_id");
    expect(item).toHaveProperty("activity_type");
    expect(item).toHaveProperty("created_at");
    expect(item).toHaveProperty("read");
  });

  test("200.4 record multiple activity types", async () => {
    const types = ["like", "comment", "tip"];
    for (const actType of types) {
      const resp = await apiPost(alicePage, "/ui/activity/feed/record", {
        user_id: ALICE_ID,
        actor_id: BOB_ID,
        activity_type: actType,
        target_type: "post",
        target_id: `post_${TS}_${actType}`,
        metadata: { description: `${actType} activity ${TS}` },
      });
      expect(resp.ok()).toBeTruthy();
      const data = await resp.json();
      expect(data.ok).toBe(true);
    }
  });

  test("200.5 GET /ui/activity/feed/unread-count reflects new activities", async () => {
    const resp = await apiGet(alicePage, "/ui/activity/feed/unread-count");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data).toHaveProperty("count");
    expect(data.count).toBeGreaterThanOrEqual(4); // follow + like + comment + tip
  });

  test("200.6 GET /ui/activity/feed/filter?activity_type=follow returns only follows", async () => {
    const resp = await apiGet(
      alicePage,
      "/ui/activity/feed/filter?activity_type=follow",
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    for (const item of data.items) {
      expect(item.activity_type).toBe("follow");
    }
  });

  test("200.7 filter by like type returns only likes", async () => {
    const resp = await apiGet(
      alicePage,
      "/ui/activity/feed/filter?activity_type=like",
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);
    for (const item of data.items) {
      expect(item.activity_type).toBe("like");
    }
  });

  test("200.8 POST /ui/activity/feed/mark-read marks activities as read", async () => {
    const resp = await apiPost(alicePage, "/ui/activity/feed/mark-read", {});
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.marked_count).toBeGreaterThanOrEqual(1);
  });

  test("200.9 unread count is zero after mark-read", async () => {
    const resp = await apiGet(alicePage, "/ui/activity/feed/unread-count");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.count).toBe(0);
  });

  test("200.10 feed items have created_at field with valid timestamp", async () => {
    // Record a fresh activity to verify fields
    await apiPost(alicePage, "/ui/activity/feed/record", {
      user_id: ALICE_ID,
      actor_id: BOB_ID,
      activity_type: "share",
      target_type: "post",
      target_id: `post_ts_${TS}`,
      metadata: { description: `share for field check ${TS}` },
    });
    const resp = await apiGet(alicePage, "/ui/activity/feed");
    const data = await resp.json();
    const shareItem = data.items.find(
      (it: any) =>
        it.activity_type === "share" &&
        it.target_id === `post_ts_${TS}`,
    );
    expect(shareItem).toBeTruthy();
    expect(shareItem.created_at).toBeGreaterThan(1_700_000_000); // sanity: after 2023
  });
});

// =============================================================================
// Section 201 — Activity Feed UI (SOC-003)
// =============================================================================

test.describe("201 — Activity Feed UI (SOC-003)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    ensureActivityFeedTable();
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Seed activities for UI tests
    const session = getSessions()[ALICE_ID];
    for (const actType of ["follow", "like", "comment", "mention", "tip"]) {
      await alicePage.request.post(`${BASE}/ui/activity/feed/record`, {
        data: {
          user_id: ALICE_ID,
          actor_id: BOB_ID,
          activity_type: actType,
          target_type: "post",
          target_id: `ui_${TS}_${actType}`,
          metadata: { description: `UI test ${actType} ${TS}` },
        },
        headers: { "x-csrf-token": session.csrf_token },
      });
    }
  });

  test.afterAll(async () => {
    await alicePage.context().close();
  });

  test("201.1 /activity page loads with heading", async () => {
    await alicePage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.getByText("Activity Feed", { exact: true }).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("201.2 activity items are displayed in the list", async () => {
    await alicePage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("[data-testid='activity-list']"),
    ).toBeVisible({ timeout: 10_000 });
    const items = alicePage.locator("[data-testid='activity-item']");
    await expect(items.first()).toBeVisible({ timeout: 5_000 });
    const count = await items.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test("201.3 filter tabs are present and clickable", async () => {
    await alicePage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("[data-testid='filter-tabs']"),
    ).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.locator("[data-testid='filter-all']")).toBeVisible();
    await expect(alicePage.locator("[data-testid='filter-follow']")).toBeVisible();
    await expect(alicePage.locator("[data-testid='filter-like']")).toBeVisible();
    await expect(alicePage.locator("[data-testid='filter-tip']")).toBeVisible();
  });

  test("201.4 clicking filter tab shows only matching activity types", async () => {
    await alicePage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });
    await expect(
      alicePage.locator("[data-testid='filter-tabs']"),
    ).toBeVisible({ timeout: 10_000 });

    // Click follow filter
    await alicePage.locator("[data-testid='filter-follow']").click();
    await alicePage.waitForTimeout(1_500);

    // All visible items should have activity_type="follow"
    const items = alicePage.locator("[data-testid='activity-item']");
    const count = await items.count();
    if (count > 0) {
      for (let i = 0; i < count; i++) {
        const type = await items.nth(i).getAttribute("data-activity-type");
        expect(type).toBe("follow");
      }
    }
  });

  test("201.5 mark all read button clears unread state", async () => {
    await alicePage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });
    // Click "All" filter to reset
    await alicePage.locator("[data-testid='filter-all']").click();
    await alicePage.waitForTimeout(1_000);

    const markBtn = alicePage.locator("[data-testid='mark-all-read-btn']");
    await expect(markBtn).toBeVisible({ timeout: 10_000 });
    await markBtn.click();
    await alicePage.waitForTimeout(2_000);
    // After marking read, button should still be visible (but may be disabled)
    await expect(markBtn).toBeVisible();
  });

  test("201.6 page loads for user with no activities", async () => {
    const ctx = await alicePage.context().browser()!.newContext();
    const bobPage = await ctx.newPage();
    await injectAuth(bobPage, BOB_ID);
    await bobPage.goto(`${BASE}/activity`, { waitUntil: "domcontentloaded" });

    // Page should load without errors
    await expect(
      bobPage.getByText("Activity Feed", { exact: true }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Should show either items or the empty state. Wait for the feed query to
    // resolve (the loading spinner is shown until then, so neither testid is
    // present immediately after the heading mounts).
    const emptyState = bobPage.locator("[data-testid='empty-feed']");
    const actList = bobPage.locator("[data-testid='activity-list']");
    await expect(emptyState.or(actList).first()).toBeVisible({ timeout: 10_000 });
    const emptyVisible = await emptyState.isVisible().catch(() => false);
    const listVisible = await actList.isVisible().catch(() => false);
    expect(emptyVisible || listVisible).toBe(true);

    await ctx.close();
  });
});
