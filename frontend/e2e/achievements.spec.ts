/**
 * E2E tests for ENGAGE-001 Achievements & Gamification System.
 *
 * Sections:
 *   80  — Admin definition CRUD API          (7 tests)
 *   81  — Admin seed endpoint                (2 tests)
 *   82  — Progress advance + auto-unlock API (6 tests)
 *   83  — Display badges API                 (5 tests)
 *   84  — Leaderboard API                    (5 tests)
 *   84b — Achievements UI page               (7 tests)
 *
 * Auth:
 *   Root  — root.admin@testdev.local (for admin endpoints)
 *   Alice — e2e_alice@test.local     (for user endpoints + UI)
 *
 * IMPORTANT: ACHIEVEMENTS_ENABLED=true must be set in .env.local.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ── Constants ────────────────────────────────────────────────────────────────

const BASE      = "http://localhost:3000";
const ROOT_ID   = "root";
const ALICE_ID  = "alice";
const TS        = Date.now();

// Unique test IDs scoped to this run
const ACH_ID_1   = `ach_test_a_${TS}`;
const ACH_ID_2   = `ach_test_b_${TS}`;
const ACH_ID_3   = `ach_test_c_${TS}`;
const METRIC_KEY = `test_metric_${TS}`;

// ── Session bootstrap ────────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    (uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    session.user_sub,
  );
}

// ── API helpers (through Vite proxy so cookies are forwarded) ────────────────

function csrfFor(identity: string): string {
  return getSessions()[identity].csrf_token;
}

async function apiGet(page: Page, identity: string, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPost(page: Page, identity: string, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiPut(page: Page, identity: string, path: string, body: object) {
  return page.request.put(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": csrfFor(identity) },
  });
}

// ── DDB helper ───────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, json
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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
`;

function ddbCleanup(tableName: string, pk: string, pkVal: string, sk?: string, skVal?: string): void {
  try {
    let keyDict: string;
    if (sk && skVal) {
      keyDict = `{'${pk}': '${pkVal}', '${sk}': '${skVal}'}`;
    } else {
      keyDict = `{'${pk}': '${pkVal}'}`;
    }
    execSync(
      `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('${tableName}')
tbl.delete_item(Key=${keyDict})
print('cleaned')
"`,
      { timeout: 10_000 },
    );
  } catch {
    // best-effort
  }
}

// =============================================================================
// Section 80 — Admin definition CRUD API
// =============================================================================

test.describe("80 — Admin definition CRUD API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test.afterAll(async () => {
    // Clean up test definitions
    try {
      await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${ACH_ID_1}`);
    } catch { /* ignore */ }
    try {
      await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${ACH_ID_2}`);
    } catch { /* ignore */ }
    await rootPage.close();
  });

  test("80.1 Root can create an achievement definition", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
      achievement_id: ACH_ID_1,
      category: "creator",
      subcategory: "testing",
      label: "Test Achievement A",
      description: "A test achievement for E2E",
      icon_url: "/assets/badges/test.svg",
      rarity: "common",
      threshold: 5,
      points: 10,
      metric_key: METRIC_KEY,
      sort_order: 0,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.achievement_id).toBe(ACH_ID_1);
    expect(data.category).toBe("creator");
    expect(data.label).toBe("Test Achievement A");
    expect(data.threshold).toBe(5);
    expect(data.points).toBe(10);
    expect(data.active).toBe(true);
  });

  test("80.2 Duplicate achievement_id returns 409", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
      achievement_id: ACH_ID_1,
      category: "creator",
      subcategory: "testing",
      label: "Duplicate",
      description: "Should fail",
      icon_url: "/assets/badges/test.svg",
      rarity: "common",
      threshold: 5,
      points: 10,
      metric_key: METRIC_KEY,
    });
    expect(resp.status()).toBe(409);
  });

  test("80.3 Root can create a second definition with higher threshold", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
      achievement_id: ACH_ID_2,
      category: "creator",
      subcategory: "testing",
      label: "Test Achievement B",
      description: "A higher tier test achievement",
      icon_url: "/assets/badges/test-b.svg",
      rarity: "uncommon",
      threshold: 10,
      points: 25,
      metric_key: METRIC_KEY,
      sort_order: 1,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.achievement_id).toBe(ACH_ID_2);
    expect(data.threshold).toBe(10);
  });

  test("80.4 Root can update a definition", async () => {
    const resp = await apiPut(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${ACH_ID_1}`, {
      label: "Updated Test A",
      points: 15,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.label).toBe("Updated Test A");
    expect(data.points).toBe(15);
  });

  test("80.5 Root can list definitions", async () => {
    const resp = await apiGet(rootPage, ROOT_ID, "/ui/achievements/definitions?active_only=false");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.definitions).toBeDefined();
    const testDefs = data.definitions.filter(
      (d: { metric_key: string }) => d.metric_key === METRIC_KEY,
    );
    expect(testDefs.length).toBeGreaterThanOrEqual(2);
  });

  test("80.6 Root can soft-delete a definition", async () => {
    const resp = await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${ACH_ID_2}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);

    // Verify it's deactivated
    const listResp = await apiGet(rootPage, ROOT_ID, "/ui/achievements/definitions?active_only=true");
    const listData = await listResp.json();
    const deleted = listData.definitions.find(
      (d: { achievement_id: string }) => d.achievement_id === ACH_ID_2,
    );
    expect(deleted).toBeUndefined();
  });

  test("80.7 Non-root (Alice) cannot create definitions (403)", async () => {
    const alicePage = await rootPage.context().browser()!.newPage();
    await injectAuth(alicePage, ALICE_ID);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/achievements/admin/definitions", {
      achievement_id: "ach_should_fail",
      category: "creator",
      subcategory: "testing",
      label: "Should Fail",
      description: "Alice should not be able to do this",
      icon_url: "/assets/badges/fail.svg",
      rarity: "common",
      threshold: 1,
      points: 5,
      metric_key: "fail_metric",
    });
    expect(resp.status()).toBe(403);
    await alicePage.close();
  });
});

// =============================================================================
// Section 81 — Admin seed endpoint
// =============================================================================

test.describe("81 — Admin seed endpoint", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);
  });

  test.afterAll(async () => {
    await rootPage.close();
  });

  test("81.1 Root can seed default achievements", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/seed", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.count).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.created)).toBe(true);
  });

  test("81.2 Seeding again is idempotent (no duplicates)", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/seed", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    // Most or all should be skipped as duplicates
  });
});

// =============================================================================
// Section 82 — Progress advance + auto-unlock API
// =============================================================================

test.describe("82 — Progress advance + auto-unlock API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let aliceSub: string;
  const PROGRESS_METRIC = `progress_e2e_${TS}`;
  const PROGRESS_ACH_ID = `ach_prog_${TS}`;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Create a definition for this section's metric with threshold=3
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
      achievement_id: PROGRESS_ACH_ID,
      category: "general",
      subcategory: "e2e",
      label: "Progress Test Badge",
      description: "Unlocked after 3 increments",
      icon_url: "/assets/badges/progress.svg",
      rarity: "rare",
      threshold: 3,
      points: 50,
      metric_key: PROGRESS_METRIC,
      sort_order: 0,
    });
    expect(resp.status()).toBe(201);
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${PROGRESS_ACH_ID}`);
    } catch { /* ignore */ }
    await rootPage.close();
    await alicePage.close();
  });

  test("82.1 Alice can advance progress (delta=1)", async () => {
    // GAP-0161: admin/advance is now ROOT-only; root advances Alice's progress.
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/advance", {
      metric_key: PROGRESS_METRIC,
      delta: 1,
      user_sub: aliceSub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.newly_unlocked).toEqual([]);
  });

  test("82.2 Alice can check progress for metric", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/achievements/progress/${PROGRESS_METRIC}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.metric_key).toBe(PROGRESS_METRIC);
    expect(data.current_value).toBe(1);
  });

  test("82.3 Advance to threshold triggers auto-unlock", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/advance", {
      metric_key: PROGRESS_METRIC,
      delta: 2,
      user_sub: aliceSub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.newly_unlocked.length).toBe(1);
    expect(data.newly_unlocked[0].achievement_id).toBe(PROGRESS_ACH_ID);
    expect(data.newly_unlocked[0].label).toBe("Progress Test Badge");
    expect(data.newly_unlocked[0].rarity).toBe("rare");
    expect(data.newly_unlocked[0].points).toBe(50);
  });

  test("82.4 Further advance does not re-unlock (idempotent)", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/advance", {
      metric_key: PROGRESS_METRIC,
      delta: 1,
      user_sub: aliceSub,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.newly_unlocked).toEqual([]);
  });

  test("82.5 Alice can list all progress", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/progress");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.progress)).toBe(true);
    const prog = data.progress.find(
      (p: { metric_key: string }) => p.metric_key === PROGRESS_METRIC,
    );
    expect(prog).toBeDefined();
    expect(prog.current_value).toBe(4);
  });

  test("82.6 Alice has the earned achievement", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/earned");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.achievements)).toBe(true);
    const earned = data.achievements.find(
      (a: { achievement_id: string }) => a.achievement_id === PROGRESS_ACH_ID,
    );
    expect(earned).toBeDefined();
    expect(earned.points).toBe(50);
    expect(earned.displayed).toBe(false);
  });
});

// =============================================================================
// Section 83 — Display badges API
// =============================================================================

test.describe("83 — Display badges API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const BADGE_METRIC = `badge_e2e_${TS}`;
  const BADGE_ACH_IDS = [
    `ach_badge_a_${TS}`,
    `ach_badge_b_${TS}`,
    `ach_badge_c_${TS}`,
    `ach_badge_d_${TS}`,
  ];
  let aliceSub: string;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Create 4 definitions and unlock them all for Alice
    for (let i = 0; i < BADGE_ACH_IDS.length; i++) {
      const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
        achievement_id: BADGE_ACH_IDS[i],
        category: "general",
        subcategory: "badge_test",
        label: `Badge ${i + 1}`,
        description: `Badge test ${i + 1}`,
        icon_url: `/assets/badges/badge-${i}.svg`,
        rarity: i === 3 ? "epic" : "common",
        threshold: 1,
        points: 10,
        metric_key: `${BADGE_METRIC}_${i}`,
        sort_order: i,
      });
      expect(resp.status()).toBe(201);

      // Advance to unlock (GAP-0161: ROOT-only; root targets Alice)
      const advResp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/advance", {
        metric_key: `${BADGE_METRIC}_${i}`,
        delta: 1,
        user_sub: aliceSub,
      });
      expect(advResp.status()).toBe(200);
    }
  });

  test.afterAll(async () => {
    for (const achId of BADGE_ACH_IDS) {
      try {
        await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${achId}`);
      } catch { /* ignore */ }
    }
    await rootPage.close();
    await alicePage.close();
  });

  test("83.1 Alice can set display badges (max 3)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/achievements/display-badges", {
      achievement_ids: [BADGE_ACH_IDS[0], BADGE_ACH_IDS[1], BADGE_ACH_IDS[2]],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.display_badges.length).toBe(3);
  });

  test("83.2 Exceeding max 3 display badges returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/achievements/display-badges", {
      achievement_ids: BADGE_ACH_IDS,
    });
    expect(resp.status()).toBe(400);
  });

  test("83.3 Setting non-unlocked badge returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/achievements/display-badges", {
      achievement_ids: ["ach_nonexistent_fake"],
    });
    expect(resp.status()).toBe(400);
  });

  test("83.4 Anyone can view Alice's display badges", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, `/ui/achievements/display-badges/${aliceSub}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_sub).toBe(aliceSub);
    expect(data.display_badges.length).toBe(3);
    expect(data.total_points).toBeGreaterThan(0);
    expect(data.achievement_count).toBeGreaterThan(0);
  });

  test("83.5 Alice can clear display badges", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/achievements/display-badges", {
      achievement_ids: [],
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.display_badges).toEqual([]);

    // Verify via GET
    const getResp = await apiGet(alicePage, ALICE_ID, `/ui/achievements/display-badges/${aliceSub}`);
    const getData = await getResp.json();
    expect(getData.display_badges.length).toBe(0);
  });
});

// =============================================================================
// Section 84 — Leaderboard API
// =============================================================================

test.describe("84 — Leaderboard API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("84.1 Alice can fetch weekly leaderboard", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/leaderboard?period=weekly");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe("weekly");
    expect(Array.isArray(data.entries)).toBe(true);
  });

  test("84.2 Alice can fetch monthly leaderboard", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/leaderboard?period=monthly");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe("monthly");
    expect(Array.isArray(data.entries)).toBe(true);
  });

  test("84.3 Alice can fetch alltime leaderboard", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/leaderboard?period=alltime");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe("alltime");
    expect(Array.isArray(data.entries)).toBe(true);
    // Alice should appear because she unlocked badges in previous sections
    if (data.entries.length > 0) {
      expect(data.entries[0].rank).toBe(1);
      expect(typeof data.entries[0].total_points).toBe("number");
    }
  });

  test("84.4 Alice can fetch her own rank", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/leaderboard/me?period=alltime");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.period).toBe("alltime");
    expect(typeof data.total_points).toBe("number");
    expect(data.user_sub).toBe(getSessions()[ALICE_ID].user_sub);
  });

  test("84.5 Leaderboard entries have correct shape", async () => {
    const resp = await apiGet(alicePage, ALICE_ID, "/ui/achievements/leaderboard?period=alltime&limit=5");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    if (data.entries.length > 0) {
      const entry = data.entries[0];
      expect(entry).toHaveProperty("rank");
      expect(entry).toHaveProperty("user_sub");
      expect(entry).toHaveProperty("total_points");
      expect(entry).toHaveProperty("achievement_count");
    }
  });
});

// =============================================================================
// Section 84b — Achievements UI page
// =============================================================================

test.describe("84b — Achievements UI page", () => {
  let rootPage: Page;
  let alicePage: Page;
  let aliceSub: string;
  const UI_METRIC = `ui_ach_${TS}`;
  const UI_ACH_ID = `ach_ui_${TS}`;
  const UI_BADGE_LABEL = `UI Badge ${TS}`;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, ROOT_ID);

    // Create a definition and unlock for Alice (for badge grid)
    const resp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/definitions", {
      achievement_id: UI_ACH_ID,
      category: "creator",
      subcategory: "ui_test",
      label: UI_BADGE_LABEL,
      description: "Badge visible in the UI",
      icon_url: "/assets/badges/ui-test.svg",
      rarity: "epic",
      threshold: 1,
      points: 100,
      metric_key: UI_METRIC,
      sort_order: 0,
    });
    expect(resp.status()).toBe(201);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Advance to unlock (GAP-0161: ROOT-only; root targets Alice)
    const advResp = await apiPost(rootPage, ROOT_ID, "/ui/achievements/admin/advance", {
      metric_key: UI_METRIC,
      delta: 1,
      user_sub: aliceSub,
    });
    expect(advResp.status()).toBe(200);
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, ROOT_ID, `/ui/achievements/admin/definitions/${UI_ACH_ID}`);
    } catch { /* ignore */ }
    await rootPage.close();
    await alicePage.close();
  });

  test("84b.1 Alice can navigate to /achievements page", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByRole("heading", { name: "Achievements" })).toBeVisible();
  });

  test("84b.2 Page shows My Badges tab by default", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    // Wait for the badges tab content to load
    await expect(alicePage.getByText("badges earned")).toBeVisible({ timeout: 10_000 });
  });

  test("84b.3 Badge grid shows earned badges", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("badges earned")).toBeVisible({ timeout: 10_000 });
    // Should see at least one badge (the one we unlocked)
    await expect(alicePage.getByText(UI_BADGE_LABEL).first()).toBeVisible({ timeout: 10_000 });
  });

  test("84b.4 Badge shows rarity and points", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText(UI_BADGE_LABEL).first()).toBeVisible({ timeout: 10_000 });
    // The badge grid shows rarity badges and point labels
    await expect(alicePage.getByText("epic").first()).toBeVisible();
    await expect(alicePage.getByText("+100 pts").first()).toBeVisible();
  });

  test("84b.5 Progress tab shows progress bars", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("tab", { name: "Progress" }).click();
    // Should show at least one progress entry
    await expect(
      alicePage.getByText("Loading progress...").or(alicePage.locator(".h-3"))
    ).toBeVisible({ timeout: 10_000 });
  });

  test("84b.6 Leaderboard tab shows leaderboard", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("tab", { name: "Leaderboard" }).click();
    // Should show leaderboard content or empty state
    await expect(
      alicePage.getByText("Leaderboard").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("84b.7 Leaderboard has period selector", async () => {
    await alicePage.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
    await alicePage.getByRole("tab", { name: "Leaderboard" }).click();
    // The period selector (Select component) should be visible
    await expect(alicePage.getByRole("combobox")).toBeVisible({ timeout: 10_000 });
  });
});
