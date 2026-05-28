/**
 * E2E tests for SOC-006: Creator Storefront Page
 *
 * Section 117: Profile Page Tabs (5 tests)
 * Section 118: Follow Button (4 tests)
 * Section 119: Content Loading (4 tests)
 * Section 120: Unauthenticated View (3 tests)
 * Section 121: Stats Row (2 tests)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// --- Constants ----------------------------------------------------------------

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const API = "http://localhost:8000";
const ALICE_SUB = "e2e_alice@test.local";
const BOB_SUB = "e2e_bob@test.local";
const ALICE_KEY = "alice";
const BOB_KEY = "bob";
const TS = Date.now();

// --- Session bootstrap -------------------------------------------------------

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

// --- Request helpers ---------------------------------------------------------

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// --- DDB seed helpers --------------------------------------------------------

function ensureUsersAndProfiles(): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
users_tbl = ddb.Table('users')
prof_tbl = ddb.Table('profiles')

for sub, name, desc, loc in [
    ('${ALICE_SUB}', 'Alice Test', 'I create amazing content about technology and art.', 'San Francisco, CA'),
    ('${BOB_SUB}', 'Bob Test', 'E2E test profile', ''),
]:
    if not users_tbl.get_item(Key={'user_sub': sub}).get('Item'):
        users_tbl.put_item(Item={'user_sub': sub, 'created_at': int(time.time()) - 86400})

    prof = prof_tbl.get_item(Key={'user_sub': sub}).get('Item')
    profile_data = (prof.get('profile') or {}) if prof else {}
    profile_data['display_name'] = name
    profile_data['description'] = desc
    if loc:
        profile_data['location'] = loc
    profile_data.setdefault('follower_count', 42)
    profile_data.setdefault('following_count', 15)
    profile_data.setdefault('post_count', 0)
    prof_tbl.put_item(Item={
        'user_sub': sub,
        'profile': profile_data,
        'updated_at': int(time.time()),
    })

print('done')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

function seedAlicePosts(count: number): string[] {
  const raw = execSync(
    `${PYTHON} -c "
import boto3, os, uuid, time, json
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))

from datetime import datetime, timezone
post_ids = []
base_ts = int(time.time()) + 10
for i in range(${count}):
    post_id = uuid.uuid4().hex
    created_ts = base_ts + i
    created_at_iso = datetime.fromtimestamp(created_ts, tz=timezone.utc).isoformat()
    tbl.put_item(Item={
        'pk': f'POST#{post_id}',
        'sk': 'META',
        'Entity': 'Post',
        'post_id': post_id,
        'user_id': '${ALICE_SUB}',
        'created_at': created_at_iso,
        'published_at': created_at_iso,
        'status': 'published',
        'visibility': 'public',
        'body': f'Storefront test post {i} ts=${TS}',
        'body_format': 'plain',
        'locked': False,
        'like_count': i * 3,
        'comment_count': i,
        'tip_total_cents': 0,
        'GSI2PK': 'POST_AUTHOR#${ALICE_SUB}',
        'GSI2SK': f'{created_at_iso}#POST#{post_id}',
    })
    post_ids.append(post_id)

# Update post_count on profile
prof_tbl = ddb.Table('profiles')
prof = prof_tbl.get_item(Key={'user_sub': '${ALICE_SUB}'}).get('Item') or {}
profile_data = prof.get('profile') or {}
profile_data['post_count'] = len(post_ids) + int(profile_data.get('post_count', 0))
prof_tbl.put_item(Item={
    'user_sub': '${ALICE_SUB}',
    'profile': profile_data,
    'updated_at': int(time.time()),
})

print(json.dumps(post_ids))
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
  return JSON.parse(raw.toString().trim());
}

function seedSubscriptionPlan(): string {
  const raw = execSync(
    `${PYTHON} -c "
import boto3, os, uuid, time, json
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('subscriptions')

plan_id = f'plan_sf_{uuid.uuid4().hex[:8]}'
now = int(time.time())
tbl.put_item(Item={
    'pk': 'CREATOR#${ALICE_SUB}',
    'sk': f'PLAN#{plan_id}',
    'plan_id': plan_id,
    'creator_id': '${ALICE_SUB}',
    'name': 'Premium Access ${TS}',
    'description': 'Get full access to all premium content',
    'price_cents': 999,
    'currency': 'USD',
    'interval': 'month',
    'status': 'active',
    'metadata': {},
    'assets': [],
    'created_at': now,
    'updated_at': now,
})

print(plan_id)
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
  return raw.toString().trim();
}

function cleanupFollow(): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))

# Remove Bob -> Alice follow
try:
    tbl.delete_item(Key={'pk': 'USER#${BOB_SUB}', 'sk': 'FOLLOWING#${ALICE_SUB}'})
except Exception:
    pass
# Remove Alice <- Bob follower record
try:
    tbl.delete_item(Key={'pk': 'USER#${ALICE_SUB}', 'sk': 'FOLLOWER#${BOB_SUB}'})
except Exception:
    pass

# Remove Alice -> Bob follow
try:
    tbl.delete_item(Key={'pk': 'USER#${ALICE_SUB}', 'sk': 'FOLLOWING#${BOB_SUB}'})
except Exception:
    pass
try:
    tbl.delete_item(Key={'pk': 'USER#${BOB_SUB}', 'sk': 'FOLLOWER#${ALICE_SUB}'})
except Exception:
    pass

print('cleaned')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

function setFollowerCount(userSub: string, count: number): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path

env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
prof_tbl = ddb.Table('profiles')
prof = prof_tbl.get_item(Key={'user_sub': '${userSub}'}).get('Item') or {}
profile_data = prof.get('profile') or {}
profile_data['follower_count'] = ${count}
prof_tbl.put_item(Item={
    'user_sub': '${userSub}',
    'profile': profile_data,
    'updated_at': int(time.time()),
})
print('done')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// =============================================================================
// Test setup
// =============================================================================

test.describe("Creator Storefront", () => {

let bobPage: Page;
let alicePage: Page;
let seededPostIds: string[];
let planId: string;

test.beforeAll(async ({ browser }) => {
  ensureUsersAndProfiles();
  seededPostIds = seedAlicePosts(3);
  planId = seedSubscriptionPlan();
  cleanupFollow();

  bobPage = await newIdentityPage(browser, BOB_KEY);
  alicePage = await newIdentityPage(browser, ALICE_KEY);
});

test.afterAll(async () => {
  await bobPage?.close();
  await alicePage?.close();
});

// =============================================================================
// Section 117: Profile Page Tabs
// =============================================================================

test.describe("117 - Profile Page Tabs", () => {
  test("117.1 Tabs visible on authenticated profile view", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await expect(bobPage.getByRole("tab", { name: "Videos" })).toBeVisible();
    await expect(bobPage.getByRole("tab", { name: "Posts" })).toBeVisible();
    await expect(bobPage.getByRole("tab", { name: "About" })).toBeVisible();
  });

  test("117.2 Videos tab is default for authenticated users", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    const videosTab = bobPage.getByRole("tab", { name: "Videos" });
    await expect(videosTab).toBeVisible();
    await expect(videosTab).toHaveAttribute("data-state", "active");
  });

  test("117.3 Posts tab shows post cards when clicked", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await bobPage.getByRole("tab", { name: "Posts" }).click();
    // Wait for posts to load — we seeded 3 posts
    await expect(bobPage.getByTestId("post-card").first()).toBeVisible({ timeout: 10_000 });
    // Should see our seeded post text
    await expect(bobPage.getByText(`Storefront test post`, { exact: false }).first()).toBeVisible({ timeout: 8_000 });
  });

  test("117.4 About tab shows bio and location", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await bobPage.getByRole("tab", { name: "About" }).click();
    await expect(bobPage.getByText("I create amazing content about technology and art.")).toBeVisible();
    await expect(bobPage.getByText("San Francisco, CA")).toBeVisible();
  });

  test("117.5 Subscription plans section shown when creator has plans", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await expect(bobPage.getByText("Subscription Plans")).toBeVisible({ timeout: 10_000 });
    // Plan card should show the seeded plan
    await expect(bobPage.getByText(`Premium Access ${TS}`)).toBeVisible();
  });
});

// =============================================================================
// Section 118: Follow Button
// =============================================================================

test.describe("118 - Follow Button", () => {
  test("118.1 Follow button visible on other user's profile", async () => {
    cleanupFollow();
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await expect(bobPage.getByTestId("follow-button")).toBeVisible();
    await expect(bobPage.getByTestId("follow-button")).toContainText("Follow");
  });

  test("118.2 Clicking Follow changes state to Following", async () => {
    cleanupFollow();
    await bobPage.goto(`/u/${ALICE_SUB}`);
    const btn = bobPage.getByTestId("follow-button");
    await expect(btn).toBeVisible();
    await expect(btn).toContainText("Follow");
    await btn.click();
    await expect(btn).toContainText("Following", { timeout: 5_000 });
  });

  test("118.3 Clicking unfollow reverts to Follow", async () => {
    // Make sure we are following first
    const followResp = await apiPost(bobPage, BOB_KEY, "/ui/social/follow", {
      target_user_id: ALICE_SUB,
    });
    // May already be following from previous test
    expect([200, 409].includes(followResp.status())).toBe(true);

    await bobPage.goto(`/u/${ALICE_SUB}`);
    const btn = bobPage.getByTestId("follow-button");
    // Button shows "Following" when not hovered, "Unfollow" on hover — accept either
    await expect(btn).toBeVisible({ timeout: 5_000 });
    const text = await btn.textContent();
    expect(text === "Following" || text === "Unfollow").toBeTruthy();

    // Click to unfollow
    await btn.click();
    // After unfollowing, button reverts to "Follow"
    await expect(btn).toContainText("Follow", { timeout: 5_000 });
    // Verify button text is exactly "Follow" (not "Following" or "Unfollow")
    await expect(btn).not.toContainText("Following");
  });

  test("118.4 Follow button not visible on own profile", async () => {
    await alicePage.goto(`/u/${ALICE_SUB}`);
    // Wait for the page to load fully
    await expect(alicePage.getByRole("tab", { name: "Videos" })).toBeVisible();
    // Follow button should not be present on own profile
    await expect(alicePage.getByTestId("follow-button")).not.toBeVisible();
  });
});

// =============================================================================
// Section 119: Content Loading
// =============================================================================

test.describe("119 - Content Loading", () => {
  test("119.1 Videos tab shows empty state when no videos", async () => {
    // Bob has no videos — view Bob's profile from Alice
    await alicePage.goto(`/u/${BOB_SUB}`);
    await alicePage.getByRole("tab", { name: "Videos" }).click();
    await expect(alicePage.getByTestId("videos-empty")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("No videos yet")).toBeVisible();
  });

  test("119.2 Posts tab shows empty state when no posts", async () => {
    // Clean up any Bob posts from other specs
    try {
      execSync(
        `${PYTHON} -c "
import boto3, os
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))
resp = tbl.query(IndexName='GSI2', KeyConditionExpression=boto3.dynamodb.conditions.Key('GSI2PK').eq('POST_AUTHOR#${BOB_SUB}'))
with tbl.batch_writer() as batch:
    for item in resp.get('Items', []):
        batch.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
"`,
        { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
      );
    } catch { /* ignore */ }

    // Bob has no posts — view Bob's profile from Alice
    await alicePage.goto(`/u/${BOB_SUB}`);
    await alicePage.getByRole("tab", { name: "Posts" }).click();
    await expect(alicePage.getByTestId("posts-empty")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByText("No posts yet")).toBeVisible();
  });

  test("119.3 Posts tab supports filter pills", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    await bobPage.getByRole("tab", { name: "Posts" }).click();
    await expect(bobPage.getByTestId("post-filter-pills")).toBeVisible();
    // Check all filter buttons are present
    await expect(bobPage.getByTestId("filter-all")).toBeVisible();
    await expect(bobPage.getByTestId("filter-image")).toBeVisible();
    await expect(bobPage.getByTestId("filter-video")).toBeVisible();
    await expect(bobPage.getByTestId("filter-text")).toBeVisible();
    // Click Images filter
    await bobPage.getByTestId("filter-image").click();
    // Since all seeded posts are text-only, filtering by image should show empty or no matching posts
    // Wait for the query to settle
    await bobPage.waitForTimeout(1000);
  });

  test("119.4 Public profile API returns creator data with social fields", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_id).toBe(ALICE_SUB);
    expect(typeof data.display_name).toBe("string");
    expect(typeof data.follower_count).toBe("number");
    expect(typeof data.following_count).toBe("number");
    expect(typeof data.post_count).toBe("number");
    expect(typeof data.is_following).toBe("boolean");
    expect(typeof data.has_subscription_plans).toBe("boolean");
    expect(data.has_subscription_plans).toBe(true);
  });
});

// =============================================================================
// Section 120: Unauthenticated View
// =============================================================================

test.describe("120 - Unauthenticated View", () => {
  test("120.1 Unauthenticated user sees Posts and About tabs", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`/u/${ALICE_SUB}`);

    // Posts and About tabs should be visible
    await expect(page.getByRole("tab", { name: "Posts" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("tab", { name: "About" })).toBeVisible();

    await page.close();
    await ctx.close();
  });

  test("120.2 Videos tab hidden for unauthenticated users", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`/u/${ALICE_SUB}`);

    // Wait for page to load
    await expect(page.getByRole("tab", { name: "Posts" })).toBeVisible({ timeout: 10_000 });
    // Videos tab should NOT be visible
    await expect(page.getByRole("tab", { name: "Videos" })).not.toBeVisible();

    await page.close();
    await ctx.close();
  });

  test("120.3 Unauthenticated user sees sign in button", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(`/u/${ALICE_SUB}`);

    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible({ timeout: 10_000 });

    await page.close();
    await ctx.close();
  });
});

// =============================================================================
// Section 121: Stats Row
// =============================================================================

test.describe("121 - Stats Row", () => {
  test("121.1 Stats row shows follower/following/post counts", async () => {
    await bobPage.goto(`/u/${ALICE_SUB}`);
    const statsRow = bobPage.getByTestId("stats-row");
    await expect(statsRow).toBeVisible();
    await expect(statsRow).toContainText("followers");
    await expect(statsRow).toContainText("following");
    await expect(statsRow).toContainText("posts");
  });

  test("121.2 Stats row formats large numbers", async () => {
    // Set Alice's follower count to 1500
    setFollowerCount(ALICE_SUB, 1500);

    // Reload the page to get fresh data
    await bobPage.goto(`/u/${ALICE_SUB}`);
    const statsRow = bobPage.getByTestId("stats-row");
    await expect(statsRow).toBeVisible();
    // 1500 should be formatted as "1.5K"
    await expect(statsRow).toContainText("1.5K");

    // Reset to 42
    setFollowerCount(ALICE_SUB, 42);
  });
});

}); // end Creator Storefront
