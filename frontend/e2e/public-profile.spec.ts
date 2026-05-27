/**
 * E2E tests for SOC-005: Public Profile Page
 *
 * Section 115: Public Profile API (5 tests)
 * Section 116: Profile Posts API (5 tests)
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
const ROOT_KEY = "root";
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

/**
 * Ensure Alice and Bob have user records in the users table (needed for
 * identifier resolution) and profile records in the profiles table.
 */
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

for sub, name in [('${ALICE_SUB}', 'Alice Test'), ('${BOB_SUB}', 'Bob Test')]:
    # Ensure user record
    if not users_tbl.get_item(Key={'user_sub': sub}).get('Item'):
        users_tbl.put_item(Item={'user_sub': sub, 'created_at': int(time.time()) - 86400})

    # Ensure profile record with display_name
    prof = prof_tbl.get_item(Key={'user_sub': sub}).get('Item')
    profile_data = (prof.get('profile') or {}) if prof else {}
    if not profile_data.get('display_name'):
        profile_data['display_name'] = name
        profile_data.setdefault('description', 'E2E test profile')
        profile_data.setdefault('follower_count', 0)
        profile_data.setdefault('following_count', 0)
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

/**
 * Seed published text posts for Alice in the app_single_table.
 * Returns the created post IDs.
 */
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

post_ids = []
base_ts = int(time.time()) - 3600
for i in range(${count}):
    post_id = uuid.uuid4().hex
    created_at = base_ts + i
    tbl.put_item(Item={
        'pk': f'POST#{post_id}',
        'sk': 'META',
        'Entity': 'Post',
        'post_id': post_id,
        'user_id': '${ALICE_SUB}',
        'created_at': created_at,
        'published_at': created_at,
        'status': 'published',
        'visibility': 'public',
        'body': f'E2E public profile test post {i} ts=${TS}',
        'body_format': 'plain',
        'locked': False,
        'like_count': i * 2,
        'comment_count': i,
        'tip_total_cents': 0,
        'GSI2PK': 'POST_AUTHOR#${ALICE_SUB}',
        'GSI2SK': f'{created_at}#POST#{post_id}',
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

/**
 * Clean up any existing follow relationship between Bob and Alice.
 */
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
print('cleaned')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// =============================================================================
// Test setup
// =============================================================================

let bobPage: Page;
let seededPostIds: string[];

test.beforeAll(async ({ browser }) => {
  ensureUsersAndProfiles();
  seededPostIds = seedAlicePosts(3);
  cleanupFollow();

  bobPage = await newIdentityPage(browser, BOB_KEY);
});

test.afterAll(async () => {
  await bobPage?.close();
});

// =============================================================================
// Section 115: Public Profile API
// =============================================================================

test.describe("115 - Public Profile API", () => {
  test("115.1 Get Alice's public profile (authenticated as Bob)", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.user_id).toBe(ALICE_SUB);
    expect(typeof data.display_name).toBe("string");
    expect(data.display_name.length).toBeGreaterThan(0);
    expect(typeof data.follower_count).toBe("number");
    expect(data.follower_count).toBeGreaterThanOrEqual(0);
    expect(typeof data.is_following).toBe("boolean");
    expect(typeof data.is_followed_by).toBe("boolean");
  });

  test("115.2 Profile includes social counts", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.follower_count).toBe("number");
    expect(data.follower_count).toBeGreaterThanOrEqual(0);
    expect(typeof data.following_count).toBe("number");
    expect(data.following_count).toBeGreaterThanOrEqual(0);
    expect(typeof data.post_count).toBe("number");
    expect(data.post_count).toBeGreaterThanOrEqual(0);
  });

  test("115.3 Meta endpoint returns SEO data", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/meta/${ALICE_SUB}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.title).toBe("string");
    expect(data.title.length).toBeGreaterThan(0);
    expect(typeof data.description).toBe("string");
    expect(typeof data.image).toBe("string");
  });

  test("115.4 Non-existent profile returns 404", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/profile/public/nonexistent_user_that_does_not_exist@nowhere.invalid`,
    );
    expect(resp.status()).toBe(404);
  });

  test("115.5 Profile with follow relationship shows is_following", async () => {
    // Ensure clean state
    cleanupFollow();

    // Verify not following
    const before = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}`);
    expect(before.status()).toBe(200);
    const dataBefore = await before.json();
    expect(dataBefore.is_following).toBe(false);

    // Follow Alice
    const followResp = await apiPost(bobPage, BOB_KEY, "/ui/social/follow", {
      target_user_id: ALICE_SUB,
    });
    expect(followResp.status()).toBe(200);

    // Re-fetch profile -- should now show is_following=true
    const after = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}`);
    expect(after.status()).toBe(200);
    const dataAfter = await after.json();
    expect(dataAfter.is_following).toBe(true);

    // Clean up -- unfollow
    const unfollowResp = await apiPost(bobPage, BOB_KEY, "/ui/social/unfollow", {
      target_user_id: ALICE_SUB,
    });
    expect(unfollowResp.status()).toBe(200);
  });
});

// =============================================================================
// Section 116: Profile Posts API
// =============================================================================

test.describe("116 - Profile Posts API", () => {
  test("116.1 Get Alice's public posts", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}/posts`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.items)).toBe(true);
    expect(typeof data.total_count).toBe("number");
  });

  test("116.2 Posts have expected fields", async () => {
    const resp = await apiGet(bobPage, `/ui/profile/public/${ALICE_SUB}/posts`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(1);

    const item = data.items[0];
    expect(typeof item.post_id).toBe("string");
    expect(item.post_id.length).toBeGreaterThan(0);
    // body_preview is string or null
    expect(
      typeof item.body_preview === "string" || item.body_preview === null,
    ).toBe(true);
    expect(typeof item.locked).toBe("boolean");
    expect(typeof item.like_count).toBe("number");
    expect(typeof item.comment_count).toBe("number");
  });

  test("116.3 Filter by type (text)", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/profile/public/${ALICE_SUB}/posts`,
      { filter: "text" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // All seeded posts are text-only (no image_urls, no video_id)
    for (const item of data.items) {
      const hasImages =
        Array.isArray(item.image_urls) && item.image_urls.length > 0;
      const hasVideo = !!item.video_id;
      expect(hasImages).toBe(false);
      expect(hasVideo).toBe(false);
    }
  });

  test("116.4 Pagination with limit", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/profile/public/${ALICE_SUB}/posts`,
      { limit: "1" },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.items.length).toBeLessThanOrEqual(1);
    // With 3+ seeded posts and limit=1 there should be a next_cursor
    if (data.items.length === 1) {
      expect(typeof data.next_cursor).toBe("string");
    }
  });

  test("116.5 Non-existent user posts returns 404", async () => {
    const resp = await apiGet(
      bobPage,
      `/ui/profile/public/nonexistent@nowhere.invalid/posts`,
    );
    expect(resp.status()).toBe(404);
  });
});
