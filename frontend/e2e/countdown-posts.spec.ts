/**
 * FEED-005: Countdown Newsfeed Posts E2E tests.
 *
 * Section 701: Countdown Post Creation API
 * Section 702: Countdown Post in Feed + Interactions API
 * Section 703: Countdown Post Rendering (UI)
 * Section 704: Countdown Post Pre/Post-Zero State (UI)
 * Section 705: Countdown Post Composer (UI)
 *
 * Repo gotcha: GET /feed queries GSI1PK = FEED#{viewer_user_id} and only
 * returns the viewer's OWN posts (no fan-out). To assert a created post is
 * present we fetch the AUTHOR's own feed, or GET /posts/{post_id}.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const PYTHON = "python3";

const TS = Date.now();
const nowSec = () => Math.floor(Date.now() / 1000);

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** POST helper that includes session cookies and CSRF header. */
async function feedPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function feedGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** Seed a default payment method for tip tests. */
function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
tbl.put_item(Item={'pk': pk, 'sk': 'PM#${pmId}', 'payment_method_id': '${pmId}', 'brand': 'visa', 'last4': '4242', 'exp_month': 12, 'exp_year': 2099, 'is_default': True, 'priority': 0, 'created_at': int(time.time())})
tbl.put_item(Item={'pk': pk, 'sk': 'BILLING', 'autopay_enabled': False, 'currency': 'usd', 'default_payment_method_id': '${pmId}'})
print('injected')
"`,
    { timeout: 10_000 },
  );
}

/** Backdate a post's target_datetime directly in DynamoDB to force the expired state. */
function backdateTarget(postId: string, targetSec: number): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('APP_TABLE', 'app_single_table'))
tbl.update_item(Key={'pk': 'POST#${postId}', 'sk': 'META'}, UpdateExpression='SET target_datetime = :t', ExpressionAttributeValues={':t': ${targetSec}})
print('backdated')
"`,
    { timeout: 10_000 },
  );
}

// ─── Section 701: Countdown Post Creation API ─────────────────────────────────

test.describe("701 — Countdown Post Creation API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("701.1 — create countdown post with valid params", async () => {
    const title = `Premiere ${TS}`;
    const target = nowSec() + 7200;
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: target,
      associated_event_type: "broadcast",
      associated_event_id: `bcast_${TS}`,
      body: `Get ready ${TS}`,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.post_kind).toBe("countdown");
    expect(data.countdown_title).toBe(title);
    expect(data.target_datetime).toBe(target);
    expect(data.associated_event_type).toBe("broadcast");
    expect(data.associated_event_id).toBe(`bcast_${TS}`);
  });

  test("701.2 — countdown post carries body text", async () => {
    const title = `WithBody ${TS}`;
    const body = `Body text ${TS}`;
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: nowSec() + 3600,
      associated_event_type: "custom",
      body,
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.countdown_title).toBe(title);
    expect(data.body).toContain(body);
  });

  test("701.3 — reject countdown with past target_datetime (400)", async () => {
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: `Past ${TS}`,
      target_datetime: nowSec() - 3600,
    });
    expect(resp.status()).toBe(400);
  });

  test("701.4 — reject broadcast countdown without event id (400)", async () => {
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: `NoEvt ${TS}`,
      target_datetime: nowSec() + 3600,
      associated_event_type: "broadcast",
    });
    expect(resp.status()).toBe(400);
  });

  test("701.5 — reject countdown without title (400)", async () => {
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      target_datetime: nowSec() + 3600,
    });
    expect(resp.status()).toBe(400);
  });

  test("701.6 — unauthenticated create rejected", async ({ browser }) => {
    const ctx = await browser.newContext();
    const anonPage = await ctx.newPage();
    const resp = await anonPage.request.post(`${API}/posts`, {
      data: {
        post_kind: "countdown",
        countdown_title: `Anon ${TS}`,
        target_datetime: nowSec() + 3600,
      },
    });
    expect(resp.status()).toBeGreaterThanOrEqual(401);
    expect(resp.status()).toBeLessThan(500);
    await ctx.close();
  });
});

// ─── Section 702: Countdown Post in Feed + Interactions API ────────────────────

test.describe("702 — Countdown Post in Feed + Interactions API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let postId: string;
  const title = `FeedCountdown ${TS}`;
  const target = nowSec() + 86400 * 2;
  const TIP_PM_ID = `pm_cd_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    injectPaymentMethod(BOB_ID, TIP_PM_ID);

    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: target,
      associated_event_type: "custom",
      body: `Feed body ${TS}`,
    });
    expect(resp.ok()).toBeTruthy();
    postId = (await resp.json()).post_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("702.1 — countdown post appears in author's own feed with all fields", async () => {
    const resp = await feedGet(alicePage, "/feed?limit=50");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const items = data.items ?? data;
    const found = items.find((p: { post_id: string }) => p.post_id === postId);
    expect(found).toBeTruthy();
    expect(found.post_kind).toBe("countdown");
    expect(found.countdown_title).toBe(title);
    expect(found.target_datetime).toBe(target);
    expect(found.associated_event_type).toBe("custom");
  });

  test("702.2 — GET /posts/{id} returns countdown fields", async () => {
    const resp = await feedGet(alicePage, `/posts/${postId}`);
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.post_kind).toBe("countdown");
    expect(data.countdown_title).toBe(title);
    expect(data.target_datetime).toBe(target);
  });

  test("702.3 — like + react + comment work on countdown post", async () => {
    const likeResp = await feedPost(bobPage, `/posts/${postId}/like`, {}, BOB_ID);
    expect(likeResp.ok()).toBeTruthy();

    const reactResp = await feedPost(bobPage, `/posts/${postId}/reactions`, { emoji: "fire" }, BOB_ID);
    expect(reactResp.ok()).toBeTruthy();

    const commentResp = await feedPost(
      bobPage,
      `/posts/${postId}/comments`,
      { body: `Excited ${TS}` },
      BOB_ID,
    );
    expect(commentResp.ok()).toBeTruthy();

    const detail = await feedGet(alicePage, `/posts/${postId}`);
    const data = await detail.json();
    expect(data.like_count).toBeGreaterThanOrEqual(1);
    expect(data.comment_count).toBeGreaterThanOrEqual(1);
  });
});

// ─── Section 703: Countdown Post Rendering (UI) ───────────────────────────────

test.describe("703 — Countdown Post Rendering (UI)", () => {
  let alicePage: Page;
  let postId: string;
  const title = `RenderCountdown ${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: nowSec() + 86400 * 3,
      associated_event_type: "custom",
    });
    expect(resp.ok()).toBeTruthy();
    postId = (await resp.json()).post_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("703.1 — countdown card renders with title + ticking timer", async () => {
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const card = alicePage.locator('[data-testid="countdown-card"]').first();
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(
      alicePage.locator('[data-testid="countdown-title"]').filter({ hasText: title }).first(),
    ).toBeVisible();
    await expect(card.locator('[data-testid="countdown-timer"]').first()).toBeVisible();
  });

  test("703.2 — custom countdown shows no event CTA button", async () => {
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const titleEl = alicePage
      .locator('[data-testid="countdown-title"]')
      .filter({ hasText: title })
      .first();
    await expect(titleEl).toBeVisible({ timeout: 15_000 });
    const card = titleEl.locator(
      'xpath=ancestor::*[@data-testid="countdown-card"]',
    );
    await expect(card.locator('[data-testid="countdown-cta"]')).toHaveCount(0);
  });
});

// ─── Section 704: Countdown Post Pre/Post-Zero State (UI) ──────────────────────

test.describe("704 — Countdown Post Pre/Post-Zero State (UI)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("704.1 — future target shows ticking timer (pre-zero)", async () => {
    const title = `PreZero ${TS}`;
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: nowSec() + 86400,
      associated_event_type: "custom",
    });
    expect(resp.ok()).toBeTruthy();
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const titleEl = alicePage
      .locator('[data-testid="countdown-title"]')
      .filter({ hasText: title })
      .first();
    await expect(titleEl).toBeVisible({ timeout: 15_000 });
    const card = titleEl.locator('xpath=ancestor::*[@data-testid="countdown-card"]');
    await expect(card).toHaveAttribute("data-expired", "false");
    await expect(card.locator('[data-testid="countdown-timer"]')).toBeVisible();
  });

  test("704.2 — backdated target shows expired state (post-zero)", async () => {
    const title = `PostZero ${TS}`;
    // create with a valid future target, then backdate it in DDB.
    const resp = await feedPost(alicePage, "/posts", {
      post_kind: "countdown",
      countdown_title: title,
      target_datetime: nowSec() + 3600,
      associated_event_type: "broadcast",
      associated_event_id: `bcast_pz_${TS}`,
    });
    expect(resp.ok()).toBeTruthy();
    const postId = (await resp.json()).post_id;
    backdateTarget(postId, nowSec() - 60);

    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const titleEl = alicePage
      .locator('[data-testid="countdown-title"]')
      .filter({ hasText: title })
      .first();
    await expect(titleEl).toBeVisible({ timeout: 15_000 });
    const card = titleEl.locator('xpath=ancestor::*[@data-testid="countdown-card"]');
    await expect(card).toHaveAttribute("data-expired", "true");
    await expect(card.locator('[data-testid="countdown-expired"]')).toBeVisible();
    // expired broadcast countdown reveals its "Watch Live" CTA
    await expect(card.locator('[data-testid="countdown-cta"]')).toBeVisible();
  });
});

// ─── Section 705: Countdown Post Composer (UI) ────────────────────────────────

test.describe("705 — Countdown Post Composer (UI)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("705.1 — countdown toggle opens + closes composer; event id field is conditional", async () => {
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const toggle = alicePage.locator('[data-testid="countdown-toggle-btn"]').first();
    await expect(toggle).toBeVisible({ timeout: 15_000 });

    await toggle.click();
    const composer = alicePage.locator('[data-testid="countdown-composer"]').first();
    await expect(composer).toBeVisible();
    await expect(composer.locator('[data-testid="countdown-title-input"]')).toBeVisible();
    await expect(composer.locator('[data-testid="countdown-target-input"]')).toBeVisible();

    // custom (default) → no event id field
    await expect(composer.locator('[data-testid="countdown-event-id"]')).toHaveCount(0);
    // broadcast → event id field appears
    await composer.locator('[data-testid="countdown-event-type"]').selectOption("broadcast");
    await expect(composer.locator('[data-testid="countdown-event-id"]')).toBeVisible();
    // back to custom → field hidden again
    await composer.locator('[data-testid="countdown-event-type"]').selectOption("custom");
    await expect(composer.locator('[data-testid="countdown-event-id"]')).toHaveCount(0);

    // toggle off dismisses the composer
    await toggle.click();
    await expect(alicePage.locator('[data-testid="countdown-composer"]')).toHaveCount(0);
  });
});
