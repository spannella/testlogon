import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import path from "path";

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";

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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const root = path.resolve(process.cwd(), "..");
    const raw = execSync(`python3 ${path.join(root, "e2e_session_setup.py")}`, {
      cwd: root,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

function upsertPaymentMethod(userSub: string, pmId: string): void {
  const root = path.resolve(process.cwd(), "..");
  execSync(
    `python3 -c "
import boto3, os, time
from pathlib import Path
env_file = Path('${path.join(root, ".env.local")}')
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
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = '${pmId}'
tbl.put_item(Item={
    'pk': pk, 'sk': 'PM#' + pm_id, 'payment_method_id': pm_id,
    'provider': 'stripe', 'provider_method_id': pm_id, 'method_type': 'card',
    'label': 'Test Card ****4242', 'brand': 'visa', 'last4': '4242',
    'exp_month': 12, 'exp_year': 2099, 'is_default': True, 'priority': 0, 'created_at': int(time.time()),
})
tbl.put_item(Item={
    'pk': pk, 'sk': 'BILLING', 'autopay_enabled': False, 'currency': 'usd', 'default_payment_method_id': pm_id,
})
print('ok')
"`,
    { cwd: root, timeout: 10_000 },
  );
}

function removePaymentMethod(userSub: string, pmId: string): void {
  const root = path.resolve(process.cwd(), "..");
  try {
    execSync(
      `python3 -c "
import boto3, os
from pathlib import Path
env_file = Path('${path.join(root, ".env.local")}')
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
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
tbl.delete_item(Key={'pk': pk, 'sk': 'PM#${pmId}'})
tbl.delete_item(Key={'pk': pk, 'sk': 'BILLING'})
print('ok')
"`,
      { cwd: root, timeout: 10_000 },
    );
  } catch {
    // best-effort cleanup
  }
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function gotoFeed(page: Page, userId: string) {
  await injectAuth(page, userId);
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.locator('a[href="/feed"]').first().click();
  await page.waitForTimeout(1200);
}

async function apiPost(page: Page, userId: string, pathSuffix: string, payload: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${pathSuffix}`, {
    data: payload,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, pathSuffix: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${pathSuffix}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

test.describe("feed unlock-limit capped journey", () => {
  test("first N unlocks succeed, N+1 rejected, sold-out visible in UI", async ({ browser }) => {
    const authorPage = await browser.newPage();
    const bobPage = await browser.newPage();
    const charliePage = await browser.newPage();

    const postBody = `e2e unlock cap ${Date.now()}`;
    const unlockLimit = 1;
    const bobPm = `pm_bob_${Date.now()}`;
    const charliePm = `pm_charlie_${Date.now()}`;
    let postId = "";

    try {
      upsertPaymentMethod(BOB_ID, bobPm);
      upsertPaymentMethod(CHARLIE_ID, charliePm);

      await injectAuth(authorPage, ALICE_ID);
      const createResp = await apiPost(authorPage, ALICE_ID, "/posts", {
        body: postBody,
        unlock_price_cents: 125,
        unlock_limit: unlockLimit,
      });
      expect(createResp.ok()).toBeTruthy();
      const created = await createResp.json();
      postId = created.post_id as string;

      await injectAuth(bobPage, BOB_ID);
      const bobUnlock = await apiPost(bobPage, BOB_ID, "/posts/unlock", {
        post_id: postId,
        payment_method_id: bobPm,
      });
      expect(bobUnlock.ok()).toBeTruthy();

      await injectAuth(charliePage, CHARLIE_ID);
      const overCapUnlock = await apiPost(charliePage, CHARLIE_ID, "/posts/unlock", {
        post_id: postId,
        payment_method_id: charliePm,
      });
      expect(overCapUnlock.status()).toBe(409);
      const overCapBody = await overCapUnlock.json();
      expect(overCapBody?.detail?.code).toBe("unlock_limit_reached");

      await gotoFeed(authorPage, ALICE_ID);
      const soldOutCard = authorPage.locator("article, div").filter({ hasText: postBody }).first();
      await expect(soldOutCard).toContainText("Unlocks 1/1");
      await expect(soldOutCard).toContainText("Sold out");
    } finally {
      if (postId) {
        await apiDelete(authorPage, ALICE_ID, `/posts/${postId}`);
      }
      removePaymentMethod(BOB_ID, bobPm);
      removePaymentMethod(CHARLIE_ID, charliePm);
      await authorPage.close();
      await bobPage.close();
      await charliePage.close();
    }
  });
});
