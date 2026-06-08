/**
 * VIDEO SEGMENT 07 — Subscriptions & Monetization  (~2 min)
 *
 * A guided tour of the creator-economy money loop:
 *   - Subscription plans browser (price · interval · subscribe)
 *   - Subscribing to a creator, then seeing the live "active" subscription state
 *   - The creator earnings dashboard (balance cards + earnings breakdown chart,
 *     including subscription revenue)
 *   - Requesting a payout against the available balance
 *   - An admin (root) approving that payout in the built-in Admin Queue
 *
 * Pattern mirrors seg06-groups.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Every feature shown is brought on-screen
 * and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (all sessions seeded by e2e_admin_session_setup.py):
 *   - Alice  — the creator on camera. We seed her billing-ledger CREDIT entries
 *              (subscription revenue + tips + unlocks, all past the 7-day hold so
 *              they count as *available* balance) + a payout method, so the
 *              earnings dashboard and payout balance are non-zero and real.
 *   - Bob    — a second creator with one active subscription plan, so Alice has a
 *              real plan to browse and subscribe to on camera.
 *   - root   — the platform admin who approves Alice's payout.
 *
 * Seeding notes:
 *   - Earnings + payout balance come from the `billing` table LEDGER#... CREDIT
 *     rows (read by /ui/earnings/summary + /ui/payouts/balance). The earnings
 *     classifier buckets a row by its `reason`: "subscription"→subscriptions,
 *     "tip"→tips, "unlock"→unlocks. We seed all three so the breakdown chart has
 *     multiple bars (with a healthy subscriptions slice).
 *   - Bob's plan is created via the public/X-User-Id subscription API.
 *   - The PayoutDashboard has a built-in "Admin Queue" tab that renders only when
 *     the access token's role is admin/root — so beat 6 just re-opens /payouts as
 *     root and approves from that tab (no separate admin route needed).
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg07-monetization.demo.ts
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

/** Run a small inline python snippet against the local DDB (sources .env.local). */
function ddbPy(body: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
${body}
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 20_000 },
  );
}

/** Ensure the CreatorPayouts table exists (with the GSIs the payout service needs). */
function ensurePayoutsTable(): void {
  ddbPy(`
import time
try:
    ddb.meta.client.describe_table(TableName='CreatorPayouts')
except Exception:
    ddb.create_table(
        TableName='CreatorPayouts',
        AttributeDefinitions=[
            {'AttributeName': 'payout_id', 'AttributeType': 'S'},
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'created_at', 'AttributeType': 'N'},
            {'AttributeName': 'status', 'AttributeType': 'S'},
        ],
        KeySchema=[{'AttributeName': 'payout_id', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[
            {'IndexName': 'ByUserCreatedAt', 'KeySchema': [
                {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'ByStatusCreatedAt', 'KeySchema': [
                {'AttributeName': 'status', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
        ],
    )
    time.sleep(2)
`);
}

/** Cancel all active payouts + drop the per-user sentinel so a fresh request works. */
function cleanupActivePayouts(userSub: string): void {
  ddbPy(`
import boto3.dynamodb.conditions as C
tbl = ddb.Table('CreatorPayouts')
active = {}
try:
    resp = tbl.query(IndexName='ByUserCreatedAt', KeyConditionExpression=C.Key('user_id').eq('${userSub}'))
    for it in resp.get('Items', []):
        if it.get('status') in ('requested','approved','processing'):
            active[it['payout_id']] = it
except Exception:
    pass
sk = {'FilterExpression': C.Attr('user_id').eq('${userSub}') & C.Attr('status').is_in(['requested','approved','processing'])}
while True:
    s = tbl.scan(**sk)
    for it in s.get('Items', []):
        active[it['payout_id']] = it
    lek = s.get('LastEvaluatedKey')
    if not lek: break
    sk['ExclusiveStartKey'] = lek
for pid in active:
    tbl.update_item(Key={'payout_id': pid}, UpdateExpression='SET #s=:s',
                    ExpressionAttributeNames={'#s':'status'}, ExpressionAttributeValues={':s':'cancelled'})
tbl.delete_item(Key={'payout_id': 'PAYOUT_STATE#${userSub}'})
`);
}

/**
 * Seed CREDIT ledger entries for the creator, past the 7-day hold so they count
 * as *available* balance. `reason` drives the earnings classifier so we get a
 * multi-category breakdown chart (subscriptions / tips / unlocks).
 */
function seedEarnings(userSub: string): number {
  // Reason drives the earnings classifier: subscription→subscriptions,
  // tip→tips, unlock→unlocks. Built inside Python (single-quoted) to avoid
  // double-quote collisions with the shell ``-c "..."`` wrapper.
  // $120 subscriptions + $80 tips + $45 unlocks = $245 available.
  ddbPy(`
import uuid, time
import boto3.dynamodb.conditions as C
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
# Idempotent: clear any prior seg07 seed rows so the breakdown totals stay clean
# across re-records (each run seeds a fixed set; we don't want them to stack).
resp = tbl.query(KeyConditionExpression=C.Key('pk').eq(pk) & C.Key('sk').begins_with('LEDGER#'))
for it in resp.get('Items', []):
    if (it.get('meta') or {}).get('content_id') == 'seg07_seed':
        tbl.delete_item(Key={'pk': pk, 'sk': it['sk']})
base = int(time.time()) - 700000  # ~8 days ago, past 7-day hold -> available
# NOTE: the classifier checks meta.content_type FIRST (message/post/comment -> tips),
# so only the tips rows carry that meta. Subscription/unlock rows rely on 'reason'.
rows = [
    (6, 2000, 'Subscription: monthly plan', 'subscription'),
    (8, 1000, 'Tip: message',               'message'),
    (3, 1500, 'Unlock: locked post',        'unlock'),
]
i = 0
for count, cents, reason, ctype in rows:
    for _ in range(count):
        eid = uuid.uuid4().hex
        ts = base + i
        i += 1
        tbl.put_item(Item={
            'pk': pk, 'sk': 'LEDGER#' + str(ts) + '#' + eid, 'entry_id': eid, 'ts': ts,
            'type': 'credit', 'amount_cents': cents, 'currency': 'USD',
            'state': 'settled', 'reason': reason,
            'meta': {'content_type': ctype, 'content_id': 'seg07_seed'},
        })
`);
  return 12000 + 8000 + 4500;
}

/** Give the creator a saved payout destination so the request form has a target. */
function seedPayoutMethod(userSub: string): void {
  ddbPy(`
import uuid, time
# Payout methods live on CreatorPayouts tagged record_kind='payout_method',
# keyed by payout_id==method_id, and read via the ByUserCreatedAt GSI.
tbl = ddb.Table('CreatorPayouts')
mid = 'pmth_' + uuid.uuid4().hex
now = int(time.time())
tbl.put_item(Item={
    'payout_id': mid, 'method_id': mid, 'user_id': '${userSub}',
    'record_kind': 'payout_method', 'method_type': 'bank_ach',
    'account_last4': '4242', 'routing_last4': '1234',
    'nickname': 'Main checking', 'is_default': True,
    'created_at': now, 'updated_at': now,
})
`);
}

test("Segment 07 — Subscriptions & Monetization", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions["alice"].user_sub;
  const bobSub = sessions["bob"].user_sub;

  // ── Seed (off camera, before any UI is shown) ──────────────────────────────
  ensurePayoutsTable();
  cleanupActivePayouts(aliceSub);
  seedEarnings(aliceSub);
  seedPayoutMethod(aliceSub);

  // Bob creates an active subscription plan (subscription API uses X-User-Id).
  await page.request.post(`${API}/api/creators/${bobSub}/plans`, {
    data: {
      name: "Studio Supporter",
      description: "Monthly support — early drops, behind-the-scenes, and member chat.",
      price_cents: 999,
      currency: "USD",
      interval: "month",
    },
    headers: { "X-User-Id": bobSub },
  });

  // ── Auth as Alice (creator on camera) + load the shell ─────────────────────
  await injectAuth(page, "alice");
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ───────────────────────────────────────────────────────────────
  await titleCard(
    page,
    7,
    "Subscriptions & Monetization",
    "Plans · subscribe · creator earnings · payouts",
  );

  // ── 2. Subscription plans browser ──────────────────────────────────────────
  await page.goto(`${BASE}/subscriptions`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByRole("heading", { name: "Subscriptions", exact: true }),
    "Subscriptions",
    "Browse a creator's plans and manage your own subscriptions in one place",
    { ms: 4500 },
  );

  // Open Browse Plans and pull up Bob's plan.
  await page.getByRole("tab", { name: /browse plans/i }).click().catch(() => {});
  await page.waitForTimeout(800);
  await page.getByPlaceholder(/enter creator id/i).fill(bobSub);
  await page.waitForTimeout(1600); // let the public plans query resolve

  await reveal(
    page,
    page.getByText("Studio Supporter").first(),
    "Subscription plans",
    "Each plan shows its name, price, and billing interval",
    { ms: 5000 },
  );
  await reveal(
    page,
    page.getByText("$9.99").first(),
    "Transparent pricing",
    "A clear monthly price — and any perks the creator includes",
    { ms: 5000 },
  );

  // ── 3. Subscribe → active subscription state ───────────────────────────────
  await reveal(
    page,
    page.getByRole("button", { name: /^subscribe$/i }).first(),
    "One tap to subscribe",
    "Subscribing starts billing and unlocks the creator's members-only content",
    { ms: 4000 },
  );
  await page.getByRole("button", { name: /^subscribe$/i }).first().click().catch(() => {});
  await page.waitForTimeout(2000); // wait for the subscribe mutation + toast

  // Switch to "My Subscriptions" to show the now-active subscription.
  await page.getByRole("tab", { name: /my subscriptions/i }).click().catch(() => {});
  await page.waitForTimeout(2500);
  // The card title is the plan id (the list payload doesn't join the plan name),
  // so anchor the beats on the always-present price + the "active" status badge.
  await reveal(
    page,
    page.locator("p, span, div").filter({ hasText: /^\$9\.99$/ }).first(),
    "Your active subscription",
    "It appears instantly under My Subscriptions with full billing details",
    { ms: 5000 },
  );
  await reveal(
    page,
    page.getByText("active", { exact: true }).first(),
    "Active status",
    "Status, renewal date, and invoices are all tracked for you",
    { ms: 5000 },
  );

  // ── 4. Creator earnings dashboard ──────────────────────────────────────────
  await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Payouts" }).waitFor({ timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(1800);

  await reveal(
    page,
    page.getByTestId("total-earned"),
    "Creator earnings",
    "Lifetime earnings across every revenue stream on the platform",
    { ms: 5000 },
  );
  await reveal(
    page,
    page.getByTestId("available-balance"),
    "Available balance",
    "Earnings past the hold period are ready to withdraw",
    { ms: 5000 },
  );

  // Earnings breakdown chart — including subscription revenue.
  await reveal(
    page,
    page.getByText("Earnings Breakdown").first(),
    "Earnings breakdown",
    "See exactly where the money comes from",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByText("Subscriptions").first(),
    "Subscription revenue",
    "Subscriptions, tips, and unlocks each get their own share of the chart",
    { ms: 5500 },
  );

  // ── 5. Request a payout ────────────────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Request Payout").first(),
    "Request a payout",
    "Withdraw available earnings to a saved destination",
    { ms: 4000 },
  );
  // Fill the amount (well under the available balance, over the $10 minimum).
  await page.locator("#payout-amount").scrollIntoViewIfNeeded().catch(() => {});
  await page.locator("#payout-amount").fill("50.00");
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.locator("#payout-amount"),
    "Choose an amount",
    "Pick how much to withdraw — the form validates it against your balance",
    { ms: 3500, ring: false },
  );
  await page.getByRole("button", { name: "Request Payout" }).click().catch(() => {});
  // Wait for the request to land + the history table to refetch.
  await expect(page.getByTestId("status-requested").first())
    .toBeVisible({ timeout: 12_000 })
    .catch(() => {});
  await page.waitForTimeout(1000);

  await reveal(
    page,
    page.getByText("Payout History").first(),
    "Payout submitted",
    "The request lands in your history as 'requested', awaiting review",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByTestId("status-requested").first(),
    "Awaiting approval",
    "Every payout is reviewed by the platform before it's paid out",
    { ms: 5000 },
  );

  // ── 6. Admin approves the payout (root) ────────────────────────────────────
  await caption(page, "Switching to the platform admin", "Payouts are reviewed before they're paid");
  await beat(page, 1800);

  // Re-auth the SAME context as root (admin-role token → Admin Queue tab renders).
  const root = sessions["root"];
  await page.context().clearCookies();
  await page.context().addCookies(root.cookies);
  await page.addInitScript(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: root.user_sub, token: root.access_token },
  );
  await page.goto(`${BASE}/payouts`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);

  // Open the Admin Queue tab.
  await page.getByRole("tab", { name: /admin queue/i }).click().catch(() => {});
  await page.waitForTimeout(1800);

  await reveal(
    page,
    page.getByText("Payout Queue").first(),
    "Admin payout queue",
    "Admins see every pending payout across all creators",
    { ms: 5000 },
  );
  // The newest 'requested' row is Alice's request.
  await reveal(
    page,
    page.getByTestId("admin-payout-row").first(),
    "The pending request",
    "Alice's $50 withdrawal is waiting for a decision",
    { ms: 4500 },
  );

  // Approve it.
  await reveal(
    page,
    page.getByTestId("approve-btn").first(),
    "One click to approve",
    "Approving releases the funds to the creator",
    { ms: 3500, ring: false },
  );
  await page.getByTestId("approve-btn").first().click().catch(() => {});
  await page.waitForTimeout(2200); // approve mutation + queue refetch (now 'approved')

  // Switch the queue filter to "Approved" to show the new status.
  await page.getByTestId("admin-status-filter").click().catch(() => {});
  await page.waitForTimeout(600);
  await page.getByRole("option", { name: "Approved" }).click().catch(() => {});
  await page.waitForTimeout(1800);

  await reveal(
    page,
    page.getByText("approved", { exact: true }).first(),
    "Approved",
    "Status flips to 'approved' — the payout is on its way",
    { ms: 5000 },
  );

  // ── 7. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Monetization ✓", "Next: Shop");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
