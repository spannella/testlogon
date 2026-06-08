/**
 * VIDEO SEGMENT 13 — Ads Platform  (~110-145s)
 *
 * A guided tour of the platform's self-serve advertising stack:
 *   - Advertiser dashboard (/ads/dashboard): an advertiser account with its
 *     status (active) + balance / lifetime spend
 *   - Campaign manager (/ads/campaigns?account=…): a live campaign with budget
 *     and status
 *   - Creative manager (/ads/creatives?campaign=…): an uploaded image creative
 *     (real magic-byte PNG) + its approved status, plus the rendered preview
 *   - Targeting editor (/ads/targeting): an audience targeting set — demographics,
 *     geography, devices — with a live audience-size estimate
 *   - Broadcast pre-roll ad (/live/{sid}): the in-stream pre-roll ad overlay a
 *     non-subscribing viewer sees when joining a live broadcast
 *   - Ad analytics (/ads/analytics?account_id=…): impressions, clicks, CTR,
 *     spend, CPA — the figures that drive ROAS
 *   - Admin Ad Platform dashboard (/admin/ad-platform): the ROOT-only Emergency
 *     Controls tab + the platform-wide ad kill-switch status badge
 *
 * Pattern mirrors seg12-kyc.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py):
 *   - alice — the advertiser (owns the account / campaign / creative / targeting)
 *   - bob   — a non-subscribing viewer (sees the broadcast pre-roll ad)
 *   - root  — platform admin (broadcast session owner + kill-switch operator)
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - alice's existing ad accounts are wiped (GAP-0039 caps a user at 5) then a
 *     fresh advertiser account is created via the API and admin-approved by root.
 *   - One campaign (admin-approved → active), one image creative with a real-PNG
 *     asset uploaded (GAP-0040 magic-byte gate) and admin-approved, and one
 *     targeting set are created via the API.
 *   - Daily analytics rollup rows are seeded directly into DynamoDB so the
 *     analytics dashboard KPI cards populate.
 *   - A root-owned broadcast session with pre-roll enabled is created + started
 *     so bob's viewer join serves the pre-roll overlay.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg13-ads.demo.ts
 */
import { test, expect, type APIResponse, type Page } from "@playwright/test";
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
  type SessionData,
} from "./_demo";

const ALICE = "alice";
const BOB = "bob";
const ROOT = "root";

const STAMP = Date.now();

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated request from the page's browser context as identity `sess`. */
function reqs(page: Page, sess: SessionData) {
  return {
    post: (path: string, body?: unknown) =>
      page.request.post(`${API}${path}`, {
        headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
        data: body ?? {},
      }),
    patch: (path: string, body: unknown) =>
      page.request.patch(`${API}${path}`, {
        headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
        data: body,
      }),
    get: (path: string) => page.request.get(`${API}${path}`),
  };
}

/** Wipe alice's accumulated ad accounts so the GAP-0039 5-account cap never blocks
 *  the fresh create below. Same DDB pattern the ads specs use. */
function ddbWipeAliceAccounts(): void {
  const script = `
import boto3, os
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
from boto3.dynamodb.conditions import Key
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
accts = ddb.Table('AdAccounts')
camps = ddb.Table('AdCampaigns')
for owner in ['e2e_alice@test.local']:
    resp = accts.query(IndexName='ByOwner', KeyConditionExpression=Key('owner_sub').eq(owner))
    for item in resp.get('Items', []):
        acct_pk = item['pk']
        cresp = camps.query(KeyConditionExpression=Key('pk').eq(acct_pk))
        for c in cresp.get('Items', []):
            camps.delete_item(Key={'pk': c['pk'], 'sk': c['sk']})
        accts.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('ok')
`;
  execSync("python3 -", { cwd: "/home/ubuntu/testlogon", timeout: 20_000, input: script });
}

/** Seed daily analytics rollup rows for the demo campaign/account so the analytics
 *  dashboard KPI cards (impressions/clicks/CTR/spend/CPA) + ROAS are populated. */
function seedAnalytics(accountId: string, campaignId: string, creativeId: string): void {
  const script = `
import boto3, os, datetime
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('DDB_AD_ANALYTICS_ROLLUPS','AdAnalyticsRollups'))
acct = "${accountId}"
camp = "${campaignId}"
cr = "${creativeId}"
today = datetime.datetime.now(datetime.timezone.utc).date()
# Seed 10 days of daily rollups with a gentle upward trend.
for i in range(10):
    d = (today - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
    impressions = 8200 + i * 140
    clicks = 240 + i * 6
    spend = 31500 + i * 520  # cents
    tbl.put_item(Item={
        'pk': f'CAMP#{camp}',
        'sk': f'ROLLUP#daily#{d}',
        'campaign_id': camp,
        'account_id': acct,
        'period': 'daily',
        'date': d,
        'impressions': impressions,
        'clicks': clicks,
        'skips': 30,
        'completes': int(impressions * 0.62),
        'spend_cents': spend,
        'revenue_cents': int(spend * 2.1),
        'unique_users': int(impressions * 0.8),
        'by_creative': {cr: {'impressions': impressions, 'clicks': clicks, 'spend_cents': spend}},
        'by_surface': {'feed/banner': {'impressions': impressions, 'clicks': clicks, 'spend_cents': spend}},
        'by_targeting': {'US': {'impressions': impressions, 'clicks': clicks, 'spend_cents': spend}},
        'computed_at': 0,
    })
print('seeded_analytics')
`;
  execSync("python3 -", { cwd: "/home/ubuntu/testlogon", timeout: 30_000, input: script });
}

test("Segment 13 — Ads Platform", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];
  const bob: SessionData = sessions[BOB];
  const root: SessionData = sessions[ROOT];

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  ddbWipeAliceAccounts();

  await injectAuth(page, ALICE);
  const a = reqs(page, alice);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

  // 1. Advertiser account → admin-approve.
  const acct = await jsonOk(
    (await a.post("/ui/ads/accounts", {
      company_name: `Lumina Studios`,
      billing_email: `ads_${STAMP}@lumina.test`,
    })) as APIResponse,
    "create account",
  );
  const accountId: string = acct.account_id;

  await injectAuth(page, ROOT);
  const r = reqs(page, root);
  await jsonOk(
    (await r.post(`/ui/admin/ads/accounts/${accountId}/review`, {
      decision: "approve",
      notes: "Verified advertiser",
    })) as APIResponse,
    "approve account",
  );

  // 2. Campaign → submit → admin-approve (→ active).
  await injectAuth(page, ALICE);
  const camp = await jsonOk(
    (await a.post(`/ui/ads/accounts/${accountId}/campaigns`, {
      name: `Summer Launch`,
      objective: "awareness",
      budget_cents: 50000,
      budget_type: "daily",
    })) as APIResponse,
    "create campaign",
  );
  const campaignId: string = camp.campaign_id;
  await a.post(`/ui/ads/accounts/${accountId}/campaigns/${campaignId}/submit`);
  await injectAuth(page, ROOT);
  await jsonOk(
    (await r.post(`/ui/admin/ads/campaigns/${campaignId}/review`, {
      decision: "approve",
      notes: "Campaign approved",
    })) as APIResponse,
    "approve campaign",
  );

  // 3. Image creative → upload a real-PNG asset (GAP-0040 magic-byte gate) →
  //    submit → admin-approve.
  await injectAuth(page, ALICE);
  const cr = await jsonOk(
    (await a.post(`/ui/ads/campaigns/${campaignId}/creatives`, {
      format: "image",
      title: `Hero Banner`,
      alt_text: "Summer launch hero banner",
      width: 1200,
      height: 628,
      rotation_weight: 80,
    })) as APIResponse,
    "create creative",
  );
  const creativeId: string = cr.creative_id;

  // A real, renderable 8x8 solid-blue PNG (valid signature + IHDR/IDAT/IEND), so
  // the magic-byte sniff (GAP-0040) passes AND the preview shows an actual image.
  const fakePng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEUlEQVR42mOwybuDFTEMLQkA8PNhgWhW5PYAAAAASUVORK5CYII=",
    "base64",
  );
  const upResp = await page.request.post(
    `${API}/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/upload`,
    {
      headers: { "x-csrf-token": alice.csrf_token },
      multipart: {
        file: { name: "hero.png", mimeType: "image/png", buffer: fakePng },
        asset_type: "image",
      },
    },
  );
  await jsonOk(upResp as APIResponse, "upload creative asset");
  await a.post(`/ui/ads/campaigns/${campaignId}/creatives/${creativeId}/submit`);
  await injectAuth(page, ROOT);
  await jsonOk(
    (await r.post(`/ui/admin/ads/creatives/${creativeId}/review`, {
      decision: "approve",
      notes: "Meets content policy",
    })) as APIResponse,
    "approve creative",
  );

  // 4. Targeting set.
  await injectAuth(page, ALICE);
  await jsonOk(
    (await a.post(`/ui/ads/campaigns/${campaignId}/targeting`, {
      name: `US Adults 25-44`,
      age_ranges: ["25-34", "35-44"],
      country_codes: ["US", "CA"],
      device_types: ["mobile", "desktop"],
    })) as APIResponse,
    "create targeting set",
  );

  // 5. Analytics rollups (direct DDB).
  seedAnalytics(accountId, campaignId, creativeId);

  // 6. Broadcast session w/ pre-roll, owned by root, started → bob's join serves
  //    the pre-roll overlay.
  await injectAuth(page, ROOT);
  const prof = await jsonOk(
    (await r.post("/broadcast/profiles", {
      name: `Ads Demo Profile ${STAMP}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    })) as APIResponse,
    "create broadcast profile",
  );
  const sess = await jsonOk(
    (await r.post("/broadcast/sessions", {
      profile_id: prof.id,
      pre_roll_enabled: true,
    })) as APIResponse,
    "create broadcast session",
  );
  const broadcastSid: string = sess.id;
  const startResp = await r.post(`/broadcast/sessions/${broadcastSid}/start`, {
    reason: "seg13-demo",
  });
  if (startResp.status() !== 202) {
    throw new Error(`start broadcast failed: ${startResp.status()} ${await startResp.text()}`);
  }

  // ── On-camera tour ──────────────────────────────────────────────────────────
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);

  // 1. Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    13,
    "Ads Platform",
    "Advertiser accounts · campaigns · creatives · targeting · broadcast ads · analytics · kill-switch",
  );

  // 2. Advertiser account ───────────────────────────────────────────────────────
  await caption(page, "The advertiser's view", "Loading the advertiser dashboard…");
  await page.goto(`${BASE}/ads/dashboard`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Advertiser Dashboard")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Lumina Studios").first(),
    "An advertiser account",
    "Self-serve sign-up with admin review, a spend balance, and lifetime spend",
    { ms: 4400 },
  );
  await reveal(
    page,
    page.getByText("active", { exact: false }).first(),
    "Approved & active",
    "Accounts go live only after platform review — this one is approved",
    { ms: 3800 },
  );

  // 3. Campaign ──────────────────────────────────────────────────────────────────
  await caption(page, "Campaigns", "Opening the campaign manager…");
  await page.goto(`${BASE}/ads/campaigns?account=${accountId}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByText("Campaigns", { exact: true })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Summer Launch").first(),
    "A live campaign",
    "Each campaign carries an objective, a daily budget, and a lifecycle status",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByText("awareness", { exact: false }).first(),
    "Budget & objective",
    "Awareness objective · $500.00 daily budget · approved and serving",
    { ms: 3400 },
  );

  // 4. Creative ──────────────────────────────────────────────────────────────────
  await caption(page, "Ad creatives", "Opening the creative manager…");
  await page.goto(`${BASE}/ads/creatives?campaign=${campaignId}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByText("Ad Creatives")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Hero Banner").first(),
    "An uploaded creative",
    "Image, video, or native-post creatives — uploaded, reviewed, and weighted",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByText("approved", { exact: false }).first(),
    "Approved for delivery",
    "Creatives are content-policy reviewed before they can serve",
    { ms: 3200 },
  );

  // Open the preview to show the rendered asset.
  await page.getByText("Hero Banner").first().click();
  await expect(page.getByTestId("creative-preview")).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("creative-preview").first(),
    "Live creative preview",
    "Preview exactly how the ad renders before it goes out",
    { ms: 3400, ring: false },
  );
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(600);

  // 5. Targeting ─────────────────────────────────────────────────────────────────
  await caption(page, "Audience targeting", "Opening the targeting editor…");
  await page.goto(`${BASE}/ads/targeting`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("targeting-editor")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);

  // Select the campaign so its dimension panels + estimate populate.
  const campBtn = page.getByRole("button", { name: /Summer Launch/ }).first();
  await expect(campBtn).toBeVisible({ timeout: 10_000 });
  await campBtn.click();
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.getByText("Demographics").first(),
    "Audience targeting",
    "Target by demographics, geography, devices, content, and creators",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByText("Geography").first(),
    "Geographic & device reach",
    "Pick countries and device types — exclusions are supported too",
    { ms: 3200 },
  );
  // Audience size estimate (debounced load).
  const estimate = page.getByTestId("audience-estimate").first();
  await expect(estimate).toBeVisible({ timeout: 8_000 });
  await reveal(
    page,
    estimate,
    "Live audience estimate",
    "A real-time reach estimate updates as the targeting tightens or widens",
    { ms: 3600 },
  );

  // 6. Broadcast pre-roll ad ──────────────────────────────────────────────────────
  // Switch the MAIN page to bob (a non-subscribing viewer) so the pre-roll overlay
  // is captured in this segment's recording. Same context, new identity — the
  // init-script + cookies are re-seeded for bob, and the live page reads the
  // refreshed auth-store on navigation.
  await caption(page, "Broadcast pre-roll", "Switching to a viewer joining a live stream…");
  await page.context().clearCookies();
  await injectAuth(page, BOB);
  void bob;
  await page.goto(`${BASE}/live/${broadcastSid}`, { waitUntil: "domcontentloaded" });
  const overlay = page.locator('[data-testid="broadcast-ad-overlay"]');
  await expect(overlay).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(800);
  await caption(
    page,
    "An in-stream pre-roll ad",
    "Non-subscribers see a skippable pre-roll before the live stream plays",
  );
  await expect(overlay).toBeInViewport({ ratio: 0.2, timeout: 12_000 });
  await beat(page, 6500);
  // Hold until the Skip button appears (skip-after = 5s).
  await caption(page, "Skippable after 5 seconds", "Subscribers join completely ad-free");
  await expect(page.locator('[data-testid="ad-skip-button"]')).toBeVisible({ timeout: 12_000 });
  await beat(page, 5000);
  await clearCaption(page);

  // 7. Analytics / ROAS ───────────────────────────────────────────────────────────
  // Back to alice (the account owner) for the advertiser analytics surface.
  await caption(page, "Ad analytics", "Loading the advertiser analytics dashboard…");
  await page.context().clearCookies();
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/ads/analytics?account_id=${accountId}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("ad-analytics-dashboard")).toBeVisible({ timeout: 12_000 });
  // Wait for the KPI cards to render from the seeded rollups.
  await expect(page.getByText("Impressions").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByText("Impressions").first(),
    "Performance analytics",
    "Impressions, clicks, CTR, spend, and CPA — the inputs to ROAS",
    { ms: 4400 },
  );
  await reveal(
    page,
    page.getByText("CTR").first(),
    "CTR · spend · CPA",
    "Spend versus seeded revenue drives a positive return on ad spend",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByTestId("analytics-chart").first(),
    "Performance over time",
    "Daily trends plus per-creative and per-surface breakdowns",
    { ms: 4200 },
  );

  // 8. Admin kill-switch ──────────────────────────────────────────────────────────
  await caption(page, "Platform admin", "Switching to root for the Ad Platform controls…");
  await page.context().clearCookies();
  await injectAuth(page, ROOT);
  await page.goto(`${BASE}/admin/ad-platform`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Ad Platform Management" })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByRole("tab", { name: /emergency controls/i }).first(),
    "Emergency Controls (root-only)",
    "Cross-account oversight: moderation, revenue, and a platform kill-switch",
    { ms: 3400 },
  );
  await page.getByRole("tab", { name: /emergency controls/i }).click();
  await expect(page.getByTestId("ks-panel")).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByTestId("ks-panel").first(),
    "The platform-wide ad kill-switch",
    "One control halts ALL ad serving instantly — reason-gated and audited",
    { ms: 4600 },
  );
  await reveal(
    page,
    page.getByTestId("ks-status").first(),
    "Kill-switch status",
    "A live status badge shows whether ad serving is active or halted",
    { ms: 4200 },
  );

  // 9. Outro ───────────────────────────────────────────────────────────────────────
  await caption(page, "Ads Platform ✓", "Next: VOD");
  await beat(page, 3600);
  await clearCaption(page);
  await beat(page, 900);
});
